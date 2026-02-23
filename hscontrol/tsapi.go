package hscontrol

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	hsdb "github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/policy"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/rs/zerolog/log"
	"github.com/tailscale/hujson"
	"tailscale.com/net/tsaddr"
)

const (
	tsapiOAuthTokenTTL       = time.Hour
	tsapiDefaultKeyType      = "auth"
	tsapiClientCredentialsGT = "client_credentials"
	tsapiDefaultKeyExpirySec = int64(90 * 24 * 60 * 60)
)

type tsapiState struct {
	mu sync.RWMutex

	oauthTokens     map[string]time.Time
	keyMetadataByID map[uint64]tsapiKeyMetadata
}

type tsapiKeyMetadata struct {
	Description   string
	Preauthorized bool
	ExpirySeconds int64
}

func newTSAPIState() *tsapiState {
	return &tsapiState{
		oauthTokens:     make(map[string]time.Time),
		keyMetadataByID: make(map[uint64]tsapiKeyMetadata),
	}
}

func (s *tsapiState) issueOAuthToken() (string, int64, error) {
	token, err := util.GenerateRandomStringURLSafe(48)
	if err != nil {
		return "", 0, err
	}

	expiresAt := time.Now().Add(tsapiOAuthTokenTTL)

	s.mu.Lock()
	s.oauthTokens[token] = expiresAt
	s.mu.Unlock()

	return token, int64(tsapiOAuthTokenTTL.Seconds()), nil
}

func (s *tsapiState) validateOAuthToken(token string) bool {
	now := time.Now()

	s.mu.RLock()
	expiresAt, ok := s.oauthTokens[token]
	s.mu.RUnlock()

	if !ok {
		return false
	}

	if now.After(expiresAt) {
		s.mu.Lock()
		delete(s.oauthTokens, token)
		s.mu.Unlock()

		return false
	}

	return true
}

func (s *tsapiState) setKeyMetadata(id uint64, metadata tsapiKeyMetadata) {
	s.mu.Lock()
	s.keyMetadataByID[id] = metadata
	s.mu.Unlock()
}

func (s *tsapiState) getKeyMetadata(id uint64) (tsapiKeyMetadata, bool) {
	s.mu.RLock()
	metadata, ok := s.keyMetadataByID[id]
	s.mu.RUnlock()

	return metadata, ok
}

func (s *tsapiState) deleteKeyMetadata(id uint64) {
	s.mu.Lock()
	delete(s.keyMetadataByID, id)
	s.mu.Unlock()
}

func (h *Headscale) registerTSAPIOAuthRoutes(r chi.Router) {
	r.Post("/oauth/token", h.tsapiOAuthTokenHandler)
	r.Post("/oauth/token-exchange", h.tsapiOAuthTokenExchangeHandler)
}

func (h *Headscale) registerTSAPIProtectedRoutes(r chi.Router) {
	r.Get("/tailnet/{tailnet}/keys", h.tsapiKeysHandler)
	r.Post("/tailnet/{tailnet}/keys", h.tsapiKeysHandler)
	r.Get("/tailnet/{tailnet}/keys/{id}", h.tsapiKeyHandler)
	r.Delete("/tailnet/{tailnet}/keys/{id}", h.tsapiKeyHandler)
	r.Get("/tailnet/{tailnet}/devices", h.tsapiDevicesHandler)
	r.Get("/device/{id}", h.tsapiDeviceHandler)
	r.Delete("/device/{id}", h.tsapiDeviceHandler)
	r.Post("/device/{id}/authorized", h.tsapiDeviceAuthorizedHandler)
	r.Post("/device/{id}/tags", h.tsapiDeviceTagsHandler)
	r.Post("/device/{id}/key", h.tsapiDeviceKeyHandler)
	r.Get("/device/{id}/routes", h.tsapiDeviceRoutesHandler)
	r.Post("/device/{id}/routes", h.tsapiDeviceRoutesHandler)
	r.Get("/tailnet/{tailnet}/acl", h.tsapiACLHandler)
	r.Post("/tailnet/{tailnet}/acl", h.tsapiACLHandler)
	r.Post("/tailnet/{tailnet}/acl/validate", h.tsapiACLValidateHandler)
	r.Get("/tailnet/{tailnet}/users", h.tsapiUsersHandler)
	r.Get("/users/{id}", h.tsapiUserHandler)
}

func (h *Headscale) tsapiAuthenticationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		authHeader := req.Header.Get("Authorization")
		if authHeader == "" {
			writeTSAPIError(w, http.StatusUnauthorized, "unauthorized")

			return
		}

		if strings.HasPrefix(authHeader, "Basic ") {
			apiKey, _, ok := req.BasicAuth()
			if !ok || apiKey == "" {
				writeTSAPIError(w, http.StatusUnauthorized, "unauthorized")

				return
			}

			valid, err := h.state.ValidateAPIKey(apiKey)
			if err != nil || !valid {
				writeTSAPIError(w, http.StatusUnauthorized, "unauthorized")

				return
			}

			next.ServeHTTP(w, req)

			return
		}

		if strings.HasPrefix(authHeader, AuthPrefix) {
			token := strings.TrimPrefix(authHeader, AuthPrefix)
			if token == "" {
				writeTSAPIError(w, http.StatusUnauthorized, "unauthorized")

				return
			}

			valid, err := h.state.ValidateAPIKey(token)
			if err == nil && valid {
				next.ServeHTTP(w, req)

				return
			}

			if h.tsapi.validateOAuthToken(token) {
				next.ServeHTTP(w, req)

				return
			}
		}

		writeTSAPIError(w, http.StatusUnauthorized, "unauthorized")
	})
}

type tsapiOAuthTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	Scope       string `json:"scope,omitempty"`
}

type tsapiOAuthErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

type tsapiErrorResponse struct {
	Message string `json:"message"`
}

func (h *Headscale) tsapiOAuthTokenHandler(w http.ResponseWriter, req *http.Request) {
	if err := req.ParseForm(); err != nil {
		writeTSAPIOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid form body")

		return
	}

	grantType := req.PostForm.Get("grant_type")
	if grantType != "" && grantType != tsapiClientCredentialsGT {
		writeTSAPIOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "unsupported grant_type")

		return
	}

	_, clientSecret := tsapiExtractClientCredentials(req)
	if clientSecret == "" {
		writeTSAPIOAuthError(w, http.StatusUnauthorized, "invalid_client", "missing OAuth client credentials")

		return
	}

	valid, err := h.state.ValidateAPIKey(clientSecret)
	if err != nil || !valid {
		writeTSAPIOAuthError(w, http.StatusUnauthorized, "invalid_client", "invalid OAuth client credentials")

		return
	}

	token, expiresIn, err := h.tsapi.issueOAuthToken()
	if err != nil {
		log.Error().Err(err).Msg("issuing OAuth token failed")
		writeTSAPIError(w, http.StatusInternalServerError, "internal server error")

		return
	}

	writeTSAPIJSON(w, http.StatusOK, tsapiOAuthTokenResponse{
		AccessToken: token,
		TokenType:   "Bearer",
		ExpiresIn:   expiresIn,
		Scope:       req.PostForm.Get("scope"),
	})
}

func (h *Headscale) tsapiOAuthTokenExchangeHandler(w http.ResponseWriter, req *http.Request) {
	if err := req.ParseForm(); err != nil {
		writeTSAPIOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid form body")

		return
	}

	if req.PostForm.Get("client_id") == "" || req.PostForm.Get("jwt") == "" {
		writeTSAPIOAuthError(w, http.StatusBadRequest, "invalid_request", "missing client_id or jwt")

		return
	}

	token, expiresIn, err := h.tsapi.issueOAuthToken()
	if err != nil {
		log.Error().Err(err).Msg("issuing exchanged OAuth token failed")
		writeTSAPIError(w, http.StatusInternalServerError, "internal server error")

		return
	}

	writeTSAPIJSON(w, http.StatusOK, tsapiOAuthTokenResponse{
		AccessToken: token,
		TokenType:   "Bearer",
		ExpiresIn:   expiresIn,
	})
}

func writeTSAPIOAuthError(w http.ResponseWriter, code int, errType, description string) {
	writeTSAPIJSON(w, code, tsapiOAuthErrorResponse{
		Error:            errType,
		ErrorDescription: description,
	})
}

func writeTSAPIError(w http.ResponseWriter, code int, message string) {
	writeTSAPIJSON(w, code, tsapiErrorResponse{Message: message})
}

func writeTSAPIJSON(w http.ResponseWriter, code int, response any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)

	if response == nil {
		return
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Error().Err(err).Msg("writing tsapi JSON response failed")
	}
}

type tsapiKeyCapabilities struct {
	Devices struct {
		Create struct {
			Reusable      bool     `json:"reusable"`
			Ephemeral     bool     `json:"ephemeral"`
			Preauthorized bool     `json:"preauthorized"`
			Tags          []string `json:"tags,omitempty"`
		} `json:"create"`
	} `json:"devices"`
}

type tsapiKey struct {
	ID           string               `json:"id"`
	KeyType      string               `json:"keyType,omitempty"`
	Key          string               `json:"key,omitempty"`
	Description  string               `json:"description"`
	ExpirySecs   *int64               `json:"expirySeconds,omitempty"`
	Created      time.Time            `json:"created"`
	Updated      time.Time            `json:"updated"`
	Expires      time.Time            `json:"expires"`
	Revoked      time.Time            `json:"revoked"`
	Capabilities tsapiKeyCapabilities `json:"capabilities"`
	Invalid      bool                 `json:"invalid"`
	UserID       string               `json:"userId,omitempty"`
}

type tsapiCreateKeyRequest struct {
	Capabilities  tsapiKeyCapabilities `json:"capabilities"`
	ExpirySeconds int64                `json:"expirySeconds,omitempty"`
	KeyType       string               `json:"keyType,omitempty"`
	Description   string               `json:"description,omitempty"`
}

func (h *Headscale) tsapiKeysHandler(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodGet:
		h.tsapiListKeysHandler(w)

	case http.MethodPost:
		h.tsapiCreateKeyHandler(w, req)

	default:
		writeTSAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (h *Headscale) tsapiKeyHandler(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodGet:
		h.tsapiGetKeyHandler(w, req)

	case http.MethodDelete:
		h.tsapiDeleteKeyHandler(w, req)

	default:
		writeTSAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (h *Headscale) tsapiCreateKeyHandler(w http.ResponseWriter, req *http.Request) {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		writeTSAPIError(w, http.StatusBadRequest, "failed to read request body")

		return
	}

	var request tsapiCreateKeyRequest
	if err := json.Unmarshal(body, &request); err != nil {
		writeTSAPIError(w, http.StatusBadRequest, "invalid request body")

		return
	}

	if request.KeyType != "" && request.KeyType != tsapiDefaultKeyType {
		writeTSAPIError(w, http.StatusNotImplemented, "only auth keys are supported")

		return
	}

	if err := tsapiValidateTags(request.Capabilities.Devices.Create.Tags); err != nil {
		writeTSAPIError(w, http.StatusBadRequest, err.Error())

		return
	}

	expirySeconds := request.ExpirySeconds
	if expirySeconds <= 0 {
		expirySeconds = tsapiDefaultKeyExpirySec
	}
	expires := time.Now().Add(time.Duration(expirySeconds) * time.Second)
	expiration := &expires

	userID, err := h.tsapiDefaultUserID()
	if err != nil {
		writeTSAPIError(w, http.StatusInternalServerError, "failed to resolve default user")

		return
	}

	createdKey, err := h.state.CreatePreAuthKey(
		userID,
		request.Capabilities.Devices.Create.Reusable,
		request.Capabilities.Devices.Create.Ephemeral,
		expiration,
		request.Capabilities.Devices.Create.Tags,
	)
	if err != nil {
		writeTSAPIError(w, http.StatusBadRequest, err.Error())

		return
	}

	h.tsapi.setKeyMetadata(createdKey.ID, tsapiKeyMetadata{
		Description:   request.Description,
		Preauthorized: request.Capabilities.Devices.Create.Preauthorized,
		ExpirySeconds: expirySeconds,
	})

	response := tsapiKeyFromPreAuthKeyNew(*createdKey, request.Description, request.Capabilities.Devices.Create.Preauthorized, expirySeconds)
	response.Key = createdKey.Key

	writeTSAPIJSON(w, http.StatusOK, response)
}

func (h *Headscale) tsapiListKeysHandler(w http.ResponseWriter) {
	keys, err := h.state.ListPreAuthKeys()
	if err != nil {
		writeTSAPIError(w, http.StatusInternalServerError, "failed to list keys")

		return
	}

	sort.Slice(keys, func(i, j int) bool {
		return keys[i].ID < keys[j].ID
	})

	response := make([]tsapiKey, 0, len(keys))
	for _, key := range keys {
		response = append(response, h.tsapiKeyFromPreAuthKey(key))
	}

	writeTSAPIJSON(w, http.StatusOK, map[string][]tsapiKey{"keys": response})
}

func (h *Headscale) tsapiGetKeyHandler(w http.ResponseWriter, req *http.Request) {
	id, ok := tsapiParseID(chi.URLParam(req, "id"))
	if !ok {
		writeTSAPIError(w, http.StatusNotFound, "key not found")

		return
	}

	key, found, err := h.tsapiGetPreAuthKeyByID(id)
	if err != nil {
		writeTSAPIError(w, http.StatusInternalServerError, "failed to fetch key")

		return
	}
	if !found {
		writeTSAPIError(w, http.StatusNotFound, "key not found")

		return
	}

	writeTSAPIJSON(w, http.StatusOK, h.tsapiKeyFromPreAuthKey(*key))
}

func (h *Headscale) tsapiDeleteKeyHandler(w http.ResponseWriter, req *http.Request) {
	id, ok := tsapiParseID(chi.URLParam(req, "id"))
	if !ok {
		writeTSAPIError(w, http.StatusNotFound, "key not found")

		return
	}

	_, found, err := h.tsapiGetPreAuthKeyByID(id)
	if err != nil {
		writeTSAPIError(w, http.StatusInternalServerError, "failed to fetch key")

		return
	}
	if !found {
		writeTSAPIError(w, http.StatusNotFound, "key not found")

		return
	}

	if err := h.state.DeletePreAuthKey(id); err != nil {
		writeTSAPIError(w, http.StatusInternalServerError, "failed to delete key")

		return
	}

	h.tsapi.deleteKeyMetadata(id)

	writeTSAPIJSON(w, http.StatusOK, map[string]any{})
}

type tsapiDevice struct {
	Addresses                 []string  `json:"addresses"`
	Name                      string    `json:"name"`
	ID                        string    `json:"id"`
	NodeID                    string    `json:"nodeId"`
	Authorized                bool      `json:"authorized"`
	User                      string    `json:"user"`
	Tags                      []string  `json:"tags"`
	KeyExpiryDisabled         bool      `json:"keyExpiryDisabled"`
	BlocksIncomingConnections bool      `json:"blocksIncomingConnections"`
	ClientVersion             string    `json:"clientVersion"`
	Created                   time.Time `json:"created"`
	Expires                   time.Time `json:"expires"`
	Hostname                  string    `json:"hostname"`
	IsEphemeral               bool      `json:"isEphemeral"`
	IsExternal                bool      `json:"isExternal"`
	ConnectedToControl        bool      `json:"connectedToControl"`
	LastSeen                  string    `json:"lastSeen"`
	MachineKey                string    `json:"machineKey"`
	NodeKey                   string    `json:"nodeKey"`
	OS                        string    `json:"os"`
	TailnetLockError          string    `json:"tailnetLockError"`
	TailnetLockKey            string    `json:"tailnetLockKey"`
	UpdateAvailable           bool      `json:"updateAvailable"`

	AdvertisedRoutes []string `json:"advertisedRoutes,omitempty"`
	EnabledRoutes    []string `json:"enabledRoutes,omitempty"`
}

type tsapiDeviceRoutes struct {
	AdvertisedRoutes []string `json:"advertisedRoutes"`
	EnabledRoutes    []string `json:"enabledRoutes"`
}

type tsapiSetAuthorizedRequest struct {
	Authorized bool `json:"authorized"`
}

type tsapiSetTagsRequest struct {
	Tags []string `json:"tags"`
}

type tsapiSetKeyRequest struct {
	KeyExpiryDisabled bool `json:"keyExpiryDisabled"`
}

type tsapiSetRoutesRequest struct {
	Routes []string `json:"routes"`
}

func (h *Headscale) tsapiDevicesHandler(w http.ResponseWriter, req *http.Request) {
	users, err := h.state.ListAllUsers()
	if err != nil {
		writeTSAPIError(w, http.StatusInternalServerError, "failed to list users")

		return
	}

	usersByID := tsapiUsersByID(users)

	devices := make([]tsapiDevice, 0)
	for _, node := range h.state.ListNodes().All() {
		if !node.Valid() {
			continue
		}

		device := h.tsapiDeviceFromNode(node, usersByID)
		if !tsapiDeviceMatchesQueryFilters(device, req.URL.Query()) {
			continue
		}

		devices = append(devices, device)
	}

	sort.Slice(devices, func(i, j int) bool {
		iID, _ := tsapiParseID(devices[i].ID)
		jID, _ := tsapiParseID(devices[j].ID)

		return iID < jID
	})

	writeTSAPIJSON(w, http.StatusOK, map[string][]tsapiDevice{"devices": devices})
}

func (h *Headscale) tsapiDeviceHandler(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodGet:
		h.tsapiGetDeviceHandler(w, req)

	case http.MethodDelete:
		h.tsapiDeleteDeviceHandler(w, req)

	default:
		writeTSAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (h *Headscale) tsapiGetDeviceHandler(w http.ResponseWriter, req *http.Request) {
	node, ok := h.tsapiNodeFromDeviceID(chi.URLParam(req, "id"))
	if !ok {
		writeTSAPIError(w, http.StatusNotFound, "device not found")

		return
	}

	users, err := h.state.ListAllUsers()
	if err != nil {
		writeTSAPIError(w, http.StatusInternalServerError, "failed to list users")

		return
	}

	writeTSAPIJSON(w, http.StatusOK, h.tsapiDeviceFromNode(node, tsapiUsersByID(users)))
}

func (h *Headscale) tsapiDeleteDeviceHandler(w http.ResponseWriter, req *http.Request) {
	node, ok := h.tsapiNodeFromDeviceID(chi.URLParam(req, "id"))
	if !ok {
		writeTSAPIError(w, http.StatusNotFound, "device not found")

		return
	}

	nodeChange, err := h.state.DeleteNode(node)
	if err != nil {
		writeTSAPIError(w, http.StatusInternalServerError, "failed to delete device")

		return
	}

	h.Change(nodeChange)
	writeTSAPIJSON(w, http.StatusOK, map[string]any{})
}

func (h *Headscale) tsapiDeviceAuthorizedHandler(w http.ResponseWriter, req *http.Request) {
	node, ok := h.tsapiNodeFromDeviceID(chi.URLParam(req, "id"))
	if !ok {
		writeTSAPIError(w, http.StatusNotFound, "device not found")

		return
	}

	var request tsapiSetAuthorizedRequest
	if err := json.NewDecoder(req.Body).Decode(&request); err != nil {
		writeTSAPIError(w, http.StatusBadRequest, "invalid request body")

		return
	}

	if request.Authorized {
		if node.IsExpired() {
			_, nodeChange, err := h.state.SetNodeExpiry(node.ID(), nil)
			if err != nil {
				writeTSAPIError(w, http.StatusInternalServerError, "failed to authorize device")

				return
			}

			h.Change(nodeChange)
		}

		writeTSAPIJSON(w, http.StatusOK, map[string]any{})

		return
	}

	if !node.IsExpired() {
		now := time.Now()
		_, nodeChange, err := h.state.SetNodeExpiry(node.ID(), &now)
		if err != nil {
			writeTSAPIError(w, http.StatusInternalServerError, "failed to deauthorize device")

			return
		}

		h.Change(nodeChange)
	}

	writeTSAPIJSON(w, http.StatusOK, map[string]any{})
}

func (h *Headscale) tsapiDeviceTagsHandler(w http.ResponseWriter, req *http.Request) {
	node, ok := h.tsapiNodeFromDeviceID(chi.URLParam(req, "id"))
	if !ok {
		writeTSAPIError(w, http.StatusNotFound, "device not found")

		return
	}

	var request tsapiSetTagsRequest
	if err := json.NewDecoder(req.Body).Decode(&request); err != nil {
		writeTSAPIError(w, http.StatusBadRequest, "invalid request body")

		return
	}

	if len(request.Tags) == 0 {
		writeTSAPIJSON(w, http.StatusOK, map[string]any{})

		return
	}

	if err := tsapiValidateTags(request.Tags); err != nil {
		writeTSAPIError(w, http.StatusBadRequest, err.Error())

		return
	}

	_, nodeChange, err := h.state.SetNodeTags(node.ID(), request.Tags)
	if err != nil {
		writeTSAPIError(w, http.StatusBadRequest, err.Error())

		return
	}

	h.Change(nodeChange)
	writeTSAPIJSON(w, http.StatusOK, map[string]any{})
}

func (h *Headscale) tsapiDeviceKeyHandler(w http.ResponseWriter, req *http.Request) {
	node, ok := h.tsapiNodeFromDeviceID(chi.URLParam(req, "id"))
	if !ok {
		writeTSAPIError(w, http.StatusNotFound, "device not found")

		return
	}

	var request tsapiSetKeyRequest
	if err := json.NewDecoder(req.Body).Decode(&request); err != nil {
		writeTSAPIError(w, http.StatusBadRequest, "invalid request body")

		return
	}

	if request.KeyExpiryDisabled {
		_, nodeChange, err := h.state.SetNodeExpiry(node.ID(), nil)
		if err != nil {
			writeTSAPIError(w, http.StatusInternalServerError, "failed to update device key")

			return
		}

		h.Change(nodeChange)
		writeTSAPIJSON(w, http.StatusOK, map[string]any{})

		return
	}

	if node.Expiry().Valid() && !node.Expiry().Get().IsZero() {
		writeTSAPIJSON(w, http.StatusOK, map[string]any{})

		return
	}

	expiry := time.Now().Add(180 * 24 * time.Hour)
	_, nodeChange, err := h.state.SetNodeExpiry(node.ID(), &expiry)
	if err != nil {
		writeTSAPIError(w, http.StatusInternalServerError, "failed to update device key")

		return
	}

	h.Change(nodeChange)
	writeTSAPIJSON(w, http.StatusOK, map[string]any{})
}

func (h *Headscale) tsapiDeviceRoutesHandler(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodGet:
		h.tsapiGetDeviceRoutesHandler(w, req)

	case http.MethodPost:
		h.tsapiSetDeviceRoutesHandler(w, req)

	default:
		writeTSAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (h *Headscale) tsapiGetDeviceRoutesHandler(w http.ResponseWriter, req *http.Request) {
	node, ok := h.tsapiNodeFromDeviceID(chi.URLParam(req, "id"))
	if !ok {
		writeTSAPIError(w, http.StatusNotFound, "device not found")

		return
	}

	writeTSAPIJSON(w, http.StatusOK, tsapiDeviceRoutes{
		AdvertisedRoutes: tsapiPrefixesToStringsSorted(node.AnnouncedRoutes()),
		EnabledRoutes:    tsapiPrefixesToStringsSorted(node.ApprovedRoutes().AsSlice()),
	})
}

func (h *Headscale) tsapiSetDeviceRoutesHandler(w http.ResponseWriter, req *http.Request) {
	node, ok := h.tsapiNodeFromDeviceID(chi.URLParam(req, "id"))
	if !ok {
		writeTSAPIError(w, http.StatusNotFound, "device not found")

		return
	}

	var request tsapiSetRoutesRequest
	if err := json.NewDecoder(req.Body).Decode(&request); err != nil {
		writeTSAPIError(w, http.StatusBadRequest, "invalid request body")

		return
	}

	routes := make([]netip.Prefix, 0, len(request.Routes))
	for _, route := range request.Routes {
		prefix, err := netip.ParsePrefix(route)
		if err != nil {
			writeTSAPIError(w, http.StatusBadRequest, fmt.Sprintf("invalid route %q", route))

			return
		}

		if prefix == tsaddr.AllIPv4() || prefix == tsaddr.AllIPv6() {
			routes = append(routes, tsaddr.AllIPv4(), tsaddr.AllIPv6())

			continue
		}

		routes = append(routes, prefix)
	}

	slices.SortFunc(routes, tsapiComparePrefix)
	routes = slices.Compact(routes)

	_, nodeChange, err := h.state.SetApprovedRoutes(node.ID(), routes)
	if err != nil {
		writeTSAPIError(w, http.StatusBadRequest, err.Error())

		return
	}

	h.Change(nodeChange)

	updatedNode, ok := h.state.GetNodeByID(node.ID())
	if !ok {
		writeTSAPIError(w, http.StatusInternalServerError, "failed to fetch device routes")

		return
	}

	writeTSAPIJSON(w, http.StatusOK, tsapiDeviceRoutes{
		AdvertisedRoutes: tsapiPrefixesToStringsSorted(updatedNode.AnnouncedRoutes()),
		EnabledRoutes:    tsapiPrefixesToStringsSorted(updatedNode.ApprovedRoutes().AsSlice()),
	})
}

type tsapiUser struct {
	ID                 string    `json:"id"`
	DisplayName        string    `json:"displayName"`
	LoginName          string    `json:"loginName"`
	ProfilePicURL      string    `json:"profilePicUrl"`
	TailnetID          string    `json:"tailnetId"`
	Created            time.Time `json:"created"`
	Type               string    `json:"type"`
	Role               string    `json:"role"`
	Status             string    `json:"status"`
	DeviceCount        int       `json:"deviceCount"`
	LastSeen           time.Time `json:"lastSeen"`
	CurrentlyConnected bool      `json:"currentlyConnected"`
}

type tsapiUserStats struct {
	deviceCount int
	lastSeen    time.Time
	connected   bool
}

func (h *Headscale) tsapiUsersHandler(w http.ResponseWriter, req *http.Request) {
	users, err := h.state.ListAllUsers()
	if err != nil {
		writeTSAPIError(w, http.StatusInternalServerError, "failed to list users")

		return
	}

	stats := h.tsapiBuildUserStats()

	sort.Slice(users, func(i, j int) bool {
		return users[i].ID < users[j].ID
	})

	query := req.URL.Query()
	requestedTypes := query["type"]
	requestedRoles := query["role"]

	response := make([]tsapiUser, 0, len(users))
	for index, user := range users {
		role := tsapiRoleForUserIndex(index)
		if !tsapiUserMatchesFilters(requestedTypes, requestedRoles, role) {
			continue
		}

		response = append(response, tsapiUserFromUser(user, role, stats[user.ID]))
	}

	writeTSAPIJSON(w, http.StatusOK, map[string][]tsapiUser{"users": response})
}

func (h *Headscale) tsapiUserHandler(w http.ResponseWriter, req *http.Request) {
	id, ok := tsapiParseID(chi.URLParam(req, "id"))
	if !ok {
		writeTSAPIError(w, http.StatusNotFound, "user not found")

		return
	}

	user, err := h.state.GetUserByID(types.UserID(id))
	if err != nil {
		if errors.Is(err, hsdb.ErrUserNotFound) {
			writeTSAPIError(w, http.StatusNotFound, "user not found")

			return
		}

		writeTSAPIError(w, http.StatusInternalServerError, "failed to fetch user")

		return
	}

	stats := h.tsapiBuildUserStats()
	users, err := h.state.ListAllUsers()
	if err != nil {
		writeTSAPIError(w, http.StatusInternalServerError, "failed to list users")

		return
	}

	sort.Slice(users, func(i, j int) bool {
		return users[i].ID < users[j].ID
	})

	role := "member"
	for index := range users {
		if users[index].ID == user.ID {
			role = tsapiRoleForUserIndex(index)

			break
		}
	}

	writeTSAPIJSON(w, http.StatusOK, tsapiUserFromUser(*user, role, stats[user.ID]))
}

func (h *Headscale) tsapiACLHandler(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodGet:
		h.tsapiGetACLHandler(w, req)

	case http.MethodPost:
		h.tsapiSetACLHandler(w, req)

	default:
		writeTSAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (h *Headscale) tsapiGetACLHandler(w http.ResponseWriter, req *http.Request) {
	policyData, err := h.tsapiCurrentPolicyData()
	if err != nil {
		writeTSAPIError(w, http.StatusInternalServerError, "failed to fetch acl")

		return
	}

	w.Header().Set("ETag", tsapiPolicyETag(policyData))

	if strings.Contains(req.Header.Get("Accept"), "application/hujson") {
		if req.URL.Query().Get("details") == "1" {
			writeTSAPIJSON(w, http.StatusOK, struct {
				ACL      []byte   `json:"acl"`
				Warnings []string `json:"warnings"`
			}{
				ACL:      []byte(policyData),
				Warnings: []string{},
			})

			return
		}

		w.Header().Set("Content-Type", "application/hujson")
		w.WriteHeader(http.StatusOK)

		_, _ = io.WriteString(w, policyData)

		return
	}

	response := []byte(policyData)
	if !json.Valid(response) {
		standardized, err := hujson.Standardize(response)
		if err == nil {
			response = standardized
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	_, _ = w.Write(response)
}

func (h *Headscale) tsapiSetACLHandler(w http.ResponseWriter, req *http.Request) {
	if h.cfg.Policy.Mode != types.PolicyModeDB {
		writeTSAPIError(w, http.StatusBadRequest, "acl updates require policy.mode=database")

		return
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		writeTSAPIError(w, http.StatusBadRequest, "failed to read request body")

		return
	}

	currentPolicy, err := h.tsapiCurrentPolicyData()
	if err != nil {
		writeTSAPIError(w, http.StatusInternalServerError, "failed to fetch acl")

		return
	}

	ifMatch := strings.TrimSpace(req.Header.Get("If-Match"))
	if ifMatch != "" {
		if tsapiNormalizeETag(ifMatch) == "ts-default" {
			if !tsapiPolicyIsDefault(currentPolicy) {
				writeTSAPIError(w, http.StatusPreconditionFailed, "policy has been modified from default")

				return
			}
		} else if tsapiNormalizeETag(ifMatch) != tsapiNormalizeETag(tsapiPolicyETag(currentPolicy)) {
			writeTSAPIError(w, http.StatusPreconditionFailed, "etag mismatch")

			return
		}
	}

	if err := h.tsapiValidateACLData(body); err != nil {
		writeTSAPIError(w, http.StatusBadRequest, err.Error())

		return
	}

	policyData := strings.TrimSpace(string(body))
	if policyData != "" {
		if _, err := h.state.SetPolicy([]byte(policyData)); err != nil {
			writeTSAPIError(w, http.StatusBadRequest, err.Error())

			return
		}
	}

	if _, err := h.state.SetPolicyInDB(policyData); err != nil {
		writeTSAPIError(w, http.StatusInternalServerError, "failed to store acl")

		return
	}

	changes, err := h.state.ReloadPolicy()
	if err != nil {
		writeTSAPIError(w, http.StatusInternalServerError, "failed to reload acl")

		return
	}

	if len(changes) > 0 {
		h.Change(changes...)
	}

	updatedPolicyData, err := h.tsapiCurrentPolicyData()
	if err != nil {
		writeTSAPIError(w, http.StatusInternalServerError, "failed to fetch acl")

		return
	}

	w.Header().Set("ETag", tsapiPolicyETag(updatedPolicyData))

	if strings.Contains(req.Header.Get("Accept"), "application/hujson") {
		w.Header().Set("Content-Type", "application/hujson")
		w.WriteHeader(http.StatusOK)

		_, _ = io.WriteString(w, updatedPolicyData)

		return
	}

	response := []byte(updatedPolicyData)
	if !json.Valid(response) {
		standardized, err := hujson.Standardize(response)
		if err == nil {
			response = standardized
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	_, _ = w.Write(response)
}

func (h *Headscale) tsapiACLValidateHandler(w http.ResponseWriter, req *http.Request) {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		writeTSAPIError(w, http.StatusBadRequest, "failed to read request body")

		return
	}

	standardized := body
	if hujsonBody, err := hujson.Standardize(body); err == nil {
		standardized = hujsonBody
	}

	if strings.HasPrefix(strings.TrimSpace(string(standardized)), "[") {
		var tests []json.RawMessage
		if err := json.Unmarshal(standardized, &tests); err != nil {
			writeTSAPIError(w, http.StatusBadRequest, "invalid acl test payload")

			return
		}

		w.WriteHeader(http.StatusOK)

		return
	}

	if err := h.tsapiValidateACLData(standardized); err != nil {
		writeTSAPIError(w, http.StatusBadRequest, err.Error())

		return
	}

	writeTSAPIJSON(w, http.StatusOK, map[string]any{})
}

func (h *Headscale) tsapiCurrentPolicyData() (string, error) {
	policyData, err := h.state.DebugPolicy()
	if err != nil {
		if errors.Is(err, types.ErrPolicyNotFound) {
			return "{}", nil
		}

		return "", err
	}

	if strings.TrimSpace(policyData) == "" {
		return "{}", nil
	}

	return policyData, nil
}

func (h *Headscale) tsapiValidateACLData(policyData []byte) error {
	if strings.TrimSpace(string(policyData)) == "" {
		return nil
	}

	users, err := h.state.ListAllUsers()
	if err != nil {
		return fmt.Errorf("loading users for policy validation: %w", err)
	}

	if _, err := policy.NewPolicyManager(policyData, users, h.state.ListNodes()); err != nil {
		return fmt.Errorf("invalid ACL: %w", err)
	}

	return nil
}

func tsapiPolicyIsDefault(policyData string) bool {
	trimmed := strings.TrimSpace(policyData)
	if trimmed == "" || trimmed == "{}" {
		return true
	}

	standardized, err := hujson.Standardize([]byte(trimmed))
	if err != nil {
		return false
	}

	return strings.TrimSpace(string(standardized)) == "{}"
}

func tsapiPolicyETag(policyData string) string {
	hasher := fnv.New64a()
	_, _ = hasher.Write([]byte(policyData))

	return fmt.Sprintf("\"hs-tsapi-%x\"", hasher.Sum64())
}

func tsapiNormalizeETag(value string) string {
	trimmed := strings.TrimSpace(value)
	trimmed = strings.TrimPrefix(trimmed, "W/")

	return strings.Trim(trimmed, "\"")
}

func (h *Headscale) tsapiBuildUserStats() map[uint]tsapiUserStats {
	stats := make(map[uint]tsapiUserStats)

	for _, node := range h.state.ListNodes().All() {
		if !node.Valid() || !node.UserID().Valid() || node.IsTagged() {
			continue
		}

		uid := node.UserID().Get()
		entry := stats[uid]
		entry.deviceCount++

		if node.IsOnline().Valid() && node.IsOnline().Get() {
			entry.connected = true
			entry.lastSeen = time.Now()
		} else if node.LastSeen().Valid() && node.LastSeen().Get().After(entry.lastSeen) {
			entry.lastSeen = node.LastSeen().Get()
		}

		stats[uid] = entry
	}

	return stats
}

func tsapiUserFromUser(user types.User, role string, stats tsapiUserStats) tsapiUser {
	lastSeen := user.CreatedAt
	if !stats.lastSeen.IsZero() {
		lastSeen = stats.lastSeen
	}

	return tsapiUser{
		ID:                 strconv.FormatUint(uint64(user.ID), util.Base10),
		DisplayName:        tsapiUserDisplayName(user),
		LoginName:          tsapiUserLoginName(user),
		ProfilePicURL:      user.ProfilePicURL,
		TailnetID:          "-",
		Created:            user.CreatedAt,
		Type:               "member",
		Role:               role,
		Status:             "active",
		DeviceCount:        stats.deviceCount,
		LastSeen:           lastSeen,
		CurrentlyConnected: stats.connected,
	}
}

func tsapiUserDisplayName(user types.User) string {
	if user.DisplayName != "" {
		return user.DisplayName
	}

	return tsapiUserLoginName(user)
}

func tsapiUserLoginName(user types.User) string {
	if user.Email != "" {
		return user.Email
	}

	if user.Name != "" {
		return user.Name
	}

	if user.ProviderIdentifier.Valid && user.ProviderIdentifier.String != "" {
		return user.ProviderIdentifier.String
	}

	return strconv.FormatUint(uint64(user.ID), util.Base10)
}

func tsapiRoleForUserIndex(index int) string {
	if index == 0 {
		return "owner"
	}

	return "member"
}

func tsapiUserMatchesFilters(requestedTypes, requestedRoles []string, role string) bool {
	if len(requestedTypes) > 0 && !tsapiAnyStringMatch(requestedTypes, "member") {
		return false
	}

	if len(requestedRoles) > 0 && !tsapiAnyStringMatch(requestedRoles, role) {
		return false
	}

	return true
}

func tsapiAnyStringMatch(candidates []string, expected string) bool {
	for _, candidate := range candidates {
		if candidate == expected {
			return true
		}
	}

	return false
}

func tsapiUsersByID(users []types.User) map[uint]types.User {
	result := make(map[uint]types.User, len(users))
	for _, user := range users {
		result[user.ID] = user
	}

	return result
}

func (h *Headscale) tsapiNodeFromDeviceID(raw string) (types.NodeView, bool) {
	nodeID, ok := tsapiParseNodeID(raw)
	if !ok {
		return types.NodeView{}, false
	}

	return h.state.GetNodeByID(nodeID)
}

func tsapiParseNodeID(raw string) (types.NodeID, bool) {
	normalized := strings.TrimSpace(raw)
	normalized = strings.TrimPrefix(normalized, "n")

	parsed, err := strconv.ParseUint(normalized, util.Base10, 64)
	if err != nil {
		return 0, false
	}

	return types.NodeID(parsed), true
}

func tsapiNodeIDString(nodeID types.NodeID) string {
	return "n" + strconv.FormatUint(uint64(nodeID), util.Base10)
}

func (h *Headscale) tsapiDeviceFromNode(node types.NodeView, usersByID map[uint]types.User) tsapiDevice {
	name := node.Hostname()
	if fqdn, err := node.GetFQDN(h.cfg.BaseDomain); err == nil {
		name = fqdn
	}

	var (
		clientVersion string
		osName        string
	)
	if hostinfo := node.Hostinfo().AsStruct(); hostinfo != nil {
		clientVersion = hostinfo.IPNVersion
		osName = hostinfo.OS
	}

	connected := node.IsOnline().Valid() && node.IsOnline().Get()

	lastSeen := ""
	if !connected && node.LastSeen().Valid() {
		lastSeen = node.LastSeen().Get().Format(time.RFC3339Nano)
	}

	expires := time.Time{}
	keyExpiryDisabled := true
	if node.Expiry().Valid() {
		expires = node.Expiry().Get()
		keyExpiryDisabled = node.Expiry().Get().IsZero()
	}

	return tsapiDevice{
		Addresses:                 node.IPsAsString(),
		Name:                      name,
		ID:                        strconv.FormatUint(uint64(node.ID()), util.Base10),
		NodeID:                    tsapiNodeIDString(node.ID()),
		Authorized:                !node.IsExpired(),
		User:                      tsapiDeviceUser(node, usersByID),
		Tags:                      node.Tags().AsSlice(),
		KeyExpiryDisabled:         keyExpiryDisabled,
		BlocksIncomingConnections: false,
		ClientVersion:             clientVersion,
		Created:                   node.CreatedAt(),
		Expires:                   expires,
		Hostname:                  node.Hostname(),
		IsEphemeral:               node.IsEphemeral(),
		IsExternal:                false,
		ConnectedToControl:        connected,
		LastSeen:                  lastSeen,
		MachineKey:                node.MachineKey().String(),
		NodeKey:                   node.NodeKey().String(),
		OS:                        osName,
		TailnetLockError:          "",
		TailnetLockKey:            "",
		UpdateAvailable:           false,
		AdvertisedRoutes:          tsapiPrefixesToStringsSorted(node.AnnouncedRoutes()),
		EnabledRoutes:             tsapiPrefixesToStringsSorted(node.ApprovedRoutes().AsSlice()),
	}
}

func tsapiDeviceUser(node types.NodeView, usersByID map[uint]types.User) string {
	if node.IsTagged() {
		return types.TaggedDevices.Name
	}

	if node.UserID().Valid() {
		if user, ok := usersByID[node.UserID().Get()]; ok {
			return tsapiUserLoginName(user)
		}

		return strconv.FormatUint(uint64(node.UserID().Get()), util.Base10)
	}

	if node.User().Valid() {
		if node.User().Email() != "" {
			return node.User().Email()
		}

		if node.User().Name() != "" {
			return node.User().Name()
		}
	}

	return ""
}

func tsapiComparePrefix(a, b netip.Prefix) int {
	if a.IsValid() && !b.IsValid() {
		return 1
	}

	if !a.IsValid() && b.IsValid() {
		return -1
	}

	if c := a.Addr().Compare(b.Addr()); c != 0 {
		return c
	}

	return cmp.Compare(a.Bits(), b.Bits())
}

func tsapiPrefixesToStringsSorted(prefixes []netip.Prefix) []string {
	if len(prefixes) == 0 {
		return nil
	}

	copyPrefixes := append([]netip.Prefix(nil), prefixes...)
	slices.SortFunc(copyPrefixes, tsapiComparePrefix)

	return util.PrefixesToString(copyPrefixes)
}

func tsapiDeviceMatchesQueryFilters(device tsapiDevice, query url.Values) bool {
	for key, values := range query {
		switch key {
		case "fields":
			continue

		case "name":
			if !tsapiAnyStringMatch(values, device.Name) {
				return false
			}

		case "hostname":
			if !tsapiAnyStringMatch(values, device.Hostname) {
				return false
			}

		case "user":
			if !tsapiAnyStringMatch(values, device.User) {
				return false
			}

		case "os":
			if !tsapiAnyStringMatch(values, device.OS) {
				return false
			}

		case "authorized":
			if !tsapiAnyBoolMatch(values, device.Authorized) {
				return false
			}

		case "isExternal":
			if !tsapiAnyBoolMatch(values, device.IsExternal) {
				return false
			}

		case "isEphemeral":
			if !tsapiAnyBoolMatch(values, device.IsEphemeral) {
				return false
			}

		case "tags":
			if !tsapiAnyValueInSlice(values, device.Tags) {
				return false
			}
		}
	}

	return true
}

func tsapiAnyBoolMatch(candidates []string, expected bool) bool {
	for _, candidate := range candidates {
		parsed, err := strconv.ParseBool(candidate)
		if err != nil {
			continue
		}

		if parsed == expected {
			return true
		}
	}

	return false
}

func tsapiAnyValueInSlice(values []string, haystack []string) bool {
	for _, value := range values {
		if slices.Contains(haystack, value) {
			return true
		}
	}

	return false
}

func tsapiKeyFromPreAuthKeyNew(key types.PreAuthKeyNew, description string, preauthorized bool, expirySeconds int64) tsapiKey {
	created := time.Time{}
	if key.CreatedAt != nil {
		created = *key.CreatedAt
	}

	expires := time.Time{}
	if key.Expiration != nil {
		expires = *key.Expiration
	}

	response := tsapiKey{
		ID:          strconv.FormatUint(key.ID, util.Base10),
		KeyType:     tsapiDefaultKeyType,
		Description: description,
		ExpirySecs:  &expirySeconds,
		Created:     created,
		Updated:     created,
		Expires:     expires,
		Invalid:     false,
	}

	response.Capabilities.Devices.Create.Reusable = key.Reusable
	response.Capabilities.Devices.Create.Ephemeral = key.Ephemeral
	response.Capabilities.Devices.Create.Preauthorized = preauthorized
	response.Capabilities.Devices.Create.Tags = append([]string(nil), key.Tags...)

	if key.User != nil {
		response.UserID = strconv.FormatUint(uint64(key.User.ID), util.Base10)
	}

	return response
}

func (h *Headscale) tsapiKeyFromPreAuthKey(key types.PreAuthKey) tsapiKey {
	created := time.Time{}
	if key.CreatedAt != nil {
		created = *key.CreatedAt
	}

	expires := time.Time{}
	if key.Expiration != nil {
		expires = *key.Expiration
	}

	metadata, metadataFound := h.tsapi.getKeyMetadata(key.ID)

	preauthorized := !key.Used
	if metadataFound {
		preauthorized = metadata.Preauthorized
	}

	description := ""
	if metadataFound {
		description = metadata.Description
	}

	expirySeconds := tsapiExpirySeconds(key.CreatedAt, key.Expiration)
	if metadataFound {
		s := metadata.ExpirySeconds
		expirySeconds = &s
	}

	response := tsapiKey{
		ID:          strconv.FormatUint(key.ID, util.Base10),
		KeyType:     tsapiDefaultKeyType,
		Description: description,
		ExpirySecs:  expirySeconds,
		Created:     created,
		Updated:     created,
		Expires:     expires,
		Invalid:     key.Validate() != nil,
	}

	response.Capabilities.Devices.Create.Reusable = key.Reusable
	response.Capabilities.Devices.Create.Ephemeral = key.Ephemeral
	response.Capabilities.Devices.Create.Preauthorized = preauthorized
	response.Capabilities.Devices.Create.Tags = append([]string(nil), key.Tags...)

	if key.UserID != nil {
		response.UserID = strconv.FormatUint(uint64(*key.UserID), util.Base10)
	}

	return response
}

func tsapiExpirySeconds(createdAt, expiresAt *time.Time) *int64 {
	if expiresAt == nil {
		return nil
	}

	if createdAt == nil {
		return nil
	}

	seconds := int64(expiresAt.Sub(*createdAt).Seconds())
	if seconds < 0 {
		seconds = 0
	}

	return &seconds
}

func (h *Headscale) tsapiDefaultUserID() (*types.UserID, error) {
	users, err := h.state.ListAllUsers()
	if err != nil {
		return nil, err
	}

	if len(users) == 0 {
		user, _, err := h.state.CreateUser(types.User{Name: "default"})
		if err != nil {
			return nil, err
		}

		uid := types.UserID(user.ID)

		return &uid, nil
	}

	sort.Slice(users, func(i, j int) bool {
		return users[i].ID < users[j].ID
	})

	uid := types.UserID(users[0].ID)

	return &uid, nil
}

func (h *Headscale) tsapiGetPreAuthKeyByID(id uint64) (*types.PreAuthKey, bool, error) {
	keys, err := h.state.ListPreAuthKeys()
	if err != nil {
		return nil, false, err
	}

	for idx := range keys {
		if keys[idx].ID == id {
			return &keys[idx], true, nil
		}
	}

	return nil, false, nil
}

func tsapiParseID(raw string) (uint64, bool) {
	parsed, err := strconv.ParseUint(strings.TrimSpace(raw), util.Base10, 64)
	if err != nil {
		return 0, false
	}

	return parsed, true
}

func tsapiValidateTags(tags []string) error {
	for _, tag := range tags {
		if !strings.HasPrefix(tag, "tag:") {
			return fmt.Errorf("tag %q must start with 'tag:'", tag)
		}
	}

	return nil
}

func tsapiExtractClientCredentials(req *http.Request) (string, string) {
	if clientID, clientSecret, ok := req.BasicAuth(); ok {
		if clientID != "" && clientSecret != "" {
			return clientID, clientSecret
		}
	}

	return req.PostForm.Get("client_id"), req.PostForm.Get("client_secret")
}
