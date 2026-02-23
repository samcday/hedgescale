package hscontrol

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/rs/zerolog/log"
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
