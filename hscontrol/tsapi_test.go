package hscontrol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"testing"
	"time"

	grpcRuntime "github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
	tsclient "tailscale.com/client/tailscale"
	"tailscale.com/tailcfg"
)

func newTestHeadscaleForTSAPI(t *testing.T) *Headscale {
	t.Helper()

	tmpDir := t.TempDir()
	cfg := types.Config{
		NoisePrivateKeyPath: tmpDir + "/noise_private.key",
		Database: types.DatabaseConfig{
			Type: "sqlite3",
			Sqlite: types.SqliteConfig{
				Path: tmpDir + "/headscale_test.db",
			},
		},
		Policy: types.PolicyConfig{
			Mode: types.PolicyModeDB,
		},
	}

	app, err := NewHeadscale(&cfg)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, app.state.Close())
	})

	return app
}

func TestTSAPITerraformLikeKeyFlow(t *testing.T) {
	app := newTestHeadscaleForTSAPI(t)

	expiration := time.Now().Add(24 * time.Hour)
	apiKey, _, err := app.state.CreateAPIKey(&expiration)
	require.NoError(t, err)

	router := app.createRouter(grpcRuntime.NewServeMux())
	server := httptest.NewServer(router)
	t.Cleanup(server.Close)

	oldAcknowledge := tsclient.I_Acknowledge_This_API_Is_Unstable
	tsclient.I_Acknowledge_This_API_Is_Unstable = true
	t.Cleanup(func() {
		tsclient.I_Acknowledge_This_API_Is_Unstable = oldAcknowledge
	})

	client := tsclient.NewClient("-", tsclient.APIKey(apiKey))
	client.BaseURL = server.URL

	ctx := context.Background()
	capabilities := tsclient.KeyCapabilities{}
	capabilities.Devices.Create = tsclient.KeyDeviceCreateCapabilities{
		Reusable:      false,
		Ephemeral:     true,
		Preauthorized: true,
		Tags:          []string{"tag:k8s"},
	}

	secret, created, err := client.CreateKey(ctx, capabilities)
	require.NoError(t, err)
	require.NotEmpty(t, secret)
	require.NotNil(t, created)
	require.NotEmpty(t, created.ID)

	keyIDs, err := client.Keys(ctx)
	require.NoError(t, err)
	require.Contains(t, keyIDs, created.ID)

	fetched, err := client.Key(ctx, created.ID)
	require.NoError(t, err)
	require.Equal(t, created.ID, fetched.ID)

	err = client.DeleteKey(ctx, created.ID)
	require.NoError(t, err)

	_, err = client.Key(ctx, created.ID)
	require.Error(t, err)

	var errResponse tsclient.ErrResponse
	require.True(t, errors.As(err, &errResponse))
	require.Equal(t, http.StatusNotFound, errResponse.Status)
}

func TestTSAPIOAuthTokenAndTokenExchange(t *testing.T) {
	app := newTestHeadscaleForTSAPI(t)

	expiration := time.Now().Add(24 * time.Hour)
	apiKey, _, err := app.state.CreateAPIKey(&expiration)
	require.NoError(t, err)

	router := app.createRouter(grpcRuntime.NewServeMux())

	form := []byte("grant_type=client_credentials")
	oauthReq := httptest.NewRequest(http.MethodPost, "/api/v2/oauth/token", bytes.NewBuffer(form))
	oauthReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	oauthReq.SetBasicAuth("terraform", apiKey)

	oauthResp := httptest.NewRecorder()
	router.ServeHTTP(oauthResp, oauthReq)
	require.Equal(t, http.StatusOK, oauthResp.Code)

	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}
	require.NoError(t, json.Unmarshal(oauthResp.Body.Bytes(), &tokenResp))
	require.NotEmpty(t, tokenResp.AccessToken)

	keysReq := httptest.NewRequest(http.MethodGet, "/api/v2/tailnet/-/keys", nil)
	keysReq.Header.Set("Authorization", AuthPrefix+tokenResp.AccessToken)
	keysResp := httptest.NewRecorder()
	router.ServeHTTP(keysResp, keysReq)
	require.Equal(t, http.StatusOK, keysResp.Code)

	exchangeReq := httptest.NewRequest(
		http.MethodPost,
		"/api/v2/oauth/token-exchange",
		bytes.NewBufferString("client_id=worker&jwt=test-jwt"),
	)
	exchangeReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	exchangeResp := httptest.NewRecorder()
	router.ServeHTTP(exchangeResp, exchangeReq)
	require.Equal(t, http.StatusOK, exchangeResp.Code)

	var exchanged struct {
		AccessToken string `json:"access_token"`
	}
	require.NoError(t, json.Unmarshal(exchangeResp.Body.Bytes(), &exchanged))
	require.NotEmpty(t, exchanged.AccessToken)

	keysReq2 := httptest.NewRequest(http.MethodGet, "/api/v2/tailnet/-/keys", nil)
	keysReq2.Header.Set("Authorization", AuthPrefix+exchanged.AccessToken)
	keysResp2 := httptest.NewRecorder()
	router.ServeHTTP(keysResp2, keysReq2)
	require.Equal(t, http.StatusOK, keysResp2.Code)
}

func TestTSAPIDeviceEndpoints(t *testing.T) {
	app := newTestHeadscaleForTSAPI(t)

	user := app.state.CreateUserForTest("device-user")

	_, err := app.state.SetPolicy([]byte(`{"tagOwners":{"tag:test":["owner@example.com"]}}`))
	require.NoError(t, err)

	node := app.state.CreateNodeForTest(user, "device-host")
	node.Hostinfo = &tailcfg.Hostinfo{
		Hostname:    node.Hostname,
		OS:          "linux",
		IPNVersion:  "1.80.0",
		RoutableIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
	}

	_, _, err = app.state.SaveNode(node.View())
	require.NoError(t, err)

	past := time.Now().Add(-30 * time.Minute)
	_, _, err = app.state.SetNodeExpiry(node.ID, &past)
	require.NoError(t, err)

	expiration := time.Now().Add(24 * time.Hour)
	apiKey, _, err := app.state.CreateAPIKey(&expiration)
	require.NoError(t, err)

	router := app.createRouter(grpcRuntime.NewServeMux())
	legacyID := strconv.FormatUint(uint64(node.ID), 10)
	nodeID := "n" + legacyID

	listReq := httptest.NewRequest(http.MethodGet, "/api/v2/tailnet/-/devices", nil)
	listReq.SetBasicAuth(apiKey, "")
	listResp := httptest.NewRecorder()
	router.ServeHTTP(listResp, listReq)
	require.Equal(t, http.StatusOK, listResp.Code)

	var listBody struct {
		Devices []struct {
			ID     string `json:"id"`
			NodeID string `json:"nodeId"`
		} `json:"devices"`
	}
	require.NoError(t, json.Unmarshal(listResp.Body.Bytes(), &listBody))
	require.Len(t, listBody.Devices, 1)
	require.Equal(t, legacyID, listBody.Devices[0].ID)
	require.Equal(t, nodeID, listBody.Devices[0].NodeID)

	getReq := httptest.NewRequest(http.MethodGet, "/api/v2/device/"+nodeID, nil)
	getReq.SetBasicAuth(apiKey, "")
	getResp := httptest.NewRecorder()
	router.ServeHTTP(getResp, getReq)
	require.Equal(t, http.StatusOK, getResp.Code)
	require.Contains(t, getResp.Body.String(), `"advertisedRoutes"`)
	require.NotContains(t, getResp.Body.String(), `"lastSeen":null`)

	authorizedReq := httptest.NewRequest(
		http.MethodPost,
		"/api/v2/device/"+nodeID+"/authorized",
		bytes.NewBufferString(`{"authorized":true}`),
	)
	authorizedReq.Header.Set("Content-Type", "application/json")
	authorizedReq.SetBasicAuth(apiKey, "")
	authorizedResp := httptest.NewRecorder()
	router.ServeHTTP(authorizedResp, authorizedReq)
	require.Equal(t, http.StatusOK, authorizedResp.Code)

	getReq2 := httptest.NewRequest(http.MethodGet, "/api/v2/device/"+nodeID, nil)
	getReq2.SetBasicAuth(apiKey, "")
	getResp2 := httptest.NewRecorder()
	router.ServeHTTP(getResp2, getReq2)
	require.Equal(t, http.StatusOK, getResp2.Code)

	var deviceBody struct {
		Authorized        bool     `json:"authorized"`
		KeyExpiryDisabled bool     `json:"keyExpiryDisabled"`
		Tags              []string `json:"tags"`
	}
	require.NoError(t, json.Unmarshal(getResp2.Body.Bytes(), &deviceBody))
	require.True(t, deviceBody.Authorized)

	deauthorizeReq := httptest.NewRequest(
		http.MethodPost,
		"/api/v2/device/"+nodeID+"/authorized",
		bytes.NewBufferString(`{"authorized":false}`),
	)
	deauthorizeReq.Header.Set("Content-Type", "application/json")
	deauthorizeReq.SetBasicAuth(apiKey, "")
	deauthorizeResp := httptest.NewRecorder()
	router.ServeHTTP(deauthorizeResp, deauthorizeReq)
	require.Equal(t, http.StatusOK, deauthorizeResp.Code)

	getReqAfterDeauthorize := httptest.NewRequest(http.MethodGet, "/api/v2/device/"+nodeID, nil)
	getReqAfterDeauthorize.SetBasicAuth(apiKey, "")
	getRespAfterDeauthorize := httptest.NewRecorder()
	router.ServeHTTP(getRespAfterDeauthorize, getReqAfterDeauthorize)
	require.Equal(t, http.StatusOK, getRespAfterDeauthorize.Code)
	require.NoError(t, json.Unmarshal(getRespAfterDeauthorize.Body.Bytes(), &deviceBody))
	require.False(t, deviceBody.Authorized)

	reauthorizeReq := httptest.NewRequest(
		http.MethodPost,
		"/api/v2/device/"+nodeID+"/authorized",
		bytes.NewBufferString(`{"authorized":true}`),
	)
	reauthorizeReq.Header.Set("Content-Type", "application/json")
	reauthorizeReq.SetBasicAuth(apiKey, "")
	reauthorizeResp := httptest.NewRecorder()
	router.ServeHTTP(reauthorizeResp, reauthorizeReq)
	require.Equal(t, http.StatusOK, reauthorizeResp.Code)

	keyReq := httptest.NewRequest(
		http.MethodPost,
		"/api/v2/device/"+nodeID+"/key",
		bytes.NewBufferString(`{"keyExpiryDisabled":true}`),
	)
	keyReq.Header.Set("Content-Type", "application/json")
	keyReq.SetBasicAuth(apiKey, "")
	keyResp := httptest.NewRecorder()
	router.ServeHTTP(keyResp, keyReq)
	require.Equal(t, http.StatusOK, keyResp.Code)

	getReq3 := httptest.NewRequest(http.MethodGet, "/api/v2/device/"+nodeID, nil)
	getReq3.SetBasicAuth(apiKey, "")
	getResp3 := httptest.NewRecorder()
	router.ServeHTTP(getResp3, getReq3)
	require.Equal(t, http.StatusOK, getResp3.Code)
	require.NoError(t, json.Unmarshal(getResp3.Body.Bytes(), &deviceBody))
	require.True(t, deviceBody.KeyExpiryDisabled)

	routesReq := httptest.NewRequest(
		http.MethodPost,
		"/api/v2/device/"+nodeID+"/routes",
		bytes.NewBufferString(`{"routes":["0.0.0.0/0"]}`),
	)
	routesReq.Header.Set("Content-Type", "application/json")
	routesReq.SetBasicAuth(apiKey, "")
	routesResp := httptest.NewRecorder()
	router.ServeHTTP(routesResp, routesReq)
	require.Equal(t, http.StatusOK, routesResp.Code)
	require.Contains(t, routesResp.Body.String(), `"enabledRoutes"`)

	getRoutesReq := httptest.NewRequest(http.MethodGet, "/api/v2/device/"+nodeID+"/routes", nil)
	getRoutesReq.SetBasicAuth(apiKey, "")
	getRoutesResp := httptest.NewRecorder()
	router.ServeHTTP(getRoutesResp, getRoutesReq)
	require.Equal(t, http.StatusOK, getRoutesResp.Code)

	var routesBody struct {
		EnabledRoutes []string `json:"enabledRoutes"`
	}
	require.NoError(t, json.Unmarshal(getRoutesResp.Body.Bytes(), &routesBody))
	require.Contains(t, routesBody.EnabledRoutes, "0.0.0.0/0")
	require.Contains(t, routesBody.EnabledRoutes, "::/0")

	tagsReq := httptest.NewRequest(
		http.MethodPost,
		"/api/v2/device/"+nodeID+"/tags",
		bytes.NewBufferString(`{"tags":["tag:test"]}`),
	)
	tagsReq.Header.Set("Content-Type", "application/json")
	tagsReq.SetBasicAuth(apiKey, "")
	tagsResp := httptest.NewRecorder()
	router.ServeHTTP(tagsResp, tagsReq)
	require.Equal(t, http.StatusOK, tagsResp.Code)

	getReq4 := httptest.NewRequest(http.MethodGet, "/api/v2/device/"+nodeID, nil)
	getReq4.SetBasicAuth(apiKey, "")
	getResp4 := httptest.NewRecorder()
	router.ServeHTTP(getResp4, getReq4)
	require.Equal(t, http.StatusOK, getResp4.Code)
	require.NoError(t, json.Unmarshal(getResp4.Body.Bytes(), &deviceBody))
	require.Contains(t, deviceBody.Tags, "tag:test")

	deleteReq := httptest.NewRequest(http.MethodDelete, "/api/v2/device/"+nodeID, nil)
	deleteReq.SetBasicAuth(apiKey, "")
	deleteResp := httptest.NewRecorder()
	router.ServeHTTP(deleteResp, deleteReq)
	require.Equal(t, http.StatusOK, deleteResp.Code)

	getReq5 := httptest.NewRequest(http.MethodGet, "/api/v2/device/"+nodeID, nil)
	getReq5.SetBasicAuth(apiKey, "")
	getResp5 := httptest.NewRecorder()
	router.ServeHTTP(getResp5, getReq5)
	require.Equal(t, http.StatusNotFound, getResp5.Code)
}

func TestTSAPIACLAndUsersEndpoints(t *testing.T) {
	app := newTestHeadscaleForTSAPI(t)

	user1 := app.state.CreateUserForTest("alice")
	user2 := app.state.CreateUserForTest("bob")

	node := app.state.CreateNodeForTest(user1, "alice-host")
	node.LastSeen = ptrTo(time.Now().Add(-time.Minute))

	_, _, err := app.state.SaveNode(node.View())
	require.NoError(t, err)

	expiration := time.Now().Add(24 * time.Hour)
	apiKey, _, err := app.state.CreateAPIKey(&expiration)
	require.NoError(t, err)

	router := app.createRouter(grpcRuntime.NewServeMux())

	validateReq := httptest.NewRequest(
		http.MethodPost,
		"/api/v2/tailnet/-/acl/validate",
		bytes.NewBufferString(`{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}`),
	)
	validateReq.Header.Set("Content-Type", "application/hujson")
	validateReq.SetBasicAuth(apiKey, "")
	validateResp := httptest.NewRecorder()
	router.ServeHTTP(validateResp, validateReq)
	require.Equal(t, http.StatusOK, validateResp.Code)

	validateBadReq := httptest.NewRequest(
		http.MethodPost,
		"/api/v2/tailnet/-/acl/validate",
		bytes.NewBufferString(`{"acls":[`),
	)
	validateBadReq.Header.Set("Content-Type", "application/hujson")
	validateBadReq.SetBasicAuth(apiKey, "")
	validateBadResp := httptest.NewRecorder()
	router.ServeHTTP(validateBadResp, validateBadReq)
	require.Equal(t, http.StatusBadRequest, validateBadResp.Code)

	validateTestsReq := httptest.NewRequest(
		http.MethodPost,
		"/api/v2/tailnet/-/acl/validate",
		bytes.NewBufferString(`[{"src":"alice@example.com","accept":["100.64.0.1:80"]}]`),
	)
	validateTestsReq.Header.Set("Content-Type", "application/json")
	validateTestsReq.SetBasicAuth(apiKey, "")
	validateTestsResp := httptest.NewRecorder()
	router.ServeHTTP(validateTestsResp, validateTestsReq)
	require.Equal(t, http.StatusOK, validateTestsResp.Code)
	require.Equal(t, "", validateTestsResp.Body.String())

	setACLReq := httptest.NewRequest(
		http.MethodPost,
		"/api/v2/tailnet/-/acl",
		bytes.NewBufferString(`{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}],"tagOwners":{"tag:dev":["owner@example.com"]}}`),
	)
	setACLReq.Header.Set("Content-Type", "application/hujson")
	setACLReq.SetBasicAuth(apiKey, "")
	setACLResp := httptest.NewRecorder()
	router.ServeHTTP(setACLResp, setACLReq)
	require.Equal(t, http.StatusOK, setACLResp.Code, setACLResp.Body.String())
	require.NotEmpty(t, setACLResp.Header().Get("ETag"))
	require.Contains(t, setACLResp.Body.String(), `"tagOwners"`)

	getACLReq := httptest.NewRequest(http.MethodGet, "/api/v2/tailnet/-/acl", nil)
	getACLReq.Header.Set("Accept", "application/hujson")
	getACLReq.SetBasicAuth(apiKey, "")
	getACLResp := httptest.NewRecorder()
	router.ServeHTTP(getACLResp, getACLReq)
	require.Equal(t, http.StatusOK, getACLResp.Code)
	require.Contains(t, getACLResp.Body.String(), "tagOwners")

	getACLDetailsReq := httptest.NewRequest(http.MethodGet, "/api/v2/tailnet/-/acl?details=1", nil)
	getACLDetailsReq.Header.Set("Accept", "application/hujson")
	getACLDetailsReq.SetBasicAuth(apiKey, "")
	getACLDetailsResp := httptest.NewRecorder()
	router.ServeHTTP(getACLDetailsResp, getACLDetailsReq)
	require.Equal(t, http.StatusOK, getACLDetailsResp.Code)

	var aclDetailsBody struct {
		ACL      []byte   `json:"acl"`
		Warnings []string `json:"warnings"`
	}
	require.NoError(t, json.Unmarshal(getACLDetailsResp.Body.Bytes(), &aclDetailsBody))
	require.Contains(t, string(aclDetailsBody.ACL), "tagOwners")

	setACLMismatchReq := httptest.NewRequest(
		http.MethodPost,
		"/api/v2/tailnet/-/acl",
		bytes.NewBufferString(`{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}`),
	)
	setACLMismatchReq.Header.Set("Content-Type", "application/hujson")
	setACLMismatchReq.Header.Set("If-Match", `"mismatch"`)
	setACLMismatchReq.SetBasicAuth(apiKey, "")
	setACLMismatchResp := httptest.NewRecorder()
	router.ServeHTTP(setACLMismatchResp, setACLMismatchReq)
	require.Equal(t, http.StatusPreconditionFailed, setACLMismatchResp.Code)

	usersReq := httptest.NewRequest(http.MethodGet, "/api/v2/tailnet/-/users", nil)
	usersReq.SetBasicAuth(apiKey, "")
	usersResp := httptest.NewRecorder()
	router.ServeHTTP(usersResp, usersReq)
	require.Equal(t, http.StatusOK, usersResp.Code)

	var usersBody struct {
		Users []struct {
			ID        string `json:"id"`
			Role      string `json:"role"`
			Login     string `json:"loginName"`
			Tailnet   string `json:"tailnetId"`
			Type      string `json:"type"`
			Status    string `json:"status"`
			Devices   int    `json:"deviceCount"`
			Connected bool   `json:"currentlyConnected"`
		} `json:"users"`
	}
	require.NoError(t, json.Unmarshal(usersResp.Body.Bytes(), &usersBody))
	require.GreaterOrEqual(t, len(usersBody.Users), 2)
	require.Equal(t, "owner", usersBody.Users[0].Role)
	require.Equal(t, "-", usersBody.Users[0].Tailnet)
	require.Equal(t, "member", usersBody.Users[1].Role)

	ownerUsersReq := httptest.NewRequest(http.MethodGet, "/api/v2/tailnet/-/users?role=owner", nil)
	ownerUsersReq.SetBasicAuth(apiKey, "")
	ownerUsersResp := httptest.NewRecorder()
	router.ServeHTTP(ownerUsersResp, ownerUsersReq)
	require.Equal(t, http.StatusOK, ownerUsersResp.Code)
	require.Contains(t, ownerUsersResp.Body.String(), `"role":"owner"`)

	sharedUsersReq := httptest.NewRequest(http.MethodGet, "/api/v2/tailnet/-/users?type=shared", nil)
	sharedUsersReq.SetBasicAuth(apiKey, "")
	sharedUsersResp := httptest.NewRecorder()
	router.ServeHTTP(sharedUsersResp, sharedUsersReq)
	require.Equal(t, http.StatusOK, sharedUsersResp.Code)
	require.Contains(t, sharedUsersResp.Body.String(), `"users":[]`)

	userReq := httptest.NewRequest(http.MethodGet, "/api/v2/users/"+strconv.FormatUint(uint64(user1.ID), 10), nil)
	userReq.SetBasicAuth(apiKey, "")
	userResp := httptest.NewRecorder()
	router.ServeHTTP(userResp, userReq)
	require.Equal(t, http.StatusOK, userResp.Code)
	require.Contains(t, userResp.Body.String(), `"id":"`+strconv.FormatUint(uint64(user1.ID), 10)+`"`)
	require.Contains(t, userResp.Body.String(), `"loginName":"`+user1.Name+`"`)

	missingUserReq := httptest.NewRequest(http.MethodGet, "/api/v2/users/999999", nil)
	missingUserReq.SetBasicAuth(apiKey, "")
	missingUserResp := httptest.NewRecorder()
	router.ServeHTTP(missingUserResp, missingUserReq)
	require.Equal(t, http.StatusNotFound, missingUserResp.Code)

	_ = user2
}

func ptrTo[T any](v T) *T {
	return &v
}
