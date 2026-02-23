package hscontrol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	grpcRuntime "github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
	tsclient "tailscale.com/client/tailscale"
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
			Mode: types.PolicyModeFile,
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
