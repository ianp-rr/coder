package oauth2provider_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"golang.org/x/xerrors"

	"cdr.dev/slog/v3/sloggers/slogtest"
	"github.com/coder/coder/v2/coderd/audit"
	"github.com/coder/coder/v2/coderd/database"
	"github.com/coder/coder/v2/coderd/database/dbgen"
	"github.com/coder/coder/v2/coderd/database/dbmock"
	"github.com/coder/coder/v2/coderd/database/dbtestutil"
	"github.com/coder/coder/v2/coderd/oauth2provider"
	"github.com/coder/coder/v2/coderd/tracing"
	"github.com/coder/coder/v2/coderd/util/ptr"
	"github.com/coder/coder/v2/codersdk"
	"github.com/coder/coder/v2/testutil"
)

// TestCreateDynamicClientRegistration_DCREnabled is a focused unit test on
// the RFC 7591 handler itself, bypassing the full coderdtest HTTP server. It
// verifies the dynamic-client-registration-enabled gate: registration
// succeeds once an admin explicitly enables DCR, is rejected with 403 when
// explicitly disabled, and defaults to disabled when the setting has never
// been configured.
func TestCreateDynamicClientRegistration_DCREnabled(t *testing.T) {
	t.Parallel()

	accessURL, err := url.Parse("https://oauth2-registration-dcr-test.example.com")
	require.NoError(t, err)

	tests := []struct {
		name string
		// configureDCR is nil for "never configured".
		configureDCR *bool
		wantStatus   int
	}{
		{
			name:         "EnabledAllowsRegistration",
			configureDCR: ptr.Ref(true),
			wantStatus:   http.StatusCreated,
		},
		{
			name:         "DisabledRejectsRegistration",
			configureDCR: ptr.Ref(false),
			wantStatus:   http.StatusForbidden,
		},
		{
			name:         "NeverConfiguredDefaultsToDisabled",
			configureDCR: nil,
			wantStatus:   http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := testutil.Context(t, testutil.WaitLong)

			db, _ := dbtestutil.NewDB(t)
			if tt.configureDCR != nil {
				err := db.UpsertOAuth2DCREnabled(ctx, *tt.configureDCR)
				require.NoError(t, err)
			}

			logger := slogtest.Make(t, nil)
			auditor := audit.NewNop()
			// audit.InitRequest requires the ResponseWriter to be a
			// *tracing.StatusWriter, which normally comes from the
			// middleware chain in coderd.go; wrap it here to match.
			handler := tracing.StatusWriterMiddleware(oauth2provider.CreateDynamicClientRegistration(db, accessURL, &auditor, logger))

			req := codersdk.OAuth2ClientRegistrationRequest{
				RedirectURIs: []string{"https://example.com/callback"},
			}
			body, err := json.Marshal(req)
			require.NoError(t, err)

			r := httptest.NewRequest(http.MethodPost, "/oauth2/register", bytes.NewReader(body)).WithContext(ctx)
			r.Header.Set("Content-Type", "application/json")
			rw := httptest.NewRecorder()

			handler.ServeHTTP(rw, r)
			require.Equal(t, tt.wantStatus, rw.Code)

			if tt.wantStatus != http.StatusForbidden {
				return
			}

			var errResp map[string]string
			require.NoError(t, json.Unmarshal(rw.Body.Bytes(), &errResp))
			require.Equal(t, "invalid_request", errResp["error"])
			require.Contains(t, errResp["error_description"], "disabled")
		})
	}
}

// TestCreateDynamicClientRegistration_ClientType verifies that whether a
// client_secret is minted, and what client_type is persisted, follows the
// requested token_endpoint_auth_method (RFC 7591 §2, OAuth 2.1 §2.1).
func TestCreateDynamicClientRegistration_ClientType(t *testing.T) {
	t.Parallel()

	accessURL, err := url.Parse("https://oauth2-registration-client-type-test.example.com")
	require.NoError(t, err)

	tests := []struct {
		name string
		req  codersdk.OAuth2ClientRegistrationRequest

		wantClientType string
		wantSecret     bool
	}{
		{
			name: "DefaultAuthMethodIsConfidential",
			req: codersdk.OAuth2ClientRegistrationRequest{
				RedirectURIs: []string{"https://example.com/callback"},
			},
			wantClientType: "confidential",
			wantSecret:     true,
		},
		{
			name: "ClientSecretPostIsConfidential",
			req: codersdk.OAuth2ClientRegistrationRequest{
				RedirectURIs:            []string{"https://example.com/callback"},
				TokenEndpointAuthMethod: codersdk.OAuth2TokenEndpointAuthMethodClientSecretPost,
			},
			wantClientType: "confidential",
			wantSecret:     true,
		},
		{
			name: "NoneIsPublicWithNoSecret",
			req: codersdk.OAuth2ClientRegistrationRequest{
				RedirectURIs:            []string{"https://example.com/callback"},
				TokenEndpointAuthMethod: codersdk.OAuth2TokenEndpointAuthMethodNone,
			},
			wantClientType: "public",
			wantSecret:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := testutil.Context(t, testutil.WaitLong)

			db, _ := dbtestutil.NewDB(t)
			require.NoError(t, db.UpsertOAuth2DCREnabled(ctx, true))

			logger := slogtest.Make(t, nil)
			auditor := audit.NewNop()
			handler := tracing.StatusWriterMiddleware(oauth2provider.CreateDynamicClientRegistration(db, accessURL, &auditor, logger))

			body, err := json.Marshal(tt.req)
			require.NoError(t, err)

			r := httptest.NewRequest(http.MethodPost, "/oauth2/register", bytes.NewReader(body)).WithContext(ctx)
			r.Header.Set("Content-Type", "application/json")
			rw := httptest.NewRecorder()

			handler.ServeHTTP(rw, r)
			require.Equal(t, http.StatusCreated, rw.Code)

			var resp codersdk.OAuth2ClientRegistrationResponse
			require.NoError(t, json.Unmarshal(rw.Body.Bytes(), &resp))

			// RFC 7591 §3.2.1: client_secret is omitted entirely for a
			// client that was not issued one.
			if tt.wantSecret {
				require.NotEmpty(t, resp.ClientSecret)
			} else {
				require.Empty(t, resp.ClientSecret)
			}

			clientID, err := uuid.Parse(resp.ClientID)
			require.NoError(t, err)

			app, err := db.GetOAuth2ProviderAppByClientID(ctx, clientID)
			require.NoError(t, err)
			require.Equal(t, tt.wantClientType, app.ClientType.String)

			secrets, err := db.GetOAuth2ProviderAppSecretsByAppID(ctx, clientID)
			require.NoError(t, err)
			if tt.wantSecret {
				require.Len(t, secrets, 1)
			} else {
				require.Empty(t, secrets)
			}
		})
	}
}

// TestCreateDynamicClientRegistration_Transaction verifies that the app insert
// and the secret insert share a single database transaction, so a failure
// partway through can't leave a permanently committed, orphaned app row with
// no matching secret.
//
// A mock store is used because the failure needs to be injected between the
// two inserts, which isn't reachable through the public registration API
// against a real database (the failing insert's unique secret_prefix is
// generated internally and can't be forced to collide from the outside).
// mDB.EXPECT().InTx(...).Times(1) is the key assertion: it fails the test if
// the two inserts are ever changed back to being independent, unwrapped
// db.InsertX calls, since that path never calls InTx at all.
func TestCreateDynamicClientRegistration_Transaction(t *testing.T) {
	t.Parallel()

	accessURL, err := url.Parse("https://oauth2-registration-tx-test.example.com")
	require.NoError(t, err)

	tests := []struct {
		name            string
		secretInsertErr error
		wantStatus      int
	}{
		{
			name:       "BothInsertsShareOneTransaction",
			wantStatus: http.StatusCreated,
		},
		{
			name:            "SecretInsertFailureFailsTheWholeRegistration",
			secretInsertErr: xerrors.New("simulated secret insert failure"),
			wantStatus:      http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := testutil.Context(t, testutil.WaitLong)

			ctrl := gomock.NewController(t)
			mDB := dbmock.NewMockStore(ctrl)

			mDB.EXPECT().GetOAuth2DCREnabled(gomock.Any()).Return(true, nil).Times(1)

			// InTx must invoke the closure against the same store handle
			// (the mock itself, standing in for `tx`) so the two inserts
			// below are recorded as happening inside one shared
			// transaction, not as two independently committed statements.
			mDB.EXPECT().InTx(gomock.Any(), gomock.Any()).DoAndReturn(
				func(f func(database.Store) error, _ *database.TxOptions) error {
					return f(mDB)
				},
			).Times(1)

			appCall := mDB.EXPECT().InsertOAuth2ProviderApp(gomock.Any(), gomock.Any()).
				Return(database.OAuth2ProviderApp{
					ID:         uuid.New(),
					ClientType: sql.NullString{String: "confidential", Valid: true},
				}, nil).
				Times(1)

			secretCall := mDB.EXPECT().InsertOAuth2ProviderAppSecret(gomock.Any(), gomock.Any()).
				Return(database.OAuth2ProviderAppSecret{}, tt.secretInsertErr).
				Times(1)

			// The secret insert can only run after the app insert, matching
			// registration.go's literal ordering inside the InTx closure.
			gomock.InOrder(appCall, secretCall)

			logger := slogtest.Make(t, &slogtest.Options{IgnoreErrors: tt.secretInsertErr != nil})
			auditor := audit.NewNop()
			handler := tracing.StatusWriterMiddleware(oauth2provider.CreateDynamicClientRegistration(mDB, accessURL, &auditor, logger))

			req := codersdk.OAuth2ClientRegistrationRequest{
				RedirectURIs: []string{"https://example.com/callback"},
			}
			body, err := json.Marshal(req)
			require.NoError(t, err)

			r := httptest.NewRequest(http.MethodPost, "/oauth2/register", bytes.NewReader(body)).WithContext(ctx)
			r.Header.Set("Content-Type", "application/json")
			rw := httptest.NewRecorder()

			handler.ServeHTTP(rw, r)
			require.Equal(t, tt.wantStatus, rw.Code)
		})
	}
}

// TestCreateDynamicClientRegistration_PublicClientSkipsSecretInsert verifies
// that a public client's registration issues no InsertOAuth2ProviderAppSecret
// call at all, rather than inserting a row with an empty secret.
func TestCreateDynamicClientRegistration_PublicClientSkipsSecretInsert(t *testing.T) {
	t.Parallel()
	ctx := testutil.Context(t, testutil.WaitLong)

	accessURL, err := url.Parse("https://oauth2-registration-public-tx-test.example.com")
	require.NoError(t, err)

	ctrl := gomock.NewController(t)
	mDB := dbmock.NewMockStore(ctrl)

	mDB.EXPECT().GetOAuth2DCREnabled(gomock.Any()).Return(true, nil).Times(1)
	mDB.EXPECT().InTx(gomock.Any(), gomock.Any()).DoAndReturn(
		func(f func(database.Store) error, _ *database.TxOptions) error {
			return f(mDB)
		},
	).Times(1)
	mDB.EXPECT().InsertOAuth2ProviderApp(gomock.Any(), gomock.Any()).
		Return(database.OAuth2ProviderApp{
			ID:         uuid.New(),
			ClientType: sql.NullString{String: "public", Valid: true},
		}, nil).
		Times(1)
	// The absence of an InsertOAuth2ProviderAppSecret expectation is the
	// assertion: gomock fails on an unexpected call.

	logger := slogtest.Make(t, nil)
	auditor := audit.NewNop()
	handler := tracing.StatusWriterMiddleware(oauth2provider.CreateDynamicClientRegistration(mDB, accessURL, &auditor, logger))

	req := codersdk.OAuth2ClientRegistrationRequest{
		RedirectURIs:            []string{"https://example.com/callback"},
		TokenEndpointAuthMethod: codersdk.OAuth2TokenEndpointAuthMethodNone,
	}
	body, err := json.Marshal(req)
	require.NoError(t, err)

	r := httptest.NewRequest(http.MethodPost, "/oauth2/register", bytes.NewReader(body)).WithContext(ctx)
	r.Header.Set("Content-Type", "application/json")
	rw := httptest.NewRecorder()

	handler.ServeHTTP(rw, r)
	require.Equal(t, http.StatusCreated, rw.Code)
}

// TestUpdateClientConfiguration_ClientTypeIsImmutable verifies that an
// RFC 7592 update cannot move a registered client between public and
// confidential. Allowing it would either drop the secret requirement for a
// client that has a secret, or mark a client confidential when it has no
// secret and no way to be issued one, permanently breaking its token
// exchange. Switching between the two confidential auth methods stays
// allowed, since it changes nothing about how the client authenticates.
func TestUpdateClientConfiguration_ClientTypeIsImmutable(t *testing.T) {
	t.Parallel()

	accessURL, err := url.Parse("https://oauth2-registration-immutable-type-test.example.com")
	require.NoError(t, err)

	tests := []struct {
		name              string
		registerAs        codersdk.OAuth2TokenEndpointAuthMethod
		updateTo          codersdk.OAuth2TokenEndpointAuthMethod
		wantStatus        int
		wantFinalCallback string
		wantClientType    string
	}{
		{
			name:           "ConfidentialToPublicIsRejected",
			registerAs:     codersdk.OAuth2TokenEndpointAuthMethodClientSecretBasic,
			updateTo:       codersdk.OAuth2TokenEndpointAuthMethodNone,
			wantStatus:     http.StatusBadRequest,
			wantClientType: "confidential",
		},
		{
			name:           "PublicToConfidentialIsRejected",
			registerAs:     codersdk.OAuth2TokenEndpointAuthMethodNone,
			updateTo:       codersdk.OAuth2TokenEndpointAuthMethodClientSecretBasic,
			wantStatus:     http.StatusBadRequest,
			wantClientType: "public",
		},
		{
			// Both are confidential, so the guard must not fire.
			name:              "BasicToPostIsAllowed",
			registerAs:        codersdk.OAuth2TokenEndpointAuthMethodClientSecretBasic,
			updateTo:          codersdk.OAuth2TokenEndpointAuthMethodClientSecretPost,
			wantStatus:        http.StatusOK,
			wantFinalCallback: "https://example.com/updated-callback",
			wantClientType:    "confidential",
		},
		{
			name:              "PublicToPublicIsAllowed",
			registerAs:        codersdk.OAuth2TokenEndpointAuthMethodNone,
			updateTo:          codersdk.OAuth2TokenEndpointAuthMethodNone,
			wantStatus:        http.StatusOK,
			wantFinalCallback: "https://example.com/updated-callback",
			wantClientType:    "public",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := testutil.Context(t, testutil.WaitLong)

			db, _ := dbtestutil.NewDB(t)
			require.NoError(t, db.UpsertOAuth2DCREnabled(ctx, true))

			logger := slogtest.Make(t, nil)
			auditor := audit.NewNop()

			// Register the client first, so the update runs against a real
			// persisted client_type rather than a hand-built fixture.
			createHandler := tracing.StatusWriterMiddleware(oauth2provider.CreateDynamicClientRegistration(db, accessURL, &auditor, logger))
			createBody, err := json.Marshal(codersdk.OAuth2ClientRegistrationRequest{
				RedirectURIs:            []string{"https://example.com/callback"},
				TokenEndpointAuthMethod: tt.registerAs,
			})
			require.NoError(t, err)

			createReq := httptest.NewRequest(http.MethodPost, "/oauth2/register", bytes.NewReader(createBody)).WithContext(ctx)
			createReq.Header.Set("Content-Type", "application/json")
			createRW := httptest.NewRecorder()
			createHandler.ServeHTTP(createRW, createReq)
			require.Equal(t, http.StatusCreated, createRW.Code)

			var created codersdk.OAuth2ClientRegistrationResponse
			require.NoError(t, json.Unmarshal(createRW.Body.Bytes(), &created))
			clientID, err := uuid.Parse(created.ClientID)
			require.NoError(t, err)

			updateHandler := tracing.StatusWriterMiddleware(oauth2provider.UpdateClientConfiguration(db, &auditor, logger))
			updateBody, err := json.Marshal(codersdk.OAuth2ClientRegistrationRequest{
				RedirectURIs:            []string{"https://example.com/updated-callback"},
				TokenEndpointAuthMethod: tt.updateTo,
			})
			require.NoError(t, err)

			// The handler reads client_id via chi.URLParam, which normally
			// comes from the router in coderd.go.
			rctx := chi.NewRouteContext()
			rctx.URLParams.Add("client_id", clientID.String())
			updateCtx := context.WithValue(ctx, chi.RouteCtxKey, rctx)

			updateReq := httptest.NewRequest(http.MethodPut, "/oauth2/clients/"+clientID.String(), bytes.NewReader(updateBody)).WithContext(updateCtx)
			updateReq.Header.Set("Content-Type", "application/json")
			updateRW := httptest.NewRecorder()
			updateHandler.ServeHTTP(updateRW, updateReq)
			require.Equal(t, tt.wantStatus, updateRW.Code)

			app, err := db.GetOAuth2ProviderAppByClientID(ctx, clientID)
			require.NoError(t, err)

			// client_type is what IsPublic() reads to decide whether the token
			// endpoint validates a secret, so it must be unchanged whether the
			// update was accepted or rejected.
			require.Equal(t, tt.wantClientType, app.ClientType.String)

			if tt.wantStatus != http.StatusOK {
				var errResp map[string]string
				require.NoError(t, json.Unmarshal(updateRW.Body.Bytes(), &errResp))
				require.Equal(t, "invalid_client_metadata", errResp["error"])
				// The rejection must leave the whole update unapplied, not
				// just the client_type field.
				require.Equal(t, "https://example.com/callback", app.CallbackURL)
				return
			}

			require.Equal(t, tt.wantFinalCallback, app.CallbackURL)
			require.Equal(t, string(tt.updateTo), app.TokenEndpointAuthMethod.String)
		})
	}
}

// TestUpdateClientConfiguration_LegacyAuthMethodMismatch covers clients that
// registered before client_type was derived from token_endpoint_auth_method.
// Registration persisted the requested auth method verbatim while hardcoding
// client_type to "confidential", and "none" has always passed validation, so
// apps stored as confidential with an auth method of "none" exist in any
// deployment where a native or MCP client self-registered. That is the exact
// population public clients are for.
//
// Such a client must still be able to manage its registration. Comparing only
// the derived client type would reject it forever, including when it resends
// the metadata GET reports, leaving re-registration as the only recovery. It
// must also not be silently converted to public, since it holds a secret that
// would stop being required.
func TestUpdateClientConfiguration_LegacyAuthMethodMismatch(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		updateTo codersdk.OAuth2TokenEndpointAuthMethod
	}{
		{
			// The read-modify-write shape: echo back what GET reports.
			name:     "ResendingStoredAuthMethodIsAccepted",
			updateTo: codersdk.OAuth2TokenEndpointAuthMethodNone,
		},
		{
			// Moving to a secret-based method matches the stored confidential
			// type, so it is allowed and repairs the divergence.
			name:     "MovingToSecretBasedMethodIsAccepted",
			updateTo: codersdk.OAuth2TokenEndpointAuthMethodClientSecretBasic,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := testutil.Context(t, testutil.WaitLong)

			db, _ := dbtestutil.NewDB(t)
			require.NoError(t, db.UpsertOAuth2DCREnabled(ctx, true))

			legacy := dbgen.OAuth2ProviderApp(t, db, database.OAuth2ProviderApp{
				CallbackURL:             "https://example.com/callback",
				RedirectUris:            []string{"https://example.com/callback"},
				ClientType:              sql.NullString{String: "confidential", Valid: true},
				TokenEndpointAuthMethod: sql.NullString{String: "none", Valid: true},
				DynamicallyRegistered:   sql.NullBool{Bool: true, Valid: true},
			})
			// Registration minted a secret unconditionally back then.
			_ = dbgen.OAuth2ProviderAppSecret(t, db, database.OAuth2ProviderAppSecret{AppID: legacy.ID})

			logger := slogtest.Make(t, nil)
			auditor := audit.NewNop()
			handler := tracing.StatusWriterMiddleware(oauth2provider.UpdateClientConfiguration(db, &auditor, logger))

			body, err := json.Marshal(codersdk.OAuth2ClientRegistrationRequest{
				RedirectURIs:            []string{"https://example.com/updated-callback"},
				TokenEndpointAuthMethod: tt.updateTo,
			})
			require.NoError(t, err)

			rctx := chi.NewRouteContext()
			rctx.URLParams.Add("client_id", legacy.ID.String())
			r := httptest.NewRequest(http.MethodPut, "/oauth2/clients/"+legacy.ID.String(),
				bytes.NewReader(body)).WithContext(context.WithValue(ctx, chi.RouteCtxKey, rctx))
			r.Header.Set("Content-Type", "application/json")
			rw := httptest.NewRecorder()

			handler.ServeHTTP(rw, r)
			require.Equal(t, http.StatusOK, rw.Code, "body: %s", rw.Body.String())

			app, err := db.GetOAuth2ProviderAppByClientID(ctx, legacy.ID)
			require.NoError(t, err)
			require.Equal(t, "https://example.com/updated-callback", app.CallbackURL)
			require.Equal(t, string(tt.updateTo), app.TokenEndpointAuthMethod.String)

			// The update must not convert the client to public. It still holds
			// a secret, and IsPublic() reading "public" here would stop the
			// token endpoint from requiring it.
			require.Equal(t, "confidential", app.ClientType.String)
			require.False(t, app.IsPublic())
			secrets, err := db.GetOAuth2ProviderAppSecretsByAppID(ctx, legacy.ID)
			require.NoError(t, err)
			require.Len(t, secrets, 1)
		})
	}
}
