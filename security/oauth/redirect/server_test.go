package redirect

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"golang.org/x/oauth2"
)

func setupMockOAuthServer(t *testing.T) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("/auth", r.RequestURI)
		v := r.FormValue("redirect_uri")
		state := r.FormValue("state")
		require.NotEmpty(t, v)
		u, err := url.Parse(v)
		require.NoError(t, err)
		q := u.Query()
		q.Set("state", state)
		q.Set("code", "code")
		u.RawQuery = q.Encode()
		http.Redirect(w, r, u.String(), http.StatusTemporaryRedirect)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("/")
		// Should return authorization code back to the user
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("/token")
		// Should return acccess token back to the user
		w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
		w.Write([]byte("access_token=mocktoken&scope=user&token_type=bearer"))
	})

	server := httptest.NewServer(mux)

	return server
}

func TestServer_GetAuthCodeURL(t *testing.T) {
	oauthServer := setupMockOAuthServer(t)
	defer oauthServer.Close()

	type args struct {
		onRedirect OnRedirectFunc
		cfg        oauth2.Config
		options    []oauth2.AuthCodeOption
	}
	tests := []struct {
		name            string
		args            args
		wantAuthCodeURL string
		wantErr         bool
	}{
		{
			name: "valid",
			args: args{
				cfg: oauth2.Config{
					ClientID:     "1",
					ClientSecret: "2",
					Endpoint: oauth2.Endpoint{
						AuthURL:  oauthServer.URL + "/auth",
						TokenURL: oauthServer.URL + "/token",
					},
				},
				onRedirect: func(ctx context.Context, token string) error {
					fmt.Println("on redirect")
					require.Equal(t, "code", token)
					return nil
				},
			},
		},
	}

	s, err := NewServer("http://localhost:48694/authcbk", time.Second*1, func(err error) {
		t.Log(err)
		//require.NoError(t, err)
	})
	require.NoError(t, err)
	defer func() {
		err := s.Close()
		require.NoError(t, err)
	}()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotAuthCodeURL, err := s.GetAuthCodeURL(tt.args.onRedirect, tt.args.cfg, tt.args.options...)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			u, err := url.Parse(gotAuthCodeURL)
			require.NoError(t, err)
			p, err := url.Parse(tt.args.cfg.Endpoint.AuthURL)
			require.NoError(t, err)
			require.Equal(t, p.Host, u.Host)
			resp, err := http.Get(gotAuthCodeURL)
			require.NoError(t, err)
			resp.Body.Close()
		})
	}
}
