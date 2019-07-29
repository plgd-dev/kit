package redirect

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/gofrs/uuid"
	"github.com/patrickmn/go-cache"
	"golang.org/x/oauth2"

	router "github.com/gorilla/mux"
)

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("%v %v\n", r.Method, r.RequestURI)
		// Call the next handler, which can be another middleware in the chain, or the final handler.
		next.ServeHTTP(w, r)
	})
}

// OnRedirectFunc called when handler serve redirect request.
// data can be code or token depends on what you set in GetAuthCodeURL.
type OnRedirectFunc func(ctx context.Context, data string) (nextRedirectURI string, err error)

type Handler struct {
	cache               *cache.Cache
	redirectToResultURI string
	errors              func(error)
}

func (h *Handler) RedirectResult(w http.ResponseWriter, r *http.Request, errRes error) {
	u, err := url.Parse(h.redirectToResultURI)
	if err != nil {
		h.errors(fmt.Errorf("cannot redirect result: %v", err))
	}
	q := u.Query()
	if err != nil {
		h.errors(errRes)
		q.Set("success", "false")
		q.Set("error", errRes.Error())
	} else {
		q.Set("success", "true")
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusTemporaryRedirect)
}

func (h *Handler) OAuthCallback(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")
	state := r.FormValue("state")
	onRedirect, ok := h.cache.Get(state)

	if !ok {
		h.RedirectResult(w, r, fmt.Errorf("cannot handle  OAuthCallback for %v: not found", state))
		return
	}
	h.cache.Delete(state)

	nextRedirectURI, err := onRedirect.(OnRedirectFunc)(r.Context(), code)
	if err != nil {
		h.RedirectResult(w, r, err)
		return
	}
	if nextRedirectURI != "" {
		http.Redirect(w, r, nextRedirectURI, http.StatusTemporaryRedirect)
		return
	}
	h.RedirectResult(w, r, err)
}

func healthCheck(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

type Server struct {
	httpServer *http.Server
	cache      *cache.Cache
	uri        string
	errors     func(error)
}

func NewServer(uri, redirectToResultURI string, waitTime time.Duration, errors func(error)) (*Server, error) {
	if errors == nil {
		return nil, fmt.Errorf("invalid errors argument")
	}
	data, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", data.Host)
	if err != nil {
		return nil, err
	}
	cache := cache.New(waitTime, cache.DefaultExpiration)
	h := &Handler{
		cache:               cache,
		errors:              errors,
		redirectToResultURI: redirectToResultURI,
	}

	r := router.NewRouter()
	r.Use(loggingMiddleware)

	// health check
	r.HandleFunc("/", healthCheck).Methods("GET")
	// OAuthCallback
	r.HandleFunc(data.Path, h.OAuthCallback).Methods("GET")

	s := &Server{
		uri:        data.String(),
		cache:      cache,
		httpServer: &http.Server{Handler: r},
		errors:     errors,
	}
	go s.listen(ln)

	return s, nil
}

func (s *Server) listen(ln net.Listener) {
	err := s.httpServer.Serve(ln)
	if err != nil {
		s.errors(err)
	}
}

func (s *Server) Close() error {
	return s.httpServer.Close()
}

func (s *Server) GetAuthCodeURL(onRedirect OnRedirectFunc, cfg oauth2.Config, options ...oauth2.AuthCodeOption) (authCodeURL string, err error) {
	cfg.RedirectURL = s.uri
	state, err := uuid.NewV4()
	if err != nil {
		return "", err
	}
	s.cache.Add(state.String(), onRedirect, cache.DefaultExpiration)
	url := cfg.AuthCodeURL(state.String(), options...)
	return url, nil
}
