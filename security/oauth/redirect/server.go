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
type OnRedirectFunc func(ctx context.Context, data string) (err error)

type Handler struct {
	cache               *cache.Cache
	redirectToResultURI string
	errors              func(error)
}

func (h *Handler) RedirectResult(w http.ResponseWriter, r *http.Request, redirectURI string, errRes error) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		h.errors(fmt.Errorf("cannot redirect result: %v", err))
		return
	}
	q := u.Query()
	if errRes != nil {
		h.errors(errRes)
		q.Set("success", "false")
		q.Set("error", errRes.Error())
	} else {
		q.Set("success", "true")
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusTemporaryRedirect)
}

type redirect struct {
	finalRedirectURL string
	onRedirect       OnRedirectFunc
}

func (h *Handler) OAuthCallback(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")
	state := r.FormValue("state")
	c, ok := h.cache.Get(state)

	if !ok {
		h.errors(fmt.Errorf("cannot handle  OAuthCallback for %v: not found", state))
		w.WriteHeader(http.StatusRequestTimeout)
		return
	}
	h.cache.Delete(state)
	redirect := c.(redirect)

	err := redirect.onRedirect(r.Context(), code)
	if redirect.finalRedirectURL != "" {
		h.RedirectResult(w, r, redirect.finalRedirectURL, err)
		return
	}
	h.errors(err)
	w.WriteHeader(http.StatusBadRequest)
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

func NewServer(uri string, waitTime time.Duration, errors func(error)) (*Server, error) {
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
	cache := cache.New(waitTime, waitTime)
	h := &Handler{
		cache:  cache,
		errors: errors,
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

func (s *Server) GetAuthCodeURL(onRedirect OnRedirectFunc, cfg oauth2.Config, options ...oauth2.AuthCodeOption) (authID, authCodeURL string, err error) {
	state, err := uuid.NewV4()
	if err != nil {
		return "", "", err
	}

	v := redirect{
		finalRedirectURL: cfg.RedirectURL,
		onRedirect:       onRedirect,
	}
	cfg.RedirectURL = s.uri

	s.cache.Add(state.String(), v, cache.DefaultExpiration)
	url := cfg.AuthCodeURL(state.String(), options...)
	return state.String(), url, nil
}

func (s *Server) Remove(authID string) {
	s.cache.Delete(authID)
}
