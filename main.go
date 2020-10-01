package main

import (
	"context"
	"encoding/base64"
	"encoding/gob"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/alecthomas/kingpin"
	github "github.com/google/go-github/v32/github"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
)

const (
	// String keys used in cookies
	sessionCookieName = "roadmap-session"
	sessionTokenKey   = "token"
	sessionStateKey   = "state"
	sessionUserKey    = "user"
)

var indexTemplate = template.Must(template.New("index.tpl.html").ParseFiles("index.tpl.html"))

func main() {
	listenAddress := kingpin.Flag("listen-address", "Address to listen on").Envar("LISTEN_ADDRESS").Default("127.0.0.1:8629").String()
	clientID := kingpin.Flag("client-id", "GitHub oAuth2 client ID").Envar("CLIENT_ID").Required().String()
	clientSecret := kingpin.Flag("client-secret", "GitHub oAuth2 client secret").Envar("CLIENT_SECRET").Required().String()
	sessionKey := kingpin.Flag("session-key", "Encryption key for session cookies").Envar("SESSION_KEY").Required().String()
	githubOwner := kingpin.Flag("github-owner", "GitHub user or organization").Envar("GITHUB_OWNER").Default("syncthing").String()
	githubRepo := kingpin.Flag("github-repo", "GitHub repository").Envar("GITHUB_OWNER").Default("syncthing").String()
	githubToken := kingpin.Flag("github-token", "GitHub oAuth2 token for own access").Envar("GITHUB_TOKEN").Required().String()
	externalURL := kingpin.Flag("external-url", "Our external (root) URL").Envar("EXTERNAL_URL").Required().String()
	debugRender := kingpin.Flag("debug-render", "Just fetch issues and render the index").Bool()
	kingpin.Parse()

	if *debugRender {
		l := newCachedIssueList(*githubOwner, *githubRepo, *githubToken)
		s := pageState{cachedIssueList: l}
		indexTemplate.Execute(os.Stdout, s)
		return
	}

	// The cookie store uses Gob for serialization, we register custom types
	// beforehand so we can use them directly.
	gob.Register(&oauth2.Token{})
	gob.Register(&github.User{})

	srv := &server{
		owner: *githubOwner,
		repo:  *githubRepo,
		store: sessions.NewCookieStore([]byte(*sessionKey)),
		oauthCfg: &oauth2.Config{
			ClientID:     *clientID,
			ClientSecret: *clientSecret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://github.com/login/oauth/authorize",
				TokenURL: "https://github.com/login/oauth/access_token",
			},
			RedirectURL: strings.TrimRight(*externalURL, "/") + "/auth-callback",
			Scopes:      []string{"read:user", "public_repo"},
		},
		issues: newCachedIssueList(*githubOwner, *githubRepo, *githubToken),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", srv.index)
	mux.HandleFunc("/auth-callback", srv.authCallback)
	mux.HandleFunc("/authenticate", srv.authenticate)
	mux.HandleFunc("/vote/", srv.vote)
	mux.HandleFunc("/unvote/", srv.unvote)
	mux.HandleFunc("/logout", srv.logout)

	http.ListenAndServe(*listenAddress, mux)
}

type pageState struct {
	User string
	*cachedIssueList
}

func (p pageState) Authenticated() bool {
	return p.User != ""
}

type server struct {
	owner, repo string
	store       sessions.Store
	oauthCfg    *oauth2.Config
	issues      *cachedIssueList
}

// index renders index.tpl.html
func (s *server) index(w http.ResponseWriter, r *http.Request) {
	state := pageState{
		cachedIssueList: s.issues,
	}

	if _, user, err := s.currentUserToken(w, r); err == nil {
		// We're logged in
		state.User = user.GetLogin()
	}

	w.Header().Set("Content-Type", "text-html;charset=utf-8")
	if err := indexTemplate.Execute(w, state); err != nil {
		log.Println("Template execution:", err)
	}
}

// authenticate validates or gets a new oAuth2 token from GitHub for the
// current user, then redirects to either the front page or GitHub for
// authentication
func (s *server) authenticate(w http.ResponseWriter, r *http.Request) {
	_, _, err := s.currentUserToken(w, r)
	if err == nil {
		// We are already authenticated
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	s.redirectToGitHub(w, r)
}

// authCallback receives the oAuth2 callback from GitHub when a user has
// authenticated, sets up the session properly, and redirects to the front
// page.
func (s *server) authCallback(w http.ResponseWriter, r *http.Request) {
	// Verify that the state in the callback matches that in the user session.
	session, _ := s.store.Get(r, sessionCookieName)
	state, ok := session.Values[sessionStateKey].(string)
	if !ok || state != r.FormValue("state") {
		log.Printf("Bad state %q != expected %q", r.FormValue("state"), state)
		http.Error(w, "Bad state", http.StatusBadRequest)
		return
	}

	// Exchange the callback code for an authentication token.
	tok, err := s.oauthCfg.Exchange(r.Context(), r.FormValue("code"))
	if err != nil {
		log.Println("Resolve token:", err)
		http.Error(w, "Token rejected", http.StatusInternalServerError)
		return
	}

	// Get the correspoding GitHub user
	user, err := s.githubUser(r.Context(), tok)
	if err != nil {
		log.Println("Resolve user:", err)
		http.Error(w, "User unavailable", http.StatusInternalServerError)
		return
	}

	// Store the authentication token and GitHub user information in the session cookie.
	session.Values[sessionTokenKey] = tok
	session.Values[sessionUserKey] = user
	delete(session.Values, sessionStateKey)
	if err := session.Save(r, w); err != nil {
		log.Println("Save session:", err)
	}

	// We're authenticated, lets go
	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

// vote adds a vote to an issue for the logged in user.
// XXX: This should be a POST method
func (s *server) vote(w http.ResponseWriter, r *http.Request) {
	issue, err := strconv.Atoi(path.Base(r.URL.Path))
	if err != nil {
		http.Error(w, "Bad number", http.StatusBadRequest)
		return
	}

	tok, user, err := s.currentUserToken(w, r)
	if err != nil {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	client := s.githubClient(r.Context(), tok)
	_, _, err = client.Reactions.CreateIssueReaction(r.Context(), s.owner, s.repo, issue, "+1")
	log.Printf("User %s voted for issue %d: %v", user.GetLogin(), issue, err)
	s.issues.flushVotes(issue)

	http.Redirect(w, r, fmt.Sprintf("/#issue-%d", issue), http.StatusTemporaryRedirect)
}

// unvote removes a vote to an issue for the logged in user.
// XXX: This should be a POST method
func (s *server) unvote(w http.ResponseWriter, r *http.Request) {
	issue, err := strconv.Atoi(path.Base(r.URL.Path))
	if err != nil {
		http.Error(w, "Bad number", http.StatusBadRequest)
		return
	}

	tok, user, err := s.currentUserToken(w, r)
	if err != nil {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	id, ok := s.issues.userVoteID(issue, user.GetLogin())
	if !ok {
		http.Error(w, "Not voted", http.StatusBadRequest)
		return
	}

	client := s.githubClient(r.Context(), tok)
	_, err = client.Reactions.DeleteIssueReaction(r.Context(), s.owner, s.repo, issue, id)
	log.Printf("User %s removed vote for issue %d: %v", user.GetLogin(), issue, err)
	s.issues.flushVotes(issue)

	http.Redirect(w, r, fmt.Sprintf("/#issue-%d", issue), http.StatusTemporaryRedirect)
}

// logout removes the user session, thus logging them out
func (s *server) logout(w http.ResponseWriter, r *http.Request) {
	session, _ := s.store.Get(r, sessionCookieName)

	delete(session.Values, sessionTokenKey)
	delete(session.Values, sessionTokenKey)

	if err := session.Save(r, w); err != nil {
		log.Println("Save session:", err)
	}

	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

// currentUserToken returns the current GitHub user info and their token,
// refreshing the token when appropriate
func (s *server) currentUserToken(w http.ResponseWriter, r *http.Request) (*oauth2.Token, *github.User, error) {
	// Get the current token from the session, if any, and check that it's
	// still (supposedly) valid.
	session, _ := s.store.Get(r, sessionCookieName)
	tok, ok := session.Values[sessionTokenKey].(*oauth2.Token)
	if !ok {
		return nil, nil, errors.New("no token")
	}

	// Check if we have valid user info and the token has not expired, if so
	// we're done.
	user, ok := session.Values[sessionUserKey].(*github.User)
	if ok && tok.Expiry.After(time.Now()) {
		return tok, user, nil
	}

	// Token has expired, attempt to refresh it
	src := s.oauthCfg.TokenSource(r.Context(), tok)
	tok, err := src.Token()
	if err != nil {
		return nil, nil, err
	}

	// Get or refresh the GitHub user info
	user, err = s.githubUser(r.Context(), tok)
	if err != nil {
		log.Println("Resolve user:", err)
		return nil, nil, err
	}

	session.Values[sessionTokenKey] = tok
	session.Values[sessionUserKey] = user

	if err := session.Save(r, w); err != nil {
		log.Println("Save session:", err)
	}
	return tok, user, nil
}

// redirectToGitHub serves a temporary redirect to the GitHub authentication
// endpoint
func (s *server) redirectToGitHub(w http.ResponseWriter, r *http.Request) {
	session, _ := s.store.Get(r, sessionCookieName)
	state := base64.RawStdEncoding.EncodeToString(securecookie.GenerateRandomKey(32))
	session.Values[sessionStateKey] = state
	if err := session.Save(r, w); err != nil {
		log.Println("Save session:", err)
	}
	redir := s.oauthCfg.AuthCodeURL(state)
	http.Redirect(w, r, redir, http.StatusTemporaryRedirect)
}

// githubClient returns a GitHub client that can perform requests on behalf
// of the holder of the token
func (s *server) githubClient(ctx context.Context, tok *oauth2.Token) *github.Client {
	return github.NewClient(s.oauthCfg.Client(ctx, tok))
}

// githubUser returns the user data for the holder of the token
func (s *server) githubUser(ctx context.Context, tok *oauth2.Token) (*github.User, error) {
	client := s.githubClient(ctx, tok)
	user, _, err := client.Users.Get(ctx, "")
	return user, err
}
