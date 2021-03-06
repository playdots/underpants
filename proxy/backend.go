package proxy

import (
	"bytes"
	"io"
	"io/ioutil"
	"net/http"
	"net/mail"
	"net/url"
	"strings"

	"github.com/playdots/underpants/auth"
	"github.com/playdots/underpants/config"
	"github.com/playdots/underpants/user"

	"go.uber.org/zap"
)

// Backend is an http.Handler that handles traffic to that particular route.
type Backend struct {
	Ctx *config.Context

	Route *config.RouteInfo

	AuthProvider auth.Provider
}

// Copy the HTTP headers from one collection to another.
func copyHeaders(dst, src http.Header) {
	for key, vals := range src {
		for _, val := range vals {
			dst.Add(key, val)
		}
	}
}

func setAccessControlHeaders(b *Backend, w http.ResponseWriter) {
	// for admin dashboard xhr requests
	allowedOrigins := b.Route.AllowedOrigins
	if len(allowedOrigins) > 0 {
		allowedOriginsString := strings.Join(allowedOrigins, ",")
		w.Header().Set("Access-Control-Allow-Origin", allowedOriginsString)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Allow-Headers", "*")
		w.Header().Set("Access-Control-Allow-Methods", "PUT, POST, GET, OPTIONS")
	}
}

func addToAddHeaders(dst http.Header, toAddHeaders []*config.ToAddHeader) {
	if len(toAddHeaders) > 0 {
		for _, toAddHeader := range toAddHeaders {
			headerKey := toAddHeader.DestHeaderKey
			headerVal := toAddHeader.DestHeaderVal
			dst.Add(headerKey, headerVal)
		}
	}
}

func (b *Backend) serveHTTPAuth(w http.ResponseWriter, r *http.Request) {
	c, p := r.FormValue("c"), r.FormValue("p")
	if c == "" || !strings.HasPrefix(p, "/") {
		http.Error(w,
			http.StatusText(http.StatusBadRequest),
			http.StatusBadRequest)
		return
	}

	// verify the cookie
	if _, err := user.DecodeAndVerify(c, b.Ctx.Key); err != nil {
		// do not redirect out of here because this indicates a big
		// problem and we're likely to get into a redir loop.
		http.Error(w,
			http.StatusText(http.StatusForbidden),
			http.StatusForbidden)
		return
	}

	http.SetCookie(w, user.CreateCookie(c, b.Ctx, r))

	// Redirect validates the redirect path.
	http.Redirect(w, r, p, http.StatusFound)
}

func (b *Backend) serveHTTPProxy(w http.ResponseWriter, r *http.Request) {
	logFields := []zap.Field{
		zap.String("from", b.Route.From),
		zap.String("uri", r.RequestURI),
		zap.String("method", r.Method),
	}

	setAccessControlHeaders(b, w)

	// if we're dealing with a preflight request, return early after setting Access-Control-* headers
	if r.Method == "OPTIONS" {
		return
	}

	u, err := user.DecodeFromRequest(r, b.Ctx.Key)
	if err != nil {
		zap.L().Info("authentication required. redirecting to auth provider", logFields...)
		http.Redirect(w, r, b.AuthProvider.GetAuthURL(b.Ctx, r), http.StatusFound)
		return
	}
	logFields = append(logFields, zap.String("user", u.Email))

	b.proxyUserRequest(w, r, u, logFields)
}

func (b *Backend) proxyUserRequest(w http.ResponseWriter, r *http.Request, u *user.Info, logFields []zap.Field) {
	if !b.Ctx.UserMemberOfAny(u.Email, b.Route.AllowedGroups) {
		msg := "Forbidden: you are not a member of a group authorized to view this site."
		zap.L().Info(msg, logFields...)
		http.Error(w, msg, http.StatusForbidden)
		return
	}

	// Validate properly formatted email address
	if _, err := mail.ParseAddress(u.Email); err != nil {
		msg := "Forbidden: your email address is invalid."
		zap.L().Info(msg, logFields...)
		http.Error(w, msg, http.StatusForbidden)
		return
	}

	email := strings.Split(u.Email, "@")
	domain := email[len(email)-1]

	if !b.Ctx.DomainMemberOfAny(domain, b.Route.AllowedDomainGroups) {
		msg := "Forbidden: your domain is not a member of the group authorized to view this site."
		zap.L().Info(msg, logFields...)
		http.Error(w, msg, http.StatusForbidden)
		return
	}

	rebase, err := b.Route.ToURL().Parse(
		strings.TrimLeft(r.URL.RequestURI(), "/"))
	if err != nil {
		panic(err)
	}
	logFields = append(logFields, zap.String("dest", rebase.String()))

	br, err := http.NewRequest(r.Method, rebase.String(), r.Body)
	if err != nil {
		panic(err)
	}

	// Without passing on the original Content-Length, http.Client will use
	// Transfer-Encoding: chunked which some HTTP servers fall down on.
	br.ContentLength = r.ContentLength

	copyHeaders(br.Header, r.Header)

	// Headers we want to add during the proxy in addition to any client-supplied headers
	// e.g. sensitive auth tokens that we do not want stored in client-side dashboards

	addToAddHeaders(br.Header, b.Route.ToAddHeaders)

	// User information is passed to backends as headers.
	br.Header.Add("Underpants-Email", url.QueryEscape(u.Email))
	br.Header.Add("Underpants-Name", url.QueryEscape(u.Name))

	// Read from and reset request body.
	var bodyBytes []byte
	if br.Body != nil {
		bodyBytes, _ = ioutil.ReadAll(br.Body)
	}

	br.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))
	bodyString := string(bodyBytes)
	logFields = append(logFields, zap.String("body", bodyString))

	zap.L().Info("proxying request", logFields...)
	bp, err := http.DefaultTransport.RoundTrip(br)
	if err != nil {
		panic(err)
	}
	defer bp.Body.Close()

	copyHeaders(w.Header(), bp.Header)

	w.WriteHeader(bp.StatusCode)
	if _, err := io.Copy(w, bp.Body); err != nil {
		panic(err)
	}
}

func (b *Backend) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, auth.BaseURI) {
		b.serveHTTPAuth(w, r)
	} else {
		b.serveHTTPProxy(w, r)
	}
}
