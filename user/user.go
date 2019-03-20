package user

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/playdots/underpants/config"
)

const (
	// CookieKey is the name of the cookie used for authentication
	CookieKey = "u"

	// CookieMaxAge is the expiration age (in seconds) used for the authentication
	// cookie
	CookieMaxAge = 3600
)

// Info ...
type Info struct {
	Email             string
	Name              string
	Picture           string
	LastAuthenticated time.Time
}

func isValidMessage(key []byte, sig, msg string) bool {
	s, err := base64.URLEncoding.DecodeString(sig)
	if err != nil {
		return false
	}

	h := hmac.New(sha256.New, key)
	if _, err := h.Write([]byte(msg)); err != nil {
		return false
	}

	return subtle.ConstantTimeCompare(s, h.Sum(nil)) == 1
}

// Encode the full user object as a base64 string that is signed with the given
// key. This value is suitable for use in a cookie.
func (i *Info) Encode(key []byte) (string, error) {
	var b bytes.Buffer
	h := hmac.New(sha256.New, key)
	w := base64.NewEncoder(base64.URLEncoding,
		io.MultiWriter(h, &b))
	if err := json.NewEncoder(w).Encode(i); err != nil {
		return "", err
	}

	if err := w.Close(); err != nil {
		return "", err
	}

	return fmt.Sprintf("%s,%s",
		base64.URLEncoding.EncodeToString(h.Sum(nil)),
		b.String()), nil
}

// Decode unmarshals an encoded and signed user.
func Decode(c string, key []byte) (*Info, error) {
	s := strings.SplitN(c, ",", 2)

	if len(s) != 2 || !isValidMessage(key, s[0], s[1]) {
		return nil, fmt.Errorf("Invalid user cookie: %s", c)
	}

	var u Info
	r := base64.NewDecoder(
		base64.URLEncoding,
		bytes.NewBufferString(s[1]))
	if err := json.NewDecoder(r).Decode(&u); err != nil {
		return nil, err
	}

	return &u, nil
}

// DecodeAndVerify decodes the user but also validates that the encoded user object is
// still valid.
func DecodeAndVerify(c string, key []byte) (*Info, error) {
	u, err := Decode(c, key)
	if err != nil {
		return nil, err
	}

	if time.Now().Sub(u.LastAuthenticated).Seconds() >= CookieMaxAge {
		return nil, fmt.Errorf("Cookie too old for: %s", u.Email)
	}

	return u, nil
}

// DecodeFromRequest decodes the user from the cookie found in the http.Request.
func DecodeFromRequest(r *http.Request, key []byte) (*Info, error) {
	c, err := r.Cookie(CookieKey)

	if err != nil || c.Value == "" {
		return nil, errors.New("empty cookie")
	}

	v, err := url.QueryUnescape(c.Value)
	if err != nil {
		return nil, errors.New("unable to escape cookie")
	}

	u, err := DecodeAndVerify(v, key)
	if err != nil {
		return nil, errors.New("could not decode and verify user")
	}

	return u, nil
}

func CreateCookie(data string, ctx *config.Context, req *http.Request) *http.Cookie {
	cookie := &http.Cookie{
		Name:     CookieKey,
		Value:    url.QueryEscape(data),
		Path:     "/",
		MaxAge:   CookieMaxAge,
		HttpOnly: true,
		Secure:   ctx.HasCerts(),
	}

	// loop through all routes...
	// if we want to share cookies across subdomains for a given route and the
	// host making requests to it, and if the request is from a host that is in a
	// given route's allowed origins, modify the domain set on the cookie by excluding the subdomain
	for _, r := range ctx.Routes {
		if r.ShareCookieAcrossSubdomains && originInAllowedOrigins(req.Host, r.AllowedOrigins) {
			fullDomain, _ := url.Parse(req.Host)
			domainEls := strings.Split(fullDomain.String(), ".")

			// domainEls should be of length 3 if b.Route.From is a subdomain
			// subdomain.domain.com => {subdomain domain com}
			// ignore if there is no subdomain
			if len(domainEls) < 3 {
				return cookie
			}

			// if there is a subdomain, and we want to share the cookie across subdomains
			// set the cookie.Domain to the naked domain (subdomain removed)
			_, domainEls = domainEls[0], domainEls[1:]
			nakedDomain := strings.Join(domainEls, ".")
			cookie.Domain = nakedDomain

			return cookie
		}
	}

	return cookie
}

func originInAllowedOrigins(origin string, allowedOrigins []string) bool {
	for _, allowed := range allowedOrigins {
		allowedUrl, err := url.Parse(allowed)
		if err != nil {
			panic(err)
		}

		if allowedUrl.Host == origin {
			return true
		}
	}
	return false
}
