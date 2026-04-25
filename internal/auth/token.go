// Package auth provides bearer-token HTTP middleware.
package auth

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

// SessionCookieName is the browser session cookie used by routes that cannot
// set Authorization headers, such as native EventSource.
const SessionCookieName = "trivy_dashboard_token"

// Bearer returns middleware that requires Authorization: Bearer <expected>.
// Comparison is constant-time. An empty expected token panics at construction
// time — a missing token is a startup error, not a runtime 401.
func Bearer(expected string) func(http.Handler) http.Handler {
	if expected == "" {
		panic("auth.Bearer: empty token")
	}
	expectedBytes := []byte(expected)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := r.Header.Get("Authorization")
			const prefix = "Bearer "
			if strings.HasPrefix(h, prefix) {
				got := []byte(strings.TrimPrefix(h, prefix))
				if subtle.ConstantTimeCompare(got, expectedBytes) == 1 {
					next.ServeHTTP(w, r)
					return
				}
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			if cookie, err := r.Cookie(SessionCookieName); err == nil {
				if subtle.ConstantTimeCompare([]byte(cookie.Value), expectedBytes) == 1 {
					next.ServeHTTP(w, r)
					return
				}
			}

			w.Header().Set("WWW-Authenticate", `Bearer realm="trivy-dashboard"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		})
	}
}
