package middleware

import (
	"context"
	"net/http"

	"github.com/ramyasreetejo/jwt-authentication-golang/helpers"
)

// Middleware function to authenticate requests
func Authenticate(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// clientToken := r.Header.Get("token")
		// if clientToken == "" {
		// 	http.Error(w, "No Authorization header provided", http.StatusInternalServerError)
		// 	return
		// }

		cookie, e := r.Cookie("token")
		if e != nil {
			if e == http.ErrNoCookie {
				http.Error(w, "no cookie error", http.StatusBadRequest)
				return
			}
			http.Error(w, "cookie error", http.StatusBadRequest)
			return
		}
		clientToken := cookie.Value

		claims, err := helpers.ValidateToken(clientToken)
		if err != "" {
			http.Error(w, err, http.StatusInternalServerError)
			return
		}

		type contextKey string
		const emailKey contextKey = "email"
		const first_nameKey contextKey = "first_name"
		const last_nameKey contextKey = "last_name"
		const uidKey contextKey = "uid"
		const user_typeKey contextKey = "user_type"

		// Set user information in request context
		ctx := r.Context()
		ctx = context.WithValue(ctx, emailKey, claims.Email)
		ctx = context.WithValue(ctx, first_nameKey, claims.First_name)
		ctx = context.WithValue(ctx, last_nameKey, claims.Last_name)
		ctx = context.WithValue(ctx, uidKey, claims.Uid)
		ctx = context.WithValue(ctx, user_typeKey, claims.User_type)

		// Call the next handler
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
