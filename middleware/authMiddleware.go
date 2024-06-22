package middleware

import (
	"context"
	"net/http"

	"github.com/ramyasreetejo/jwt-authentication-golang/contextKeys"
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

		// Set user information in request context
		ctx := context.Background()
		ctx = context.WithValue(ctx, contextKeys.EmailKey, claims.Email)
		ctx = context.WithValue(ctx, contextKeys.FirstNameKey, claims.First_name)
		ctx = context.WithValue(ctx, contextKeys.LastNameKey, claims.Last_name)
		ctx = context.WithValue(ctx, contextKeys.UserIDKey, claims.User_id)
		ctx = context.WithValue(ctx, contextKeys.UserTypeKey, claims.User_type)

		// Call the next handler
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
