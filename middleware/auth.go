package middleware

import (
    "context"
    "net/http"
    "strings"
    
    "auth-service/graph"
    "auth-service/services"
)

func AuthMiddleware(authService *services.AuthService) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            ctx := r.Context()
            
            // Add IP and User-Agent to context
            ctx = graph.WithIPAddress(ctx, getClientIP(r))
            ctx = graph.WithUserAgent(ctx, r.UserAgent())
            
            // Check for Authorization header
            authHeader := r.Header.Get("Authorization")
            if authHeader != "" {
                parts := strings.Split(authHeader, " ")
                if len(parts) == 2 && parts[0] == "Bearer" {
                    claims, err := authService.ValidateToken(parts[1])
                    if err == nil {
                        user := &graph.UserContext{
                            UserID:      claims.UserID.String(),
                            Email:       claims.Email,
                            Role:        string(claims.Role),
                            Permissions: claims.Permissions,
                        }
                        ctx = graph.WithUserContext(ctx, user)
                    }
                }
            }
            
            next.ServeHTTP(w, r.WithContext(ctx))
        })
    }
}

func getClientIP(r *http.Request) string {
    if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
        return strings.Split(ip, ",")[0]
    }
    if ip := r.Header.Get("X-Real-IP"); ip != "" {
        return ip
    }
    return r.RemoteAddr
}