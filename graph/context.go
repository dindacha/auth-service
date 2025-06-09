package graph

import (
    "context"
    "net/http"
    "strings"
)

type contextKey string

const (
    userContextKey contextKey = "user"
    ipContextKey   contextKey = "ip"
    uaContextKey   contextKey = "useragent"
)

type UserContext struct {
    UserID      string
    Email       string
    Role        string
    Permissions []string
}

func GetIPFromContext(ctx context.Context) string {
    ip, _ := ctx.Value(ipContextKey).(string)
    if ip == "" {
        return "127.0.0.1" // fallback
    }
    return ip
}

func GetUserAgentFromContext(ctx context.Context) string {
    ua, _ := ctx.Value(uaContextKey).(string)
    if ua == "" {
        return "GraphQL-Client" // fallback
    }
    return ua
}

func WithIPAddress(ctx context.Context, ip string) context.Context {
    return context.WithValue(ctx, ipContextKey, ip)
}

func WithUserAgent(ctx context.Context, ua string) context.Context {
    return context.WithValue(ctx, uaContextKey, ua)
}

func GetClientIP(r *http.Request) string {
    if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
        return strings.Split(ip, ",")[0]
    }
    if ip := r.Header.Get("X-Real-IP"); ip != "" {
        return ip
    }
    return strings.Split(r.RemoteAddr, ":")[0]
}