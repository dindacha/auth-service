package handlers

import (
    "auth-service/services"
    "auth-service/config"
    "net/http"
    "strings"
    "github.com/gin-gonic/gin"
)

type AuthHandler struct {
    authService *services.AuthService
    config      *config.Config
}

func NewAuthHandler(authService *services.AuthService, cfg *config.Config) *AuthHandler {
    return &AuthHandler{
        authService: authService,
        config:      cfg,
    }
}

func (h *AuthHandler) RegisterUserAuth(c *gin.Context) {
    var req services.RegisterAuthRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    err := h.authService.RegisterUserAuth(req)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    c.JSON(http.StatusCreated, gin.H{"message": "User auth created successfully"})
}

func (h *AuthHandler) Login(c *gin.Context) {
    var req services.LoginRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    // Get IP address and user agent
    ipAddress := c.ClientIP()
    userAgent := c.GetHeader("User-Agent")

    response, err := h.authService.Login(req, ipAddress, userAgent)
    if err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
        return
    }

    c.JSON(http.StatusOK, response)
}

func (h *AuthHandler) RefreshToken(c *gin.Context) {
    var req struct {
        RefreshToken string `json:"refresh_token" binding:"required"`
    }

    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    // Get IP address and user agent
    ipAddress := c.ClientIP()
    userAgent := c.GetHeader("User-Agent")

    response, err := h.authService.RefreshToken(req.RefreshToken, ipAddress, userAgent)
    if err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
        return
    }

    c.JSON(http.StatusOK, response)
}

func (h *AuthHandler) ValidateToken(c *gin.Context) {
    authHeader := c.GetHeader("Authorization")
    if authHeader == "" {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
        return
    }

    parts := strings.Split(authHeader, " ")
    if len(parts) != 2 || parts[0] != "Bearer" {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid authorization header format"})
        return
    }

    claims, err := h.authService.ValidateToken(parts[1])
    if err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
        return
    }

    c.JSON(http.StatusOK, gin.H{
        "valid":   true,
        "user_id": claims.UserID,
        "email":   claims.Email,
        "role":    claims.Role,
    })
}

func (h *AuthHandler) CheckPermission(c *gin.Context) {
    authHeader := c.GetHeader("Authorization")
    if authHeader == "" {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
        return
    }

    parts := strings.Split(authHeader, " ")
    if len(parts) != 2 || parts[0] != "Bearer" {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid authorization header format"})
        return
    }

    claims, err := h.authService.ValidateToken(parts[1])
    if err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
        return
    }

    resource := c.Query("resource")
    action := c.Query("action")

    if resource == "" || action == "" {
        c.JSON(http.StatusBadRequest, gin.H{"error": "resource and action parameters required"})
        return
    }

    // Check if user has permission
    hasPermission := false
    for _, permission := range claims.Permissions {
        if permission == resource+":"+action {
            hasPermission = true
            break
        }
    }

    c.JSON(http.StatusOK, gin.H{
        "has_permission": hasPermission,
        "user_id":        claims.UserID,
    })
}

func (h *AuthHandler) ChangePassword(c *gin.Context) {
    var req services.ChangePasswordRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    // TODO: Implement change password
    c.JSON(http.StatusOK, gin.H{"message": "Password changed successfully"})
}

func (h *AuthHandler) GetUserSessions(c *gin.Context) {
    // TODO: Implement get user sessions
    c.JSON(http.StatusOK, gin.H{"sessions": []string{}})
}

func (h *AuthHandler) RevokeSession(c *gin.Context) {
    sessionID := c.Param("id")
    
    // TODO: Implement revoke session
    c.JSON(http.StatusOK, gin.H{"message": "Session revoked: " + sessionID})
}

func (h *AuthHandler) Logout(c *gin.Context) {
    var req struct {
        RefreshToken string `json:"refresh_token" binding:"required"`
    }

    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    // TODO: Implement logout
    c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
}