package services

import (
    "auth-service/config"
    "auth-service/models"
    "errors"
    "fmt"
    "time"
    "github.com/google/uuid"
    "golang.org/x/crypto/bcrypt"
    "gorm.io/gorm"
)

type AuthService struct {
    db           *gorm.DB
    config       *config.Config
    userClient   *UserClient
    tokenService *TokenService
}

type AuthResponse struct {
    AccessToken  string    `json:"access_token"`
    RefreshToken string    `json:"refresh_token"`
    ExpiresIn    int64     `json:"expires_in"`
    TokenType    string    `json:"token_type"`
    User         *UserInfo `json:"user"`
}

type LoginRequest struct {
    Email    string `json:"email" binding:"required,email"`
    Password string `json:"password" binding:"required"`
}

type RegisterAuthRequest struct {
    UserID   uuid.UUID `json:"user_id" binding:"required"`
    Email    string    `json:"email" binding:"required,email"`
    Password string    `json:"password" binding:"required,min=8"`
}

type ChangePasswordRequest struct {
    UserID      uuid.UUID `json:"user_id" binding:"required"`
    OldPassword string    `json:"old_password" binding:"required"`
    NewPassword string    `json:"new_password" binding:"required,min=8"`
}

func NewAuthService(db *gorm.DB, config *config.Config, userClient *UserClient) *AuthService {
    tokenService := NewTokenService(config)
    return &AuthService{
        db:           db,
        config:       config,
        userClient:   userClient,
        tokenService: tokenService,
    }
}

func (s *AuthService) RegisterUserAuth(req RegisterAuthRequest) error {
    // Check if user auth already exists
    var existingAuth models.UserAuth
    if err := s.db.Where("email = ? OR id = ?", req.Email, req.UserID).First(&existingAuth).Error; err == nil {
        return errors.New("user auth already exists")
    }

    // Validate password strength
    if err := s.validatePassword(req.Password); err != nil {
        return err
    }

    // Hash password
    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), s.config.BCryptCost)
    if err != nil {
        return err
    }

    // Create user auth record
    userAuth := &models.UserAuth{
        ID:                req.UserID,
        Email:             req.Email,
        PasswordHash:      string(hashedPassword),
        IsActive:          true,
        IsEmailVerified:   !s.config.Security.RequireEmailVerification,
        PasswordChangedAt: &time.Time{},
        CreatedAt:         time.Now(),
        UpdatedAt:         time.Now(),
    }

    if err := s.db.Create(userAuth).Error; err != nil {
        return err
    }

    // Log audit event
    s.logAuditEvent(&req.UserID, models.AuditActionLogin, "auth", "User auth created", "", "", true, "")

    return nil
}

func (s *AuthService) Login(req LoginRequest, ipAddress, userAgent string) (*AuthResponse, error) {
    // Check rate limiting
    if err := s.checkRateLimit(req.Email, ipAddress); err != nil {
        s.logLoginAttempt(req.Email, ipAddress, userAgent, false, "Rate limit exceeded")
        return nil, err
    }

    // Get user auth record
    var userAuth models.UserAuth
    if err := s.db.Where("email = ?", req.Email).First(&userAuth).Error; err != nil {
        s.logLoginAttempt(req.Email, ipAddress, userAgent, false, "User not found")
        return nil, errors.New("invalid credentials")
    }

    // Check if account is locked
    if userAuth.LockedUntil != nil && userAuth.LockedUntil.After(time.Now()) {
        s.logLoginAttempt(req.Email, ipAddress, userAgent, false, "Account locked")
        return nil, errors.New("account is temporarily locked")
    }

    // Check if account is active
    if !userAuth.IsActive {
        s.logLoginAttempt(req.Email, ipAddress, userAgent, false, "Account inactive")
        return nil, errors.New("account is deactivated")
    }

    // Verify password
    if err := bcrypt.CompareHashAndPassword([]byte(userAuth.PasswordHash), []byte(req.Password)); err != nil {
        s.handleFailedLogin(&userAuth, ipAddress, userAgent)
        return nil, errors.New("invalid credentials")
    }

    // Reset failed login count on successful login
    s.db.Model(&userAuth).Updates(map[string]interface{}{
        "failed_login_count": 0,
        "locked_until":      nil,
        "last_login_at":     time.Now(),
        "last_login_ip":     ipAddress,
    })

    // Get user info from user service
    userInfo, err := s.userClient.GetUserByEmail(req.Email)
    if err != nil {
        s.logLoginAttempt(req.Email, ipAddress, userAgent, false, "User service error")
        return nil, fmt.Errorf("failed to get user info: %w", err)
    }

    // Check if user is active in user service
    if !userInfo.IsActive {
        s.logLoginAttempt(req.Email, ipAddress, userAgent, false, "User inactive")
        return nil, errors.New("user account is deactivated")
    }

    // Create session
    sessionID := uuid.New().String()
    session := &models.Session{
        UserID:    userAuth.ID,
        TokenID:   sessionID,
        IsActive:  true,
        ExpiresAt: time.Now().Add(s.config.Security.SessionTimeout),
        CreatedAt: time.Now(),
        LastSeen:  time.Now(),
        IPAddress: ipAddress,
        UserAgent: userAgent,
    }

    if err := s.db.Create(session).Error; err != nil {
        return nil, err
    }

    // Log successful login
    s.logLoginAttempt(req.Email, ipAddress, userAgent, true, "")
    s.logAuditEvent(&userAuth.ID, models.AuditActionLogin, "auth", "User logged in", ipAddress, userAgent, true, "")

    // Generate tokens
    return s.generateAuthResponse(&userAuth, userInfo, sessionID, ipAddress, userAgent)
}

func (s *AuthService) RefreshToken(refreshToken string, ipAddress, userAgent string) (*AuthResponse, error) {
    var tokenRecord models.RefreshToken
    if err := s.db.Preload("UserAuth").Where("token = ? AND expires_at > ? AND is_revoked = ?", refreshToken, time.Now(), false).First(&tokenRecord).Error; err != nil {
        return nil, errors.New("invalid or expired refresh token")
    }

    // Check if user auth is still active
    if !tokenRecord.UserAuth.IsActive {
        return nil, errors.New("account is deactivated")
    }

    // Get user info from user service
    userInfo, err := s.userClient.GetUserByID(tokenRecord.UserID)
    if err != nil {
        return nil, fmt.Errorf("failed to get user info: %w", err)
    }

    // Check if user is still active in user service
    if !userInfo.IsActive {
        return nil, errors.New("user account is deactivated")
    }

    // Revoke old refresh token
    s.db.Model(&tokenRecord).Update("is_revoked", true)

    // Create new session
    sessionID := uuid.New().String()
    session := &models.Session{
        UserID:    tokenRecord.UserID,
        TokenID:   sessionID,
        IsActive:  true,
        ExpiresAt: time.Now().Add(s.config.Security.SessionTimeout),
        CreatedAt: time.Now(),
        LastSeen:  time.Now(),
        IPAddress: ipAddress,
        UserAgent: userAgent,
    }

    if err := s.db.Create(session).Error; err != nil {
        return nil, err
    }

    // Log audit event
    s.logAuditEvent(&tokenRecord.UserID, models.AuditActionTokenRefresh, "auth", "Token refreshed", ipAddress, userAgent, true, "")

    // Generate new tokens
    return s.generateAuthResponse(&tokenRecord.UserAuth, userInfo, sessionID, ipAddress, userAgent)
}

func (s *AuthService) ValidateToken(tokenString string) (*Claims, error) {
    claims, err := s.tokenService.ValidateToken(tokenString)
    if err != nil {
        return nil, err
    }

    // Check if session is still active
    var session models.Session
    if err := s.db.Where("token_id = ? AND is_active = ? AND expires_at > ?", claims.SessionID, true, time.Now()).First(&session).Error; err != nil {
        return nil, errors.New("session not found or expired")
    }

    // Update last seen
    s.db.Model(&session).Update("last_seen", time.Now())

    // Check if user auth still exists and is active
    var userAuth models.UserAuth
    if err := s.db.First(&userAuth, claims.UserID).Error; err != nil {
        return nil, errors.New("user not found")
    }

    if !userAuth.IsActive {
        return nil, errors.New("account is deactivated")
    }

    return claims, nil
}

func (s *AuthService) GetUserPermissions(role models.UserRole, userID uuid.UUID) ([]string, error) {
    var permissions []string
    
    // Query untuk mendapatkan permissions berdasarkan role
    err := s.db.Table("role_permissions").
        Select("permissions.name").
        Joins("JOIN permissions ON role_permissions.permission_id = permissions.id").
        Joins("JOIN roles ON roles.id = role_permissions.role_id").
        Where("roles.name = ?", string(role)).
        Pluck("permissions.name", &permissions).Error
    
    if err != nil {
        return nil, err
    }
    
    return permissions, nil
}

func (s *AuthService) generateAuthResponse(userAuth *models.UserAuth, userInfo *UserInfo, sessionID, ipAddress, userAgent string) (*AuthResponse, error) {
    // Get user permissions
    permissions, err := s.GetUserPermissions(models.UserRole(userInfo.Role), userAuth.ID)
    if err != nil {
        return nil, err
    }

    // Generate tokens
    tokenPair, err := s.tokenService.GenerateTokenPair(userAuth, userInfo, permissions, sessionID)
    if err != nil {
        return nil, err
    }

    // Store refresh token
    refreshTokenRecord := &models.RefreshToken{
        UserID:    userAuth.ID,
        Token:     tokenPair.RefreshToken,
        ExpiresAt: time.Now().Add(time.Duration(s.config.RefreshExpirationDays) * 24 * time.Hour),
        CreatedAt: time.Now(),
        UserAgent: userAgent,
        IPAddress: ipAddress,
    }

    if err := s.db.Create(refreshTokenRecord).Error; err != nil {
        return nil, err
    }

    return &AuthResponse{
        AccessToken:  tokenPair.AccessToken,
        RefreshToken: tokenPair.RefreshToken,
        ExpiresIn:    tokenPair.ExpiresIn,
        TokenType:    tokenPair.TokenType,
        User:         userInfo,
    }, nil
}

func (s *AuthService) validatePassword(password string) error {
    if len(password) < s.config.Security.PasswordMinLength {
        return fmt.Errorf("password must be at least %d characters long", s.config.Security.PasswordMinLength)
    }

    if s.config.Security.PasswordRequireSpecial {
        // Add password complexity validation here
        // This is a simplified check
        hasSpecial := false
        for _, char := range password {
            if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9')) {
                hasSpecial = true
                break
            }
        }
        if !hasSpecial {
            return errors.New("password must contain at least one special character")
        }
    }

    return nil
}

func (s *AuthService) checkRateLimit(email, ipAddress string) error {
    // Check login attempts for this email
    var count int64
    s.db.Model(&models.LoginAttempt{}).
        Where("email = ? AND created_at > ? AND success = ?", email, time.Now().Add(-s.config.RateLimit.LoginWindow), false).
        Count(&count)

    if count >= int64(s.config.RateLimit.LoginAttempts) {
        return errors.New("too many failed login attempts, please try again later")
    }

    return nil
}

func (s *AuthService) handleFailedLogin(userAuth *models.UserAuth, ipAddress, userAgent string) {
    userAuth.FailedLoginCount++
    
    // Lock account after too many failed attempts
    if userAuth.FailedLoginCount >= 5 {
        lockUntil := time.Now().Add(15 * time.Minute)
        userAuth.LockedUntil = &lockUntil
    }

    s.db.Save(userAuth)
    s.logLoginAttempt(userAuth.Email, ipAddress, userAgent, false, "Invalid password")
}

func (s *AuthService) logLoginAttempt(email, ipAddress, userAgent string, success bool, failureReason string) {
    loginAttempt := &models.LoginAttempt{
        Email:         email,
        IPAddress:     ipAddress,
        UserAgent:     userAgent,
        Success:       success,
        FailureReason: failureReason,
        CreatedAt:     time.Now(),
    }
    s.db.Create(loginAttempt)
}

func (s *AuthService) logAuditEvent(userID *uuid.UUID, action models.AuditAction, resource, details, ipAddress, userAgent string, success bool, errorMessage string) {
    auditLog := &models.AuditLog{
        UserID:       userID,
        Action:       action,
        Resource:     resource,
        Details:      details,
        IPAddress:    ipAddress,
        UserAgent:    userAgent,
        Success:      success,
        ErrorMessage: errorMessage,
        CreatedAt:    time.Now(),
    }
    s.db.Create(auditLog)
}
