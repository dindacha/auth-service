package services

import (
	"auth-service/config"
	"auth-service/models"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"time"
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

// Registration request for library members
type RegisterLibraryMemberRequest struct {
	Name     string `json:"name" binding:"required"`
	Phone    string `json:"phone" binding:"required"`
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8"`
}

// Keep existing RegisterAuthRequest for backward compatibility
type RegisterAuthRequest struct {
	UserID   string `json:"user_id" binding:"required"`
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8"`
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

// RegisterLibraryMember - Main registration method for library members
func (s *AuthService) RegisterLibraryMember(req RegisterLibraryMemberRequest) error {
	// Step 1: Check if email already exists
	var existingAuth models.UserAuth
	if err := s.db.Where("email = ?", req.Email).First(&existingAuth).Error; err == nil {
		return errors.New("email already registered")
	}

	// Step 2: Validate password
	if err := s.validatePassword(req.Password); err != nil {
		return err
	}

	// Step 3: Create member in member service first
	member, err := s.userClient.CreateMember(req.Name, req.Phone)
	if err != nil {
		return fmt.Errorf("failed to create member in member service: %w", err)
	}

	// Step 4: Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), s.config.BCryptCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Step 5: Create auth record linked to member
	userID := uuid.New()
	userAuth := &models.UserAuth{
		ID:                userID,
		MemberID:          &member.ID, // Link to member service
		Email:             req.Email,
		PasswordHash:      string(hashedPassword),
		IsActive:          true,
		IsEmailVerified:   !s.config.Security.RequireEmailVerification,
		PasswordChangedAt: &[]time.Time{time.Now()}[0],
		CreatedAt:         time.Now(),
		UpdatedAt:         time.Now(),
	}

	if err := s.db.Create(userAuth).Error; err != nil {
		return fmt.Errorf("failed to create auth record: %w", err)
	}

	// Step 6: Log audit event
	s.logAuditEvent(&userID, models.AuditActionLogin, "auth", "Library member registered", "", "", true, "")

	return nil
}

// Login - Updated to combine auth and member data
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

	// Check account status
	if userAuth.LockedUntil != nil && userAuth.LockedUntil.After(time.Now()) {
		s.logLoginAttempt(req.Email, ipAddress, userAgent, false, "Account locked")
		return nil, errors.New("account is temporarily locked")
	}

	if !userAuth.IsActive {
		s.logLoginAttempt(req.Email, ipAddress, userAgent, false, "Account inactive")
		return nil, errors.New("account is deactivated")
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(userAuth.PasswordHash), []byte(req.Password)); err != nil {
		s.handleFailedLogin(&userAuth, ipAddress, userAgent)
		return nil, errors.New("invalid credentials")
	}

	// Reset failed login count
	s.db.Model(&userAuth).Updates(map[string]interface{}{
		"failed_login_count": 0,
		"locked_until":       nil,
		"last_login_at":      time.Now(),
		"last_login_ip":      ipAddress,
	})

	// Get combined user info (auth + member data)
	userInfo, err := s.getCombinedUserInfo(&userAuth)
	if err != nil {
		s.logLoginAttempt(req.Email, ipAddress, userAgent, false, "Failed to get user info")
		return nil, err
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
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	// Log successful login
	s.logLoginAttempt(req.Email, ipAddress, userAgent, true, "")
	s.logAuditEvent(&userAuth.ID, models.AuditActionLogin, "auth", "User logged in", ipAddress, userAgent, true, "")

	// Generate auth response
	return s.generateAuthResponse(&userAuth, userInfo, sessionID, ipAddress, userAgent)
}

// RefreshToken - Updated to use combined user info
func (s *AuthService) RefreshToken(refreshToken string, ipAddress, userAgent string) (*AuthResponse, error) {
	var tokenRecord models.RefreshToken
	if err := s.db.Preload("UserAuth").Where("token = ? AND expires_at > ? AND is_revoked = ?", refreshToken, time.Now(), false).First(&tokenRecord).Error; err != nil {
		return nil, errors.New("invalid or expired refresh token")
	}

	if !tokenRecord.UserAuth.IsActive {
		return nil, errors.New("account is deactivated")
	}

	// Get updated combined user info
	userInfo, err := s.getCombinedUserInfo(&tokenRecord.UserAuth)
	if err != nil {
		return nil, err
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

	s.logAuditEvent(&tokenRecord.UserID, models.AuditActionTokenRefresh, "auth", "Token refreshed", ipAddress, userAgent, true, "")

	return s.generateAuthResponse(&tokenRecord.UserAuth, userInfo, sessionID, ipAddress, userAgent)
}

// GetUserByEmail - Gets combined user information by email
func (s *AuthService) GetUserByEmail(email string) (*UserInfo, error) {
	var userAuth models.UserAuth
	if err := s.db.Where("email = ?", email).First(&userAuth).Error; err != nil {
		return nil, errors.New("user not found")
	}

	return s.getCombinedUserInfo(&userAuth)
}

// GetUserWithBorrowings - Gets user info including current borrowings
func (s *AuthService) GetUserWithBorrowings(email string) (*UserInfo, error) {
	userInfo, err := s.GetUserByEmail(email)
	if err != nil {
		return nil, err
	}

	// The borrowings are already included from the member service
	return userInfo, nil
}

// UpdateMemberInfo - Updates member information in member service
func (s *AuthService) UpdateMemberInfo(email, name, phone string) error {
	var userAuth models.UserAuth
	if err := s.db.Where("email = ?", email).First(&userAuth).Error; err != nil {
		return errors.New("user not found")
	}

	if userAuth.MemberID == nil {
		return errors.New("user not linked to member service")
	}

	_, err := s.userClient.UpdateMember(*userAuth.MemberID, name, phone)
	return err
}

// ValidateToken - Unchanged
func (s *AuthService) ValidateToken(tokenString string) (*Claims, error) {
	claims, err := s.tokenService.ValidateToken(tokenString)
	if err != nil {
		return nil, err
	}

	var session models.Session
	if err := s.db.Where("token_id = ? AND is_active = ? AND expires_at > ?", claims.SessionID, true, time.Now()).First(&session).Error; err != nil {
		return nil, errors.New("session not found or expired")
	}

	s.db.Model(&session).Update("last_seen", time.Now())

	var userAuth models.UserAuth
	if err := s.db.First(&userAuth, claims.UserID).Error; err != nil {
		return nil, errors.New("user not found")
	}

	if !userAuth.IsActive {
		return nil, errors.New("account is deactivated")
	}

	return claims, nil
}

// Helper method to get combined user info
func (s *AuthService) getCombinedUserInfo(userAuth *models.UserAuth) (*UserInfo, error) {
	if userAuth.MemberID == nil {
		// No member link - return auth-only data
		return &UserInfo{
			ID:         userAuth.ID,
			Email:      userAuth.Email,
			Name:       "Member",
			Role:       "MEMBER",
			IsActive:   userAuth.IsActive,
			IsVerified: userAuth.IsEmailVerified,
			CreatedAt:  userAuth.CreatedAt,
			Borrowings: []Loan{},
		}, nil
	}

	// Get combined data from member service
	return s.userClient.CombineUserInfo(
		userAuth.ID,
		*userAuth.MemberID,
		userAuth.Email,
		userAuth.IsActive,
		userAuth.IsEmailVerified,
		userAuth.CreatedAt,
	)
}

// Keep your existing RegisterUserAuth for backward compatibility
func (s *AuthService) RegisterUserAuth(req RegisterAuthRequest) error {
	userID, err := uuid.Parse(req.UserID)
	if err != nil {
		return fmt.Errorf("invalid user ID format: %w", err)
	}

	var existingAuth models.UserAuth
	if err := s.db.Where("email = ? OR id = ?", req.Email, userID).First(&existingAuth).Error; err == nil {
		return errors.New("user auth already exists")
	}

	if err := s.validatePassword(req.Password); err != nil {
		return err
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), s.config.BCryptCost)
	if err != nil {
		return err
	}

	userAuth := &models.UserAuth{
		ID:                userID,
		Email:             req.Email,
		PasswordHash:      string(hashedPassword),
		IsActive:          true,
		IsEmailVerified:   !s.config.Security.RequireEmailVerification,
		PasswordChangedAt: &[]time.Time{time.Now()}[0],
		CreatedAt:         time.Now(),
		UpdatedAt:         time.Now(),
	}

	if err := s.db.Create(userAuth).Error; err != nil {
		return err
	}

	s.logAuditEvent(&userID, models.AuditActionLogin, "auth", "User auth created", "", "", true, "")
	return nil
}

// Keep all existing helper methods unchanged
func (s *AuthService) GetUserPermissions(role models.UserRole, userID uuid.UUID) ([]string, error) {
	var permissions []string

	err := s.db.Table("role_permissions").
		Select("permissions.name").
		Joins("JOIN permissions ON role_permissions.permission_id = permissions.id").
		Where("role_permissions.role = ?", string(role)).
		Pluck("permissions.name", &permissions).Error

	if err != nil {
		return nil, err
	}

	return permissions, nil
}

func (s *AuthService) generateAuthResponse(userAuth *models.UserAuth, userInfo *UserInfo, sessionID, ipAddress, userAgent string) (*AuthResponse, error) {
	permissions, err := s.GetUserPermissions(models.UserRole(userInfo.Role), userAuth.ID)
	if err != nil {
		return nil, err
	}

	tokenPair, err := s.tokenService.GenerateTokenPair(userAuth, userInfo, permissions, sessionID)
	if err != nil {
		return nil, err
	}

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
