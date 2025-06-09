package services

import (
    "auth-service/config"
    "auth-service/models"
    "errors"
    "time"
    "github.com/google/uuid"
    "github.com/golang-jwt/jwt/v5"
)

type TokenService struct {
    config *config.Config
}

type Claims struct {
    UserID      uuid.UUID           `json:"user_id"`
    Email       string              `json:"email"`
    Role        models.UserRole     `json:"role"`
    Permissions []string            `json:"permissions"`
    SessionID   string              `json:"session_id"`
    TokenType   string              `json:"token_type"`
    jwt.RegisteredClaims
}

type TokenPair struct {
    AccessToken  string    `json:"access_token"`
    RefreshToken string    `json:"refresh_token"`
    ExpiresIn    int64     `json:"expires_in"`
    TokenType    string    `json:"token_type"`
}

func NewTokenService(config *config.Config) *TokenService {
    return &TokenService{
        config: config,
    }
}

func (s *TokenService) GenerateTokenPair(userAuth *models.UserAuth, userInfo *UserInfo, permissions []string, sessionID string) (*TokenPair, error) {
    // Generate access token
    expirationTime := time.Now().Add(time.Duration(s.config.JWTExpirationHours) * time.Hour)
    
    claims := &Claims{
        UserID:      userAuth.ID,
        Email:       userAuth.Email,
        Role:        models.UserRole(userInfo.Role),
        Permissions: permissions,
        SessionID:   sessionID,
        TokenType:   "access",
        RegisteredClaims: jwt.RegisteredClaims{
            ExpiresAt: jwt.NewNumericDate(expirationTime),
            IssuedAt:  jwt.NewNumericDate(time.Now()),
            NotBefore: jwt.NewNumericDate(time.Now()),
            Issuer:    "auth-service",
            Subject:   userAuth.ID.String(),
            ID:        uuid.New().String(),
        },
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    accessToken, err := token.SignedString([]byte(s.config.JWTSecret))
    if err != nil {
        return nil, err
    }

    // Generate refresh token
    refreshToken := uuid.New().String()

    return &TokenPair{
        AccessToken:  accessToken,
        RefreshToken: refreshToken,
        ExpiresIn:    expirationTime.Unix(),
        TokenType:    "Bearer",
    }, nil
}

func (s *TokenService) ValidateToken(tokenString string) (*Claims, error) {
    claims := &Claims{}
    token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
        // Verify signing method
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, errors.New("unexpected signing method")
        }
        return []byte(s.config.JWTSecret), nil
    })

    if err != nil {
        return nil, err
    }

    if !token.Valid {
        return nil, errors.New("invalid token")
    }

    // Check token type
    if claims.TokenType != "access" {
        return nil, errors.New("invalid token type")
    }

    return claims, nil
}

func (s *TokenService) RefreshAccessToken(refreshToken string, userAuth *models.UserAuth, userInfo *UserInfo, permissions []string, sessionID string) (*TokenPair, error) {
    // Generate new token pair
    return s.GenerateTokenPair(userAuth, userInfo, permissions, sessionID)
}