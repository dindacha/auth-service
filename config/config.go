package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	Port                  string
	Environment           string
	DatabaseURL           string
	JWTSecret             string
	JWTExpirationHours    int
	RefreshExpirationDays int
	UserServiceURL        string
	BCryptCost            int
	RateLimit             RateLimitConfig
	Security              SecurityConfig
}

type RateLimitConfig struct {
	LoginAttempts int
	LoginWindow   time.Duration
	TokenRequests int
	TokenWindow   time.Duration
}

type SecurityConfig struct {
	RequireEmailVerification bool
	Enable2FA                bool
	PasswordMinLength        int
	PasswordRequireSpecial   bool
	SessionTimeout           time.Duration
	MaxActiveSessions        int
}

func Load() *Config {
	return &Config{
		Port:                  getEnv("PORT", "8081"),
		Environment:           getEnv("ENVIRONMENT", "development"),
		DatabaseURL:           getEnv("DATABASE_URL", "postgres://user:password@localhost/auth_db?sslmode=disable"),
		JWTSecret:             getEnv("JWT_SECRET", "your-secret-key"),
		JWTExpirationHours:    getEnvInt("JWT_EXPIRATION_HOURS", 24),
		RefreshExpirationDays: getEnvInt("REFRESH_EXPIRATION_DAYS", 7),
		UserServiceURL:        getEnv("USER_SERVICE_URL", "http://localhost:8082"),
		BCryptCost:            getEnvInt("BCRYPT_COST", 12),
		RateLimit: RateLimitConfig{
			LoginAttempts: getEnvInt("RATE_LIMIT_LOGIN_ATTEMPTS", 5),
			LoginWindow:   time.Duration(getEnvInt("RATE_LIMIT_LOGIN_WINDOW_MINUTES", 15)) * time.Minute,
			TokenRequests: getEnvInt("RATE_LIMIT_TOKEN_REQUESTS", 10),
			TokenWindow:   time.Duration(getEnvInt("RATE_LIMIT_TOKEN_WINDOW_MINUTES", 1)) * time.Minute,
		},
		Security: SecurityConfig{
			RequireEmailVerification: getEnvBool("REQUIRE_EMAIL_VERIFICATION", false),
			Enable2FA:                getEnvBool("ENABLE_2FA", false),
			PasswordMinLength:        getEnvInt("PASSWORD_MIN_LENGTH", 8),
			PasswordRequireSpecial:   getEnvBool("PASSWORD_REQUIRE_SPECIAL", true),
			SessionTimeout:           time.Duration(getEnvInt("SESSION_TIMEOUT_HOURS", 24)) * time.Hour,
			MaxActiveSessions:        getEnvInt("MAX_ACTIVE_SESSIONS", 5),
		},
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}
