// models/auth.go - Updated for Member Service Integration
package models

import (
	"github.com/google/uuid"
	"gorm.io/gorm"
	"time"
)

type UserRole string

const (
	UserRoleAdmin     UserRole = "ADMIN"
	UserRoleCustomer  UserRole = "CUSTOMER" // Keep for backward compatibility
	UserRoleMember    UserRole = "MEMBER"   // Primary role for library members
	UserRoleMerchant  UserRole = "MERCHANT" // Keep if needed
	UserRoleModerator UserRole = "MODERATOR"
)

// UserAuth represents authentication data
// This service stores: ID, MemberID (link), Email, Password, Auth-related fields
// Member service stores: ID, Name, Phone, Borrowings
type UserAuth struct {
	ID                uuid.UUID      `json:"id" gorm:"type:uuid;primary_key"`
	MemberID          *string        `json:"member_id" gorm:"index;unique"` // 🔄 Changed to string to match GraphQL ID
	Email             string         `json:"email" gorm:"unique;not null;index"`
	PasswordHash      string         `json:"-" gorm:"not null"`
	IsActive          bool           `json:"is_active" gorm:"default:true;index"`
	IsEmailVerified   bool           `json:"is_email_verified" gorm:"default:false"`
	Is2FAEnabled      bool           `json:"is_2fa_enabled" gorm:"default:false"`
	TwoFactorSecret   string         `json:"-" gorm:"column:two_factor_secret"`
	FailedLoginCount  int            `json:"failed_login_count" gorm:"default:0"`
	LockedUntil       *time.Time     `json:"locked_until"`
	PasswordChangedAt *time.Time     `json:"password_changed_at"`
	LastLoginAt       *time.Time     `json:"last_login_at"`
	LastLoginIP       string         `json:"last_login_ip"`
	CreatedAt         time.Time      `json:"created_at"`
	UpdatedAt         time.Time      `json:"updated_at"`
	DeletedAt         gorm.DeletedAt `json:"deleted_at" gorm:"index"`
}

// RefreshToken stores refresh tokens
type RefreshToken struct {
	ID        uuid.UUID `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	UserID    uuid.UUID `json:"user_id" gorm:"type:uuid;not null;index"`
	Token     string    `json:"token" gorm:"unique;not null;index"`
	IsRevoked bool      `json:"is_revoked" gorm:"default:false"`
	ExpiresAt time.Time `json:"expires_at" gorm:"index"`
	CreatedAt time.Time `json:"created_at"`
	UserAgent string    `json:"user_agent"`
	IPAddress string    `json:"ip_address"`
	UserAuth  UserAuth  `json:"user_auth" gorm:"foreignKey:UserID"`
}

// LoginAttempt tracks login attempts for security
type LoginAttempt struct {
	ID            uuid.UUID `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	Email         string    `json:"email" gorm:"not null;index"`
	IPAddress     string    `json:"ip_address" gorm:"index"`
	UserAgent     string    `json:"user_agent"`
	Success       bool      `json:"success" gorm:"index"`
	FailureReason string    `json:"failure_reason"`
	CreatedAt     time.Time `json:"created_at" gorm:"index"`
}

// Session tracks active user sessions
type Session struct {
	ID        uuid.UUID `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	UserID    uuid.UUID `json:"user_id" gorm:"type:uuid;not null;index"`
	TokenID   string    `json:"token_id" gorm:"unique;not null;index"`
	IsActive  bool      `json:"is_active" gorm:"default:true;index"`
	ExpiresAt time.Time `json:"expires_at" gorm:"index"`
	CreatedAt time.Time `json:"created_at"`
	LastSeen  time.Time `json:"last_seen"`
	IPAddress string    `json:"ip_address"`
	UserAgent string    `json:"user_agent"`
	UserAuth  UserAuth  `json:"user_auth" gorm:"foreignKey:UserID"`
}

// PasswordReset for password reset functionality
type PasswordReset struct {
	ID        uuid.UUID `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	UserID    uuid.UUID `json:"user_id" gorm:"type:uuid;not null;index"`
	Token     string    `json:"token" gorm:"unique;not null;index"`
	IsUsed    bool      `json:"is_used" gorm:"default:false"`
	ExpiresAt time.Time `json:"expires_at" gorm:"index"`
	CreatedAt time.Time `json:"created_at"`
	UserAuth  UserAuth  `json:"user_auth" gorm:"foreignKey:UserID"`
}

// 🆕 NEW: MemberLink represents the relationship between auth and member services
// This helps track the integration status
type MemberLink struct {
	ID         uuid.UUID  `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	AuthUserID uuid.UUID  `json:"auth_user_id" gorm:"type:uuid;not null;index"`
	MemberID   string     `json:"member_id" gorm:"not null;index"`
	LinkedAt   time.Time  `json:"linked_at"`
	IsActive   bool       `json:"is_active" gorm:"default:true"`
	LastSyncAt *time.Time `json:"last_sync_at"`
	SyncStatus string     `json:"sync_status" gorm:"default:'active'"` // active, failed, pending
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
	UserAuth   UserAuth   `json:"user_auth" gorm:"foreignKey:AuthUserID"`
}
