package models

import (
    "time"
    "github.com/google/uuid"
)

// Permission defines what actions can be performed
type Permission struct {
    ID          uuid.UUID `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
    Name        string    `json:"name" gorm:"unique;not null;index"`
    Resource    string    `json:"resource" gorm:"not null;index"`
    Action      string    `json:"action" gorm:"not null;index"`
    Description string    `json:"description"`
    IsActive    bool      `json:"is_active" gorm:"default:true"`
    CreatedAt   time.Time `json:"created_at"`
    UpdatedAt   time.Time `json:"updated_at"`
}

// RolePermission maps roles to permissions
type RolePermission struct {
    ID           uuid.UUID  `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
    Role         UserRole   `json:"role" gorm:"not null;index"`
    PermissionID uuid.UUID  `json:"permission_id" gorm:"type:uuid;not null"`
    IsActive     bool       `json:"is_active" gorm:"default:true"`
    CreatedAt    time.Time  `json:"created_at"`
    Permission   Permission `json:"permission" gorm:"foreignKey:PermissionID"`
}

// UserPermission for user-specific permissions (overrides)
type UserPermission struct {
    ID           uuid.UUID  `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
    UserID       uuid.UUID  `json:"user_id" gorm:"type:uuid;not null;index"`
    PermissionID uuid.UUID  `json:"permission_id" gorm:"type:uuid;not null"`
    IsGranted    bool       `json:"is_granted" gorm:"default:true"`
    GrantedBy    uuid.UUID  `json:"granted_by" gorm:"type:uuid"`
    ExpiresAt    *time.Time `json:"expires_at"`
    CreatedAt    time.Time  `json:"created_at"`
    Permission   Permission `json:"permission" gorm:"foreignKey:PermissionID"`
    UserAuth     UserAuth   `json:"user_auth" gorm:"foreignKey:UserID"`
}