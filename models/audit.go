package models

import (
    "time"
    "github.com/google/uuid"
)

type AuditAction string

const (
    AuditActionLogin         AuditAction = "LOGIN"
    AuditActionLogout        AuditAction = "LOGOUT"
    AuditActionPasswordChange AuditAction = "PASSWORD_CHANGE"
    AuditActionTokenRefresh  AuditAction = "TOKEN_REFRESH"
    AuditActionPermissionGrant AuditAction = "PERMISSION_GRANT"
    AuditActionPermissionRevoke AuditAction = "PERMISSION_REVOKE"
    AuditActionAccountLock   AuditAction = "ACCOUNT_LOCK"
    AuditActionAccountUnlock AuditAction = "ACCOUNT_UNLOCK"
)

// AuditLog tracks all authentication events
type AuditLog struct {
    ID          uuid.UUID   `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
    UserID      *uuid.UUID  `json:"user_id" gorm:"type:uuid;index"`
    Action      AuditAction `json:"action" gorm:"not null;index"`
    Resource    string      `json:"resource" gorm:"index"`
    Details     string      `json:"details" gorm:"type:text"`
    IPAddress   string      `json:"ip_address" gorm:"index"`
    UserAgent   string      `json:"user_agent"`
    Success     bool        `json:"success" gorm:"index"`
    ErrorMessage string     `json:"error_message"`
    CreatedAt   time.Time   `json:"created_at" gorm:"index"`
}