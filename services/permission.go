package services

import (
    "auth-service/models"
    "github.com/google/uuid"
    "gorm.io/gorm"
    "time"
)

type PermissionService struct {
    db *gorm.DB
}

func NewPermissionService(db *gorm.DB) *PermissionService {
    return &PermissionService{
        db: db,
    }
}

func (s *PermissionService) GetUserPermissions(userRole models.UserRole, userID uuid.UUID) ([]string, error) {
    var permissions []models.Permission

    // Get role-based permissions
    err := s.db.Table("permissions").
        Joins("JOIN role_permissions ON permissions.id = role_permissions.permission_id").
        Where("role_permissions.role = ? AND role_permissions.is_active = ? AND permissions.is_active = ?", userRole, true, true).
        Find(&permissions).Error

    if err != nil {
        return nil, err
    }

    // Get user-specific permissions (overrides)
    var userPermissions []models.UserPermission
    err = s.db.Preload("Permission").
        Where("user_id = ? AND (expires_at IS NULL OR expires_at > NOW())", userID).
        Find(&userPermissions).Error

    if err != nil {
        return nil, err
    }

    // Combine permissions
    permissionSet := make(map[string]bool)
    
    // Add role permissions
    for _, perm := range permissions {
        permissionSet[perm.Name] = true
    }

    // Apply user-specific overrides
    for _, userPerm := range userPermissions {
        if userPerm.IsGranted {
            permissionSet[userPerm.Permission.Name] = true
        } else {
            delete(permissionSet, userPerm.Permission.Name)
        }
    }

    // Convert to slice
    var permissionNames []string
    for permName := range permissionSet {
        permissionNames = append(permissionNames, permName)
    }

    return permissionNames, nil
}

func (s *PermissionService) HasPermission(userRole models.UserRole, userID uuid.UUID, resource, action string) (bool, error) {
    permissions, err := s.GetUserPermissions(userRole, userID)
    if err != nil {
        return false, err
    }

    // Check for specific permission
    targetPermission := resource + "_" + action
    for _, perm := range permissions {
        if perm == targetPermission {
            return true, nil
        }
    }

    return false, nil
}

func (s *PermissionService) GrantUserPermission(userID, permissionID, grantedBy uuid.UUID) error {
    userPermission := &models.UserPermission{
        UserID:       userID,
        PermissionID: permissionID,
        IsGranted:    true,
        GrantedBy:    grantedBy,
        CreatedAt:    time.Now(),
    }

    return s.db.Create(userPermission).Error
}

func (s *PermissionService) RevokeUserPermission(userID, permissionID uuid.UUID) error {
    return s.db.Model(&models.UserPermission{}).
        Where("user_id = ? AND permission_id = ?", userID, permissionID).
        Update("is_granted", false).Error
}
