package database

import (
    "auth-service/config"
    "auth-service/models"
    "gorm.io/driver/postgres"
    "gorm.io/gorm"
    "gorm.io/gorm/logger"
    "time"
)

func InitDB(cfg *config.Config) (*gorm.DB, error) {
    db, err := gorm.Open(postgres.Open(cfg.DatabaseURL), &gorm.Config{
        Logger: logger.Default.LogMode(logger.Info),
    })
    if err != nil {
        return nil, err
    }

    // Configure connection pool
    sqlDB, err := db.DB()
    if err != nil {
        return nil, err
    }

    sqlDB.SetMaxIdleConns(10)
    sqlDB.SetMaxOpenConns(100)
    sqlDB.SetConnMaxLifetime(time.Hour)

    // Enable UUID extension
    db.Exec("CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\";")

    // Auto migrate schemas
    err = db.AutoMigrate(
        &models.UserAuth{},
        &models.RefreshToken{},
        &models.LoginAttempt{},
        &models.Session{},
        &models.PasswordReset{},
        &models.Permission{},
        &models.RolePermission{},
        &models.UserPermission{},
        &models.AuditLog{},
    )
    if err != nil {
        return nil, err
    }

    // Create indexes for performance
    createIndexes(db)

    // Seed default data
    seedPermissions(db)
    cleanupExpiredTokens(db)

    return db, nil
}

func createIndexes(db *gorm.DB) {
    // Create composite indexes for better query performance
    db.Exec("CREATE INDEX IF NOT EXISTS idx_user_auth_email_active ON user_auths(email, is_active);")
    db.Exec("CREATE INDEX IF NOT EXISTS idx_login_attempts_email_created ON login_attempts(email, created_at);")
    db.Exec("CREATE INDEX IF NOT EXISTS idx_sessions_user_active ON sessions(user_id, is_active);")
    db.Exec("CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_revoked ON refresh_tokens(user_id, is_revoked);")
    db.Exec("CREATE INDEX IF NOT EXISTS idx_role_permissions_role_active ON role_permissions(role, is_active);")
    db.Exec("CREATE INDEX IF NOT EXISTS idx_audit_logs_user_action_created ON audit_logs(user_id, action, created_at);")
}

func seedPermissions(db *gorm.DB) {
    permissions := []models.Permission{
        // Payment permissions
        {Name: "create_payment", Resource: "payment", Action: "create", Description: "Create new payment"},
        {Name: "read_payment", Resource: "payment", Action: "read", Description: "Read own payment data"},
        {Name: "update_payment", Resource: "payment", Action: "update", Description: "Update payment"},
        {Name: "delete_payment", Resource: "payment", Action: "delete", Description: "Delete payment"},
        {Name: "read_all_payments", Resource: "payment", Action: "read_all", Description: "Read all payments (admin)"},
        
        // User permissions
        {Name: "read_profile", Resource: "user", Action: "read", Description: "Read own profile"},
        {Name: "update_profile", Resource: "user", Action: "update", Description: "Update own profile"},
        {Name: "manage_users", Resource: "user", Action: "manage", Description: "Manage all users (admin)"},
        
        // Auth permissions
        {Name: "manage_permissions", Resource: "auth", Action: "manage_permissions", Description: "Manage user permissions"},
        {Name: "view_audit_logs", Resource: "auth", Action: "view_audit", Description: "View audit logs"},
        {Name: "manage_sessions", Resource: "auth", Action: "manage_sessions", Description: "Manage user sessions"},
    }

    for _, perm := range permissions {
        var existing models.Permission
        if err := db.Where("name = ?", perm.Name).First(&existing).Error; err != nil {
            if err == gorm.ErrRecordNotFound {
                db.Create(&perm)
            }
        }
    }

    // Seed role permissions
    rolePermissions := map[models.UserRole][]string{
        models.UserRoleCustomer: {
            "create_payment", "read_payment", "read_profile", "update_profile",
        },
        models.UserRoleMerchant: {
            "create_payment", "read_payment", "update_payment", 
            "read_profile", "update_profile",
        },
        models.UserRoleModerator: {
            "create_payment", "read_payment", "update_payment",
            "read_profile", "update_profile", "view_audit_logs",
        },
        models.UserRoleAdmin: {
            "create_payment", "read_payment", "update_payment", "delete_payment", "read_all_payments",
            "read_profile", "update_profile", "manage_users",
            "manage_permissions", "view_audit_logs", "manage_sessions",
        },
    }

    for role, permNames := range rolePermissions {
        for _, permName := range permNames {
            var perm models.Permission
            if err := db.Where("name = ?", permName).First(&perm).Error; err == nil {
                var existing models.RolePermission
                if err := db.Where("role = ? AND permission_id = ?", role, perm.ID).First(&existing).Error; err != nil {
                    if err == gorm.ErrRecordNotFound {
                        db.Create(&models.RolePermission{
                            Role:         role,
                            PermissionID: perm.ID,
                            IsActive:     true,
                        })
                    }
                }
            }
        }
    }
}

func cleanupExpiredTokens(db *gorm.DB) {
    // Clean up expired refresh tokens
    db.Where("expires_at < ?", time.Now()).Delete(&models.RefreshToken{})
    
    // Clean up expired password reset tokens
    db.Where("expires_at < ?", time.Now()).Delete(&models.PasswordReset{})
    
    // Clean up expired sessions
    db.Where("expires_at < ?", time.Now()).Delete(&models.Session{})
}