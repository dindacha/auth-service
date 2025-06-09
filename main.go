package main

import (
    "auth-service/config"
    "auth-service/database"
    "auth-service/services"
    "auth-service/handlers"
    "log"
    "net/http"

    "github.com/gin-gonic/gin"
    "github.com/joho/godotenv"
)

func main() {
    // Load environment variables
    if err := godotenv.Load(); err != nil {
        log.Println("No .env file found")
    }

    // Load configuration
    cfg := config.Load()

    // Set Gin mode based on environment
    if cfg.Environment == "production" {
        gin.SetMode(gin.ReleaseMode)
    }

    // Initialize database
    db, err := database.InitDB(cfg)
    if err != nil {
        log.Fatal("Failed to connect to database:", err)
    }

    // Initialize services
    userClient := services.NewUserClient(cfg.UserServiceURL)
    authService := services.NewAuthService(db, cfg, userClient)
    // permissionService := services.NewPermissionService(db)

    // Initialize handlers
    authHandler := handlers.NewAuthHandler(authService, cfg)
    // permissionHandler := handlers.NewPermissionHandler(authService, permissionService)
    // adminHandler := handlers.NewAdminHandler(authService, permissionService)

    // Setup router
    r := gin.Default()

    // Global middleware (simplified)
    // r.Use(middleware.CORSMiddleware())
    // r.Use(middleware.SecurityHeaders())
    // r.Use(middleware.RequestLogger())

    // Public routes
    public := r.Group("/api/v1")
    {
        auth := public.Group("/auth")
        {
            auth.POST("/login", authHandler.Login)
            auth.POST("/refresh", authHandler.RefreshToken)
            auth.POST("/logout", authHandler.Logout)
            auth.GET("/validate", authHandler.ValidateToken)
            auth.GET("/check-permission", authHandler.CheckPermission)
        }

        // Internal endpoints (called by other services)
        internal := public.Group("/internal")
        {
            internal.POST("/register-user-auth", authHandler.RegisterUserAuth)
        }
    }

    // Protected routes (simplified)
    protected := r.Group("/api/v1")
    // protected.Use(middleware.AuthMiddleware(authService))
    {
        // User management
        user := protected.Group("/user")
        {
            user.POST("/change-password", authHandler.ChangePassword)
            user.GET("/sessions", authHandler.GetUserSessions)
            user.DELETE("/sessions/:id", authHandler.RevokeSession)
            // user.GET("/permissions", permissionHandler.GetUserPermissions)
        }

        // Admin routes (commented out for now)
        // admin := protected.Group("/admin")
        // admin.Use(middleware.RequirePermission("auth", "manage_permissions"))
        // {
        //     admin.GET("/users", adminHandler.GetUsers)
        //     admin.PUT("/users/:id/activate", adminHandler.ActivateUser)
        //     admin.PUT("/users/:id/deactivate", adminHandler.DeactivateUser)
        //     admin.POST("/users/:id/permissions", adminHandler.GrantUserPermission)
        //     admin.DELETE("/users/:id/permissions/:permissionId", adminHandler.RevokeUserPermission)
        //     admin.GET("/audit-logs", adminHandler.GetAuditLogs)
        //     admin.GET("/login-attempts", adminHandler.GetLoginAttempts)
        // }
    }

    // Health check
    r.GET("/health", func(c *gin.Context) {
        c.JSON(http.StatusOK, gin.H{
            "status":  "healthy",
            "service": "auth",
            "version": "1.0.0",
        })
    })

    log.Printf("Auth service starting on port %s", cfg.Port)
    log.Printf("Environment: %s", cfg.Environment)

    if err := r.Run(":" + cfg.Port); err != nil {
        log.Fatal("Failed to start server:", err)
    }
}