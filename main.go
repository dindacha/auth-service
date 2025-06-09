package main

import (
    "auth-service/config"
    "auth-service/database"
    "auth-service/graph"
    "auth-service/services"
    "log"
    "net/http"

    "github.com/99designs/gqlgen/graphql/handler"
    "github.com/99designs/gqlgen/graphql/playground"
    "github.com/joho/godotenv"
)

func main() {
    // Load environment variables
    if err := godotenv.Load(); err != nil {
        log.Println("No .env file found")
    }

    // Load configuration
    cfg := config.Load()

    // Initialize database
    db, err := database.InitDB(cfg)
    if err != nil {
        log.Fatal("Failed to connect to database:", err)
    }

    // Initialize services
    userClient := services.NewUserClient(cfg.UserServiceURL)
    authService := services.NewAuthService(db, cfg, userClient)

    // Initialize GraphQL resolver
    resolver := graph.NewResolver(authService, cfg)

    // Create GraphQL server
    srv := handler.NewDefaultServer(graph.NewExecutableSchema(graph.Config{
        Resolvers: resolver,
    }))

    // Middleware to add context
    contextMiddleware := func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            ctx := r.Context()
            
            // Add IP and User-Agent to context
            ctx = graph.WithIPAddress(ctx, graph.GetClientIP(r))
            ctx = graph.WithUserAgent(ctx, r.UserAgent())
            
            next.ServeHTTP(w, r.WithContext(ctx))
        })
    }

    // Setup routes
    http.Handle("/", playground.Handler("GraphQL playground", "/graphql"))
    http.Handle("/graphql", contextMiddleware(srv))

    // Health check endpoint
    http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusOK)
        w.Write([]byte(`{"status":"healthy","service":"auth","version":"1.0.0"}`))
    })

    log.Printf("🚀 GraphQL server starting on port %s", cfg.Port)
    log.Printf("🎮 GraphQL playground: http://localhost:%s/", cfg.Port)
    log.Printf("📡 GraphQL endpoint: http://localhost:%s/graphql", cfg.Port)
    log.Printf("Environment: %s", cfg.Environment)

    if err := http.ListenAndServe(":"+cfg.Port, nil); err != nil {
        log.Fatal("Failed to start server:", err)
    }
}