package graph

import (
    "auth-service/config"
    "auth-service/services"
)

// This file will not be regenerated automatically.
//
// It serves as dependency injection for your app, add any dependencies you require here.

type Resolver struct {
    authService *services.AuthService
    config      *config.Config
}

func NewResolver(authService *services.AuthService, config *config.Config) *Resolver {
    return &Resolver{
        authService: authService,
        config:      config,
    }
}