package graph

import (
    "context"
    "auth-service/graph/model"
    "auth-service/services"
    "strings"
)

// Health returns the health status
func (r *queryResolver) Health(ctx context.Context) (*model.HealthResponse, error) {
    return &model.HealthResponse{
        Status:  "healthy",
        Service: "auth",
        Version: "1.0.0",
    }, nil
}

// RegisterUserAuth creates new user authentication (kept for backward compatibility)
func (r *mutationResolver) RegisterUserAuth(ctx context.Context, input model.RegisterAuthInput) (*model.GenericResponse, error) {
    req := services.RegisterAuthRequest{
        UserID:   input.UserID,
        Email:    input.Email,
        Password: input.Password,
    }
    
    err := r.authService.RegisterUserAuth(req)
    if err != nil {
        return &model.GenericResponse{
            Success: false,
            Message: err.Error(),
        }, nil
    }
    
    return &model.GenericResponse{
        Success: true,
        Message: "User auth created successfully",
    }, nil
}

// 🆕 ADD: RegisterLibraryMember creates new library member with auth
func (r *mutationResolver) RegisterLibraryMember(ctx context.Context, input model.RegisterLibraryMemberInput) (*model.GenericResponse, error) {
    req := services.RegisterLibraryMemberRequest{
        Name:     input.Name,
        Phone:    input.Phone,
        Email:    input.Email,
        Password: input.Password,
    }
    
    err := r.authService.RegisterLibraryMember(req)
    if err != nil {
        return &model.GenericResponse{
            Success: false,
            Message: err.Error(),
        }, nil
    }
    
    return &model.GenericResponse{
        Success: true,
        Message: "Library member registered successfully",
    }, nil
}

// 🔄 UPDATE: Login handles user authentication with new user structure
func (r *mutationResolver) Login(ctx context.Context, input model.LoginInput) (*model.AuthResponse, error) {
    // Get IP and User-Agent from context
    ip := GetIPFromContext(ctx)
    ua := GetUserAgentFromContext(ctx)
    
    // Create login request
    req := services.LoginRequest{
        Email:    input.Email,
        Password: input.Password,
    }
    
    // Call auth service
    response, err := r.authService.Login(req, ip, ua)
    if err != nil {
        return nil, err
    }
    
    // Split name into firstName and lastName for GraphQL compatibility
    firstName, lastName := splitName(response.User.Name)
    
    // Convert to GraphQL response
    return &model.AuthResponse{
        AccessToken:  response.AccessToken,
        RefreshToken: response.RefreshToken,
        ExpiresIn:    int(response.ExpiresIn),
        TokenType:    response.TokenType,
        User: &model.User{
            ID:         response.User.ID.String(),
            Email:      response.User.Email,
            FirstName:  firstName,
            LastName:   lastName,
            Phone:      &response.User.Phone,
            Role:       model.UserRole(response.User.Role),
            IsActive:   response.User.IsActive,
            IsVerified: response.User.IsVerified,
            CreatedAt:  response.User.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
        },
    }, nil
}

// ValidateToken validates JWT token
func (r *queryResolver) ValidateToken(ctx context.Context, token string) (*model.ValidationResponse, error) {
    claims, err := r.authService.ValidateToken(token)
    if err != nil {
        return &model.ValidationResponse{
            Valid: false,
        }, nil
    }
    
    userID := claims.UserID.String()
    role := model.UserRole(claims.Role)
    
    return &model.ValidationResponse{
        Valid:  true,
        UserID: &userID,
        Email:  &claims.Email,
        Role:   &role,
    }, nil
}

// 🔄 UPDATE: RefreshToken refreshes access token with new user structure
func (r *mutationResolver) RefreshToken(ctx context.Context, input model.RefreshTokenInput) (*model.AuthResponse, error) {
    ip := GetIPFromContext(ctx)
    ua := GetUserAgentFromContext(ctx)
    
    response, err := r.authService.RefreshToken(input.RefreshToken, ip, ua)
    if err != nil {
        return nil, err
    }
    
    // Split name into firstName and lastName for GraphQL compatibility
    firstName, lastName := splitName(response.User.Name)
    
    return &model.AuthResponse{
        AccessToken:  response.AccessToken,
        RefreshToken: response.RefreshToken,
        ExpiresIn:    int(response.ExpiresIn),
        TokenType:    response.TokenType,
        User: &model.User{
            ID:         response.User.ID.String(),
            Email:      response.User.Email,
            FirstName:  firstName,
            LastName:   lastName,
            Phone:      &response.User.Phone,
            Role:       model.UserRole(response.User.Role),
            IsActive:   response.User.IsActive,
            IsVerified: response.User.IsVerified,
            CreatedAt:  response.User.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
        },
    }, nil
}

// 🆕 ADD: GetUserByEmail gets user by email (combines data from both services)
func (r *queryResolver) GetUserByEmail(ctx context.Context, email string) (*model.User, error) {
    userInfo, err := r.authService.GetUserByEmail(email)
    if err != nil {
        return nil, err
    }
    
    // Split name into firstName and lastName for GraphQL compatibility
    firstName, lastName := splitName(userInfo.Name)
    
    return &model.User{
        ID:         userInfo.ID.String(),
        Email:      userInfo.Email,
        FirstName:  firstName,
        LastName:   lastName,
        Phone:      &userInfo.Phone,
        Role:       model.UserRole(userInfo.Role),
        IsActive:   userInfo.IsActive,
        IsVerified: userInfo.IsVerified,
        CreatedAt:  userInfo.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
    }, nil
}

// Placeholder implementations (unchanged)
func (r *mutationResolver) Logout(ctx context.Context, refreshToken string) (*model.GenericResponse, error) {
    // TODO: Implement logout logic with authService
    return &model.GenericResponse{
        Success: true,
        Message: "Logged out successfully",
    }, nil
}

func (r *mutationResolver) ChangePassword(ctx context.Context, input model.ChangePasswordInput) (*model.GenericResponse, error) {
    // TODO: Implement change password
    return &model.GenericResponse{
        Success: true,
        Message: "Password changed successfully",
    }, nil
}

func (r *mutationResolver) RevokeSession(ctx context.Context, token string, sessionID string) (*model.GenericResponse, error) {
    // TODO: Implement revoke session
    return &model.GenericResponse{
        Success: true,
        Message: "Session revoked successfully",
    }, nil
}

func (r *queryResolver) CheckPermission(ctx context.Context, token string, resource string, action string) (*model.PermissionResponse, error) {
    claims, err := r.authService.ValidateToken(token)
    if err != nil {
        return nil, err
    }
    
    // Check if user has permission
    hasPermission := false
    targetPermission := resource + ":" + action
    for _, permission := range claims.Permissions {
        if permission == targetPermission {
            hasPermission = true
            break
        }
    }
    
    return &model.PermissionResponse{
        HasPermission: hasPermission,
        UserID:        claims.UserID.String(),
    }, nil
}

func (r *queryResolver) GetUserSessions(ctx context.Context, token string) ([]*model.Session, error) {
    // TODO: Implement get user sessions
    return []*model.Session{}, nil
}

// 🆕 ADD: Helper function to split name into firstName and lastName
func splitName(fullName string) (firstName, lastName string) {
    if fullName == "" {
        return "Member", ""
    }
    
    nameParts := strings.Fields(strings.TrimSpace(fullName))
    if len(nameParts) == 0 {
        return "Member", ""
    } else if len(nameParts) == 1 {
        return nameParts[0], ""
    } else {
        firstName = nameParts[0]
        lastName = strings.Join(nameParts[1:], " ")
        return firstName, lastName
    }
}

// Mutation returns MutationResolver implementation.
func (r *Resolver) Mutation() MutationResolver { return &mutationResolver{r} }

// Query returns QueryResolver implementation.
func (r *Resolver) Query() QueryResolver { return &queryResolver{r} }

type mutationResolver struct{ *Resolver }
type queryResolver struct{ *Resolver }