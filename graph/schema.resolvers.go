// graph/schema.resolvers.go - Updated with Member Integration
package graph

import (
	"auth-service/graph/model"
	"auth-service/services"
	"context"
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

// 🆕 PRIMARY: RegisterLibraryMember - Main registration method
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

// RegisterUserAuth - Keep for backward compatibility
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

// 🔄 UPDATED: Login with member data integration
func (r *mutationResolver) Login(ctx context.Context, input model.LoginInput) (*model.AuthResponse, error) {
	ip := GetIPFromContext(ctx)
	ua := GetUserAgentFromContext(ctx)

	req := services.LoginRequest{
		Email:    input.Email,
		Password: input.Password,
	}

	response, err := r.authService.Login(req, ip, ua)
	if err != nil {
		return nil, err
	}

	// Convert to GraphQL response with member data
	return convertToAuthResponse(response), nil
}

// 🔄 UPDATED: RefreshToken with member data integration
func (r *mutationResolver) RefreshToken(ctx context.Context, input model.RefreshTokenInput) (*model.AuthResponse, error) {
	ip := GetIPFromContext(ctx)
	ua := GetUserAgentFromContext(ctx)

	response, err := r.authService.RefreshToken(input.RefreshToken, ip, ua)
	if err != nil {
		return nil, err
	}

	return convertToAuthResponse(response), nil
}

// 🆕 NEW: GetUserByEmail - Get user info by email
func (r *queryResolver) GetUserByEmail(ctx context.Context, email string) (*model.User, error) {
	userInfo, err := r.authService.GetUserByEmail(email)
	if err != nil {
		return nil, err
	}

	return convertToGraphQLUser(userInfo), nil
}

// 🆕 NEW: GetUserWithBorrowings - Get user with current borrowings
func (r *queryResolver) GetUserWithBorrowings(ctx context.Context, email string) (*model.User, error) {
	userInfo, err := r.authService.GetUserWithBorrowings(email)
	if err != nil {
		return nil, err
	}

	return convertToGraphQLUser(userInfo), nil
}

// 🆕 NEW: UpdateMemberInfo - Update member information
func (r *mutationResolver) UpdateMemberInfo(ctx context.Context, input model.UpdateMemberInput) (*model.GenericResponse, error) {
	var name, phone string
	if input.Name != nil {
		name = *input.Name
	}
	if input.Phone != nil {
		phone = *input.Phone
	}

	err := r.authService.UpdateMemberInfo(input.Email, name, phone)
	if err != nil {
		return &model.GenericResponse{
			Success: false,
			Message: err.Error(),
		}, nil
	}

	return &model.GenericResponse{
		Success: true,
		Message: "Member information updated successfully",
	}, nil
}

// ValidateToken - Unchanged
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

// CheckPermission - Unchanged
func (r *queryResolver) CheckPermission(ctx context.Context, token string, resource string, action string) (*model.PermissionResponse, error) {
	claims, err := r.authService.ValidateToken(token)
	if err != nil {
		return nil, err
	}

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

// Placeholder implementations
func (r *mutationResolver) Logout(ctx context.Context, refreshToken string) (*model.GenericResponse, error) {
	return &model.GenericResponse{
		Success: true,
		Message: "Logged out successfully",
	}, nil
}

func (r *mutationResolver) ChangePassword(ctx context.Context, input model.ChangePasswordInput) (*model.GenericResponse, error) {
	return &model.GenericResponse{
		Success: true,
		Message: "Password changed successfully",
	}, nil
}

func (r *mutationResolver) RevokeSession(ctx context.Context, token string, sessionID string) (*model.GenericResponse, error) {
	return &model.GenericResponse{
		Success: true,
		Message: "Session revoked successfully",
	}, nil
}

func (r *queryResolver) GetUserSessions(ctx context.Context, token string) ([]*model.Session, error) {
	return []*model.Session{}, nil
}

// 🆕 HELPER: Convert service UserInfo to GraphQL User
func convertToGraphQLUser(userInfo *services.UserInfo) *model.User {
	firstName, lastName := splitName(userInfo.Name)

	// Convert loans
	var loans []*model.Loan
	for _, loan := range userInfo.Borrowings {
		loans = append(loans, &model.Loan{
			ID:                  loan.ID,
			BookID:              loan.BookID,
			TanggalPeminjaman:   &loan.TanggalPeminjaman,
			TanggalJatuhTempo:   &loan.TanggalJatuhTempo,
			TanggalPengembalian: &loan.TanggalPengembalian,
			Status:              &loan.Status,
			Denda:               &loan.Denda,
		})
	}

	var memberID *string
	if userInfo.MemberID != "" {
		memberID = &userInfo.MemberID
	}

	return &model.User{
		ID:         userInfo.ID.String(),
		MemberID:   memberID,
		Email:      userInfo.Email,
		FirstName:  firstName,
		LastName:   lastName,
		Phone:      &userInfo.Phone,
		Role:       model.UserRole(userInfo.Role),
		IsActive:   userInfo.IsActive,
		IsVerified: userInfo.IsVerified,
		CreatedAt:  userInfo.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		Borrowings: loans,
	}
}

// 🆕 HELPER: Convert service AuthResponse to GraphQL AuthResponse
func convertToAuthResponse(response *services.AuthResponse) *model.AuthResponse {
	return &model.AuthResponse{
		AccessToken: response.AccessToken,
		RefresToken: response.RefreshToken,
		ExpiresIn:   int(response.ExpiresIn),
		TokenType:   response.TokenType,
		User:        convertToGraphQLUser(response.User),
	}
}

// Helper function to split name into firstName and lastName
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

// Resolver implementations
func (r *Resolver) Mutation() MutationResolver { return &mutationResolver{r} }
func (r *Resolver) Query() QueryResolver       { return &queryResolver{r} }

type mutationResolver struct{ *Resolver }
type queryResolver struct{ *Resolver }
