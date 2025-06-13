// services/user_client.go - Updated for Member Service Integration
package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"net/http"
	"time"
)

// Member represents the member from your friend's service
type Member struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	PhoneNumber string `json:"phone_number"`
	Borrowings  []Loan `json:"borrowings"`
}

// Loan represents borrowing records
type Loan struct {
	ID                  string `json:"id"`
	BookID              int    `json:"book_id"`
	TanggalPeminjaman   string `json:"tanggal_peminjaman"`
	TanggalJatuhTempo   string `json:"tanggal_jatuh_tempo"`
	TanggalPengembalian string `json:"tanggal_pengembalian"`
	Status              string `json:"status"`
	Denda               int    `json:"denda"`
}

// UserInfo represents combined user information (auth + member data)
type UserInfo struct {
	ID         uuid.UUID `json:"id"`          // Auth service UUID
	MemberID   string    `json:"member_id"`   // Member service ID
	Name       string    `json:"name"`        // From member service
	Phone      string    `json:"phone"`       // From member service
	Email      string    `json:"email"`       // From auth service only
	Role       string    `json:"role"`        // Default "MEMBER"
	IsActive   bool      `json:"is_active"`   // From auth service
	IsVerified bool      `json:"is_verified"` // From auth service
	CreatedAt  time.Time `json:"created_at"`  // From auth service
	Borrowings []Loan    `json:"borrowings"`  // From member service
}

// GraphQL request/response structures
type GraphQLRequest struct {
	Query     string                 `json:"query"`
	Variables map[string]interface{} `json:"variables"`
}

type GraphQLResponse struct {
	Data   json.RawMessage `json:"data"`
	Errors []GraphQLError  `json:"errors"`
}

type GraphQLError struct {
	Message string `json:"message"`
}

// GraphQL queries for member service
const (
	GetMemberQuery = `
        query GetMember($id: ID!) {
            member(id: $id) {
                id
                name
                phone_number
                borrowings {
                    id
                    book_id
                    tanggal_peminjaman
                    tanggal_jatuh_tempo
                    tanggal_pengembalian
                    status
                    denda
                }
            }
        }
    `

	GetAllMembersQuery = `
        query GetAllMembers {
            members {
                id
                name
                phone_number
            }
        }
    `

	RegisterMemberMutation = `
        mutation RegisterMember($name: String!, $phone: String!) {
            registerMember(name: $name, phone: $phone) {
                id
                name
                phone_number
            }
        }
    `

	UpdateMemberMutation = `
        mutation UpdateMember($id: ID!, $name: String, $phone: String) {
            updateMember(id: $id, name: $name, phone: $phone) {
                id
                name
                phone_number
            }
        }
    `
)

type UserClient struct {
	baseURL    string
	client     *http.Client
	timeout    time.Duration
	graphqlURL string
}

func NewUserClient(baseURL string) *UserClient {
	return &UserClient{
		baseURL:    baseURL,
		client:     &http.Client{Timeout: 30 * time.Second},
		timeout:    30 * time.Second,
		graphqlURL: baseURL + "/graphql",
	}
}

// GetMemberByID fetches member data from member service
func (c *UserClient) GetMemberByID(memberID string) (*Member, error) {
	variables := map[string]interface{}{
		"id": memberID,
	}

	response, err := c.executeGraphQL(GetMemberQuery, variables)
	if err != nil {
		return nil, fmt.Errorf("failed to get member: %w", err)
	}

	var result struct {
		Member *Member `json:"member"`
	}

	if err := json.Unmarshal(response.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse member data: %w", err)
	}

	if result.Member == nil {
		return nil, fmt.Errorf("member not found with ID: %s", memberID)
	}

	return result.Member, nil
}

// GetAllMembers fetches all members (useful for admin functions)
func (c *UserClient) GetAllMembers() ([]Member, error) {
	response, err := c.executeGraphQL(GetAllMembersQuery, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get members: %w", err)
	}

	var result struct {
		Members []Member `json:"members"`
	}

	if err := json.Unmarshal(response.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse members data: %w", err)
	}

	return result.Members, nil
}

// CreateMember creates a new member in the member service
func (c *UserClient) CreateMember(name, phone string) (*Member, error) {
	variables := map[string]interface{}{
		"name":  name,
		"phone": phone,
	}

	response, err := c.executeGraphQL(RegisterMemberMutation, variables)
	if err != nil {
		return nil, fmt.Errorf("failed to create member: %w", err)
	}

	var result struct {
		RegisterMember *Member `json:"registerMember"`
	}

	if err := json.Unmarshal(response.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse created member: %w", err)
	}

	if result.RegisterMember == nil {
		return nil, fmt.Errorf("failed to create member")
	}

	return result.RegisterMember, nil
}

// UpdateMember updates member information in the member service
func (c *UserClient) UpdateMember(memberID, name, phone string) (*Member, error) {
	variables := map[string]interface{}{
		"id": memberID,
	}

	if name != "" {
		variables["name"] = name
	}
	if phone != "" {
		variables["phone"] = phone
	}

	response, err := c.executeGraphQL(UpdateMemberMutation, variables)
	if err != nil {
		return nil, fmt.Errorf("failed to update member: %w", err)
	}

	var result struct {
		UpdateMember *Member `json:"updateMember"`
	}

	if err := json.Unmarshal(response.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse updated member: %w", err)
	}

	if result.UpdateMember == nil {
		return nil, fmt.Errorf("failed to update member")
	}

	return result.UpdateMember, nil
}

// CombineUserInfo combines auth data with member data
func (c *UserClient) CombineUserInfo(authID uuid.UUID, memberID, email string, isActive, isVerified bool, createdAt time.Time) (*UserInfo, error) {
	member, err := c.GetMemberByID(memberID)
	if err != nil {
		// If member service is down, return minimal info
		return &UserInfo{
			ID:         authID,
			MemberID:   memberID,
			Name:       "Member",
			Email:      email,
			Role:       "MEMBER",
			IsActive:   isActive,
			IsVerified: isVerified,
			CreatedAt:  createdAt,
			Borrowings: []Loan{},
		}, nil
	}

	return &UserInfo{
		ID:         authID,
		MemberID:   member.ID,
		Name:       member.Name,
		Phone:      member.PhoneNumber,
		Email:      email,
		Role:       "MEMBER",
		IsActive:   isActive,
		IsVerified: isVerified,
		CreatedAt:  createdAt,
		Borrowings: member.Borrowings,
	}, nil
}

// executeGraphQL executes GraphQL queries against the member service
func (c *UserClient) executeGraphQL(query string, variables map[string]interface{}) (*GraphQLResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	reqBody := GraphQLRequest{
		Query:     query,
		Variables: variables,
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.graphqlURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "auth-service/1.0")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var graphqlResp GraphQLResponse
	if err := json.NewDecoder(resp.Body).Decode(&graphqlResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if len(graphqlResp.Errors) > 0 {
		return nil, fmt.Errorf("GraphQL errors: %v", graphqlResp.Errors)
	}

	return &graphqlResp, nil
}

// HealthCheck checks if member service is available
func (c *UserClient) HealthCheck() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, "GET", c.baseURL+"/", nil)
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("member service health check failed: %d", resp.StatusCode)
	}
	return nil
}
