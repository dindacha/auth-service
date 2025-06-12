// STEP-BY-STEP UPDATE for services/user_client.go
// Replace your entire file with this content

package services

import (
    "bytes"
    "context"
    "encoding/json"
    "fmt"
    "net/http"
    "strconv"
    "time"
    "github.com/google/uuid"
)

// STEP 1: Update UserInfo struct to match friend's service
type UserInfo struct {
    ID          uuid.UUID `json:"id"`           // We'll generate this
    MemberID    int       `json:"member_id"`    // Store their integer ID
    Name        string    `json:"name"`         // Single name (not first/last)
    PhoneNumber string    `json:"phone_number"` // Match their field name
    Email       string    `json:"email"`        // Only stored in auth service
    Role        string    `json:"role"`         // Default "MEMBER"
    IsActive    bool      `json:"is_active"`    // Default true
    IsVerified  bool      `json:"is_verified"`  // Default true
    CreatedAt   time.Time `json:"created_at"`   // Default now
}

// STEP 2: Add struct to match friend's service response
type MemberResponse struct {
    ID          int    `json:"id"`
    Name        string `json:"name"`
    PhoneNumber string `json:"phone_number"`
}

// STEP 3: Add GraphQL request/response structs
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

// STEP 4: Add GraphQL queries for friend's service
const (
    GetMemberByIDQuery = `
        query GetMember($id: ID!) {
            member(id: $id) {
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
)

// STEP 5: Update UserClient struct
type UserClient struct {
    baseURL    string
    client     *http.Client
    timeout    time.Duration
    graphqlURL string  // Add GraphQL endpoint
}

// STEP 6: Update NewUserClient function
func NewUserClient(baseURL string) *UserClient {
    return &UserClient{
        baseURL:    baseURL,
        client:     &http.Client{Timeout: 30 * time.Second},
        timeout:    30 * time.Second,
        graphqlURL: baseURL + "/graphql", // Friend's GraphQL endpoint
    }
}

// STEP 7: Update GetUserByEmail method
// Note: Since friend's service doesn't support email lookup,
// this method will not work directly. We'll handle this in auth service.
func (c *UserClient) GetUserByEmail(email string) (*UserInfo, error) {
    return nil, fmt.Errorf("email lookup not supported - use GetUserByMemberID instead")
}

// STEP 8: Replace GetUserByID with GetUserByMemberID
func (c *UserClient) GetUserByMemberID(memberID int) (*UserInfo, error) {
    variables := map[string]interface{}{
        "id": strconv.Itoa(memberID),
    }
    
    response, err := c.executeGraphQL(GetMemberByIDQuery, variables)
    if err != nil {
        return nil, fmt.Errorf("failed to get member: %w", err)
    }
    
    var result struct {
        Member *MemberResponse `json:"member"`
    }
    
    if err := json.Unmarshal(response.Data, &result); err != nil {
        return nil, fmt.Errorf("failed to parse member data: %w", err)
    }
    
    if result.Member == nil {
        return nil, fmt.Errorf("member not found with ID: %d", memberID)
    }
    
    return c.convertToUserInfo(result.Member, ""), nil
}

// STEP 9: Add GetUserByID method (for backward compatibility)
func (c *UserClient) GetUserByID(userID uuid.UUID) (*UserInfo, error) {
    // Since we can't convert UUID to friend's integer ID directly,
    // this method is not supported for the integration
    return nil, fmt.Errorf("GetUserByID not supported - use GetUserByMemberID instead")
}

// STEP 10: Replace NotifyUserAuth with CreateMember
func (c *UserClient) CreateMember(name, phone string) (*UserInfo, error) {
    variables := map[string]interface{}{
        "name":  name,
        "phone": phone,
    }
    
    response, err := c.executeGraphQL(RegisterMemberMutation, variables)
    if err != nil {
        return nil, fmt.Errorf("failed to create member: %w", err)
    }
    
    var result struct {
        RegisterMember *MemberResponse `json:"registerMember"`
    }
    
    if err := json.Unmarshal(response.Data, &result); err != nil {
        return nil, fmt.Errorf("failed to parse created member: %w", err)
    }
    
    if result.RegisterMember == nil {
        return nil, fmt.Errorf("failed to create member")
    }
    
    return c.convertToUserInfo(result.RegisterMember, ""), nil
}

// STEP 11: Add helper method to convert friend's data to UserInfo
func (c *UserClient) convertToUserInfo(member *MemberResponse, email string) *UserInfo {
    // Generate deterministic UUID from member ID
    userID := uuid.NewSHA1(uuid.NameSpaceOID, []byte(fmt.Sprintf("member_%d", member.ID)))
    
    return &UserInfo{
        ID:          userID,
        MemberID:    member.ID,
        Name:        member.Name,
        PhoneNumber: member.PhoneNumber,
        Email:       email,           // This will be stored only in auth service
        Role:        "MEMBER",        // Default role
        IsActive:    true,            // Default active
        IsVerified:  true,            // Default verified
        CreatedAt:   time.Now(),      // Default to now
    }
}

// STEP 12: Add GraphQL execution method
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

// STEP 13: Add health check method
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
        return fmt.Errorf("user service health check failed: %d", resp.StatusCode)
    }
    return nil
}

// STEP 14: Keep this for backward compatibility (but it won't be used)
type CreateUserAuthRequest struct {
    UserID   uuid.UUID `json:"user_id"`
    Email    string    `json:"email"`
    Password string    `json:"password"`
}

func (c *UserClient) NotifyUserAuth(req CreateUserAuthRequest) error {
    // This method is deprecated for the new integration
    return fmt.Errorf("NotifyUserAuth is deprecated - use CreateMember instead")
}