package services

import (
    "bytes"
    "encoding/json"
    "fmt"
    "net/http"
    "time"
    "github.com/google/uuid"
)

type UserClient struct {
    baseURL string
    client  *http.Client
}

type UserInfo struct {
    ID        uuid.UUID `json:"id"`
    Email     string    `json:"email"`
    FirstName string    `json:"first_name"`
    LastName  string    `json:"last_name"`
    Phone     string    `json:"phone"`
    Role      string    `json:"role"`
    IsActive  bool      `json:"is_active"`
    IsVerified bool     `json:"is_verified"`
    CreatedAt time.Time `json:"created_at"`
}

type CreateUserAuthRequest struct {
    UserID   uuid.UUID `json:"user_id"`
    Email    string    `json:"email"`
    Password string    `json:"password"`
}

func NewUserClient(baseURL string) *UserClient {
    return &UserClient{
        baseURL: baseURL,
        client:  &http.Client{Timeout: 30 * time.Second},
    }
}

func (c *UserClient) GetUserByEmail(email string) (*UserInfo, error) {
    req, err := http.NewRequest("GET", c.baseURL+"/api/v1/users/by-email/"+email, nil)
    if err != nil {
        return nil, err
    }

    resp, err := c.client.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    if resp.StatusCode == http.StatusNotFound {
        return nil, fmt.Errorf("user not found")
    }

    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("user service returned status %d", resp.StatusCode)
    }

    var userInfo UserInfo
    if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
        return nil, err
    }

    return &userInfo, nil
}

func (c *UserClient) GetUserByID(userID uuid.UUID) (*UserInfo, error) {
    req, err := http.NewRequest("GET", c.baseURL+"/api/v1/users/"+userID.String(), nil)
    if err != nil {
        return nil, err
    }

    resp, err := c.client.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    if resp.StatusCode == http.StatusNotFound {
        return nil, fmt.Errorf("user not found")
    }

    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("user service returned status %d", resp.StatusCode)
    }

    var userInfo UserInfo
    if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
        return nil, err
    }

    return &userInfo, nil
}

func (c *UserClient) NotifyUserAuth(req CreateUserAuthRequest) error {
    jsonData, err := json.Marshal(req)
    if err != nil {
        return err
    }

    httpReq, err := http.NewRequest("POST", c.baseURL+"/api/v1/internal/user-auth", bytes.NewBuffer(jsonData))
    if err != nil {
        return err
    }

    httpReq.Header.Set("Content-Type", "application/json")

    resp, err := c.client.Do(httpReq)
    if err != nil {
        return err
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
        return fmt.Errorf("user service returned status %d", resp.StatusCode)
    }

    return nil
}