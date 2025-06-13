# Auth Service - GraphQL API Documentation

A comprehensive authentication service with library member integration, built with Go, GraphQL, and PostgreSQL.

## 🚀 Features

- **JWT-based Authentication** with access and refresh tokens
- **Library Member Integration** - combines auth data with member service
- **Role-based Permissions** (Admin, Member, Customer, Merchant, Moderator)
- **GraphQL API** with playground interface

## 🛠️ Tech Stack

- **Backend**: Go 1.23+ with Gin framework
- **GraphQL**: gqlgen for schema-first development
- **Database**: PostgreSQL with GORM
- **Authentication**: JWT tokens with bcrypt password hashing
- **Integration**: RESTful communication with member service

## 📋 Prerequisites

- Go 1.23 or higher
- PostgreSQL 12+
- Member Service running (for full functionality)

## 🏃‍♂️ Quick Start

1. **Clone and setup**
```bash
git clone <repository-url>
cd auth-service
go mod download
```

2. **Environment Configuration**
```bash
cp .env.example .env
# Edit .env with your database credentials
```

3. **Run the service**
```bash
go run main.go
```

4. **Access GraphQL Playground**
```
http://localhost:8098/
```

## 🔧 Environment Variables

```env
PORT=8098
ENVIRONMENT=development
DATABASE_URL=postgres://postgres:password@localhost:5432/auth_db?sslmode=disable
JWT_SECRET=your-very-secret-jwt-key
JWT_EXPIRATION_HOURS=24
REFRESH_EXPIRATION_DAYS=7
USER_SERVICE_URL=http://localhost:5000

```

## 📊 GraphQL Schema Overview

### Core Types

```graphql
type User {
  id: String!
  memberId: String          # Link to member service
  email: String!
  firstName: String!        # Split from member service name
  lastName: String!         # Split from member service name
  phone: String
  role: UserRole!
  isActive: Boolean!
  isVerified: Boolean!
  createdAt: String!
  borrowings: [Loan!]!      # From member service
}

type AuthResponse {
  accessToken: String!
  refresToken: String!
  expiresIn: Int!
  tokenType: String!
  user: User!
}

enum UserRole {
  ADMIN
  CUSTOMER
  MEMBER                    # Primary role for library members
  MERCHANT
  MODERATOR
}
```

## 🔍 Query Examples

### 1. Health Check

**Query:**
```graphql
query HealthCheck {
  health {
    status
    service
    version
  }
}
```

**Response:**
```json
{
  "data": {
    "health": {
      "status": "healthy",
      "service": "auth",
      "version": "1.0.0"
    }
  }
}
```

### 2. Validate Token

**Query:**
```graphql
query ValidateToken($token: String!) {
  validateToken(token: $token) {
    valid
    userID
    email
    role
  }
}
```

**Variables:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Response:**
```json
{
  "data": {
    "validateToken": {
      "valid": true,
      "userID": "123e4567-e89b-12d3-a456-426614174000",
      "email": "member@library.com",
      "role": "MEMBER"
    }
  }
}
```

### 3. Check User Permissions

**Query:**
```graphql
query CheckPermission($token: String!, $resource: String!, $action: String!) {
  checkPermission(token: $token, resource: $resource, action: $action) {
    hasPermission
    userID
  }
}
```

**Variables:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "resource": "payment",
  "action": "create"
}
```

**Response:**
```json
{
  "data": {
    "checkPermission": {
      "hasPermission": true,
      "userID": "123e4567-e89b-12d3-a456-426614174000"
    }
  }
}
```

### 4. Get User by Email

**Query:**
```graphql
query GetUserByEmail($email: String!) {
  getUserByEmail(email: $email) {
    id
    memberId
    email
    firstName
    lastName
    phone
    role
    isActive
    isVerified
    createdAt
    borrowings {
      id
      bookId
      tanggalPeminjaman
      tanggalJatuhTempo
      status
      denda
    }
  }
}
```

**Variables:**
```json
{
  "email": "john.doe@library.com"
}
```

**Response:**
```json
{
  "data": {
    "getUserByEmail": {
      "id": "123e4567-e89b-12d3-a456-426614174000",
      "memberId": "MBR001",
      "email": "john.doe@library.com",
      "firstName": "John",
      "lastName": "Doe",
      "phone": "+1234567890",
      "role": "MEMBER",
      "isActive": true,
      "isVerified": true,
      "createdAt": "2024-01-15T10:30:00Z",
      "borrowings": [
        {
          "id": "LOAN001",
          "bookId": 123,
          "tanggalPeminjaman": "2024-01-15",
          "tanggalJatuhTempo": "2024-01-29",
          "status": "ACTIVE",
          "denda": 0
        }
      ]
    }
  }
}
```

### 5. Get User with Borrowings

**Query:**
```graphql
query GetUserWithBorrowings($email: String!) {
  getUserWithBorrowings(email: $email) {
    id
    email
    firstName
    lastName
    borrowings {
      id
      bookId
      tanggalPeminjaman
      tanggalJatuhTempo
      tanggalPengembalian
      status
      denda
    }
  }
}
```

### 6. Get User Sessions

**Query:**
```graphql
query GetUserSessions($token: String!) {
  getUserSessions(token: $token) {
    id
    tokenID
    isActive
    expiresAt
    createdAt
    lastSeen
    ipAddress
    userAgent
  }
}
```

## 🔐 Mutation Examples

### 1. Register Library Member (Primary Registration)

**Mutation:**
```graphql
mutation RegisterLibraryMember($input: RegisterLibraryMemberInput!) {
  registerLibraryMember(input: $input) {
    success
    message
  }
}
```

**Variables:**
```json
{
  "input": {
    "name": "John Doe",
    "phone": "+1234567890",
    "email": "john.doe@library.com",
    "password": "SecurePass123!"
  }
}
```

**Response:**
```json
{
  "data": {
    "registerLibraryMember": {
      "success": true,
      "message": "Library member registered successfully"
    }
  }
}
```

### 2. Login

**Mutation:**
```graphql
mutation Login($input: LoginInput!) {
  login(input: $input) {
    accessToken
    refresToken
    expiresIn
    tokenType
    user {
      id
      email
      firstName
      lastName
      role
      isActive
      borrowings {
        id
        bookId
        status
        denda
      }
    }
  }
}
```

**Variables:**
```json
{
  "input": {
    "email": "john.doe@library.com",
    "password": "SecurePass123!"
  }
}
```

**Response:**
```json
{
  "data": {
    "login": {
      "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
      "refresToken": "550e8400-e29b-41d4-a716-446655440000",
      "expiresIn": 1643723400,
      "tokenType": "Bearer",
      "user": {
        "id": "123e4567-e89b-12d3-a456-426614174000",
        "email": "john.doe@library.com",
        "firstName": "John",
        "lastName": "Doe",
        "role": "MEMBER",
        "isActive": true,
        "borrowings": []
      }
    }
  }
}
```

### 3. Refresh Token

**Mutation:**
```graphql
mutation RefreshToken($input: RefreshTokenInput!) {
  refreshToken(input: $input) {
    accessToken
    refresToken
    expiresIn
    tokenType
    user {
      id
      email
      role
    }
  }
}
```

**Variables:**
```json
{
  "input": {
    "refreshToken": "550e8400-e29b-41d4-a716-446655440000"
  }
}
```

### 4. Update Member Information

**Mutation:**
```graphql
mutation UpdateMemberInfo($input: UpdateMemberInput!) {
  updateMemberInfo(input: $input) {
    success
    message
  }
}
```

**Variables:**
```json
{
  "input": {
    "email": "john.doe@library.com",
    "name": "John Smith",
    "phone": "+1987654321"
  }
}
```

### 5. Change Password

**Mutation:**
```graphql
mutation ChangePassword($input: ChangePasswordInput!) {
  changePassword(input: $input) {
    success
    message
  }
}
```

**Variables:**
```json
{
  "input": {
    "userID": "123e4567-e89b-12d3-a456-426614174000",
    "oldPassword": "OldPass123!",
    "newPassword": "NewSecurePass456!"
  }
}
```

### 6. Logout

**Mutation:**
```graphql
mutation Logout($refreshToken: String!) {
  logout(refreshToken: $refreshToken) {
    success
    message
  }
}
```

**Variables:**
```json
{
  "refreshToken": "550e8400-e29b-41d4-a716-446655440000"
}
```

### 7. Revoke Session

**Mutation:**
```graphql
mutation RevokeSession($token: String!, $sessionID: String!) {
  revokeSession(token: $token, sessionID: $sessionID) {
    success
    message
  }
}
```

**Variables:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "sessionID": "session-uuid-here"
}
```

## 🔒 Authentication Flow

### Complete Registration & Login Flow

```graphql
# 1. Register a new library member
mutation {
  registerLibraryMember(input: {
    name: "Alice Johnson"
    phone: "+1555123456"
    email: "alice@library.com"
    password: "SecurePass123!"
  }) {
    success
    message
  }
}

# 2. Login to get tokens
mutation {
  login(input: {
    email: "alice@library.com"
    password: "SecurePass123!"
  }) {
    accessToken
    refresToken
    user {
      id
      email
      firstName
      lastName
      role
    }
  }
}

# 3. Use access token for authenticated requests
query {
  getUserSessions(token: "your-access-token-here") {
    id
    isActive
    ipAddress
    lastSeen
  }
}

# 4. Refresh token when needed
mutation {
  refreshToken(input: {
    refreshToken: "your-refresh-token-here"
  }) {
    accessToken
    refresToken
  }
}
```

## 🛡️ Security Features

### Rate Limiting
- **Login attempts**: 5 attempts per 15 minutes per email
- **Token requests**: 10 requests per minute
- **Account locking**: After 5 failed attempts (15-minute lock)

### Password Requirements
- Minimum 8 characters
- Must contain special characters (configurable)
- Bcrypt hashing with cost factor 12

### Session Management
- JWT tokens with configurable expiration
- Refresh token rotation
- Session tracking with IP and User-Agent
- Maximum active sessions per user

## 🔍 Error Handling

### Common Error Responses

```json
{
  "errors": [
    {
      "message": "invalid credentials",
      "path": ["login"]
    }
  ],
  "data": null
}
```

### Error Types
- `invalid credentials` - Wrong email/password
- `account is temporarily locked` - Too many failed attempts
- `account is deactivated` - Account disabled
- `invalid or expired refresh token` - Token issues
- `email already registered` - Duplicate registration
- `user not found` - User doesn't exist

## 🚀 Development

### Generate GraphQL Code
```bash
go run github.com/99designs/gqlgen generate
```

### Run with Hot Reload
```bash
go install github.com/cosmtrek/air@latest
air
```

### Database Migration
```bash
# Migrations are handled automatically via GORM AutoMigrate
# Check database/database.go for schema definitions
```

## 📊 Monitoring & Logging

### Audit Events Tracked
- User login/logout
- Password changes
- Token refresh
- Permission grants/revokes
- Account locks/unlocks

### Health Endpoints
- GraphQL: `http://localhost:8098/health`
- Playground: `http://localhost:8098/`

## 🔗 Integration

### Member Service Integration
The auth service integrates with a separate member service to provide combined user data:

- **Auth Service**: Handles authentication, passwords, sessions
- **Member Service**: Manages member profiles, borrowing records
- **Integration**: GraphQL communication between services

### API Endpoints
- **GraphQL**: `POST /graphql`
- **Playground**: `GET /`
- **Health**: `GET /health`

## 📚 Additional Resources

- [GraphQL Playground](http://localhost:8098/) - Interactive API explorer
- [GORM Documentation](https://gorm.io/docs/) - Database ORM
- [gqlgen Documentation](https://gqlgen.com/) - GraphQL code generation

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.