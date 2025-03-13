# NounHub Authentication System Design

## Overview
This document outlines the authentication system design for NounHub, implementing secure user authentication using AWS Cognito, API Gateway, Lambda (Golang), and DynamoDB.

## Authentication Features

### 1. Sign Up (Traditional Email)

- User provides email and password
- Email verification required
- Auto-generate initial username from email (pre-@ portion)
- Create minimal user record in DynamoDB post-signup

### 2. Sign In
- Support both email and Google authentication
- Return JWT access token upon successful authentication
- Include refresh token mechanism

### 3. Confirm Signup
- Email verification flow
- Resend confirmation code capability
- Account activation post-confirmation

### 4. Password Reset
- Forgot password flow
- Reset code verification
- New password validation

### 5. Google Sign In
- OAuth2 flow integration
- Google profile data mapping
- Account linking implementation via custom Lambda triggers:
  - Check for existing account with email
  - Link Google authentication if email matches
  - Create new account if email doesn't exist
  - Synchronize profile data from Google
- Maintain single user record across auth methods

### 6. Account Management
- View linked authentication methods
- Add/remove authentication providers
- Primary email designation
- Profile data synchronization across methods

## Authentication Flow
1. User attempts sign in (email/password or Google)
2. System checks for existing account with email
3. If account exists:
   - For Google sign in: use custom Lambda trigger to link to existing account if not already linked
   - For email sign in: validate password
4. If no account exists:
   - Create new account
   - For Google sign in: populate profile with Google data
5. Generate and return JWT tokens

### 6. Account Management
- View linked authentication methods
- Add/remove authentication providers
- Primary email designation
- Profile data synchronization across methods

## AWS Resources

### Resource Naming Convention
```
${Project}-${Component}-${Resource}-${Environment}
```
Example: `nounhub-auth-userpool-dev`

### Required Resources
1. **Cognito User Pool**
   - Separate pools for each environment
   - Custom attributes for auth method tracking:
     - `auth_method`: String (Required)
       - Values: "email" | "google"
       - Mutable: false
       - Description: Tracks the initial signup method
     - `linked_providers`: String
       - Values: Delimited string (e.g., "email,google")
       - Mutable: true
       - Description: Tracks all authentication methods linked to account
   - Custom Lambda triggers for account linking logic

2. **API Gateway**
   - REST API with Cognito authorizer
   - Rate limiting and throttling

3. **Lambda Functions**
   - Authentication handlers (Golang)
   - User data management
   - Account linking operations
   - Custom triggers for Cognito events
   - Runtime Configuration:
     - Custom runtime using provided.al2023
     - Deployment package structure:
       ```
       lambda-package/
       ├── bootstrap           # Compiled Go binary
       └── runtime/            # Runtime dependencies
           └── provided.al2023 # Amazon Linux 2023 runtime
       ```
     - Build configuration:
       - GOOS=linux GOARCH=amd64
       - CGO_ENABLED=0
       - Statically linked binary
       - Binary named 'bootstrap'
     - Optimization settings:
       - Binary stripping enabled
       - Debug information removed
       - UPX compression (optional)

4. **DynamoDB**
   - User profile table
   - Auth provider mappings

## Data Schema

### DynamoDB User Table
```json
{
  "user_id": "string (primary key)",
  "email": "string",
  "username": "string",
  "auth_providers": "string",
  "primary_provider": "string",
  "created_at": "timestamp",
  "updated_at": "timestamp"
}
```

### Common Resource Tags
```json
{
  "Environment": "${pulumi.getStack()}",
  "Project": "${pulumi.Config().name}",
  "Component": "auth",
  "ManagedBy": "pulumi"
}
```

## API Specifications

### 1. Sign Up
```
POST /auth/signup
Body: {
  "email": "string",
  "password": "string"
}
```

### 2. Sign In
```
POST /auth/signin
Body: {
  "email": "string",
  "password": "string"
}
Response: {
  "access_token": "string",
  "refresh_token": "string",
  "expires_in": number
}
```

### 3. Link Account
```
POST /auth/link
Headers: {
  "Authorization": "Bearer <token>"
}
Body: {
  "provider": "string",
  "auth_code": "string"
}
Response: {
  "success": "boolean",
  "linked_email": "string"
}
```

### 3. Google Sign In
```
POST /auth/google
Body: {
  "token": "string" // Google OAuth token
}
Response: {
  "access_token": "string",
  "refresh_token": "string",
  "expires_in": number
}
```

### 4. Get User Info
```
GET /auth/user
Headers: {
  "Authorization": "Bearer {access_token}"
}
Response: {
  "user_id": "string",
  "email": "string",
  "username": "string",
  "auth_method": "string"
}
```

## Security Considerations

1. **Token Management**
   - Short-lived access tokens (1 hour)
   - Longer-lived refresh tokens (7 days)
   - Token rotation on refresh

2. **Password Policy**
   - Minimum 6 characters

3. **Rate Limiting**
   - Login attempts: 5 per minute
   - Password reset: 3 per hour
   - Account creation: 3 per day per IP

## Next Steps
1. Add monitoring and logging
2. Implement security testing (Ignore this for now)