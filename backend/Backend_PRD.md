# NounHub Backend Product Requirements Document

*Product Managers: Marty Cagan & Julie Zhuo*

## Executive Summary

This document outlines the technical requirements and implementation details for the NounHub backend system. The backend will support a Twitter-like social platform with department-based forums for the National Open University community, built on AWS Serverless architecture.

## Technical Architecture

### Core Architecture
- **Approach**: Serverless, Monorepo
- **Framework**: SST (Serverless Stack)
- **Runtime**: Python 3.9
- **Deployment**: Single command deployment via `sst deploy`

### AWS Services

#### AWS Lambda
- 10-15 functions for CRUD operations
- Memory allocation: 256 MB per function
- Expected cold start: 200-300ms
- Package size target: <5 MB

#### API Gateway
- RESTful API endpoints
- Authentication integration with Cognito
- Rate limiting: 1000 requests per second

#### DynamoDB
- **Users Table**:
  - Partition Key: `id` (string)
  - Fields: `email` (string), `name` (string), `authProvider` (string), `emailVerified` (boolean), `createdAt` (timestamp), `lastLogin` (timestamp)
  - GSI: `email-index` for email lookups

#### Cognito
- Authentication methods:
  - Traditional email/password registration and login
  - Google Sign-In integration
  - Apple Sign-In integration
- Authentication flow:
  - Email verification after registration (confirmation code)
  - Forgot password request and verification
  - Password reset functionality
- JWT token-based authorization
- Multi-environment support (dev, staging, prod)

#### User Management
- User profile management:
  - Initial profile created at registration with name extracted from email
  - Profile completion after email verification
  - Separate API endpoints for profile operations
- Basic user profile management with core attributes

## API Endpoints

### Authentication
- `POST /auth/register` - Register new user (email/password)
- `POST /auth/register/google` - Register with Google
- `POST /auth/register/apple` - Register with Apple
- `POST /auth/login` - User login (email/password)
- `POST /auth/login/google` - Login with Google
- `POST /auth/login/apple` - Login with Apple
- `POST /auth/confirm` - Confirm signup with verification code
- `POST /auth/resend-code` - Resend verification code
- `POST /auth/forgot-password` - Request password reset
- `POST /auth/confirm-forgot-password` - Verify and reset password
- `POST /auth/logout` - User logout

### Users
- `GET /users/me` - Get current user profile
- `PUT /users/me` - Update current user profile
- `GET /users/{id}` - Get user by ID
- `GET /users` - List users (with filters)

## Data Models

### User
```json
{
  "id": "string",
  "email": "string",
  "name": "string",
  "authProvider": "string", // "email", "google", or "apple"
  "emailVerified": "boolean",
  "createdAt": "timestamp",
  "lastLogin": "timestamp"
}
```



## Project Structure

```
backend/
├── functions/
│   ├── auth/
│   │   ├── login.py
│   │   ├── login_google.py
│   │   ├── login_apple.py
│   │   ├── logout.py
│   │   ├── register.py
│   │   ├── register_google.py
│   │   ├── register_apple.py
│   │   ├── confirm.py
│   │   ├── resend_code.py
│   │   ├── forgot_password.py
│   │   └── confirm_forgot_password.py
│   ├── users/
│   │   ├── me.py
│   │   ├── update_me.py
│   │   ├── get.py
│   │   └── list.py
│   └── lib/
│       ├── db.py
│       ├── auth.py
│       └── response.py
├── models/
│   └── user.py
├── tests/
│   ├── test_auth.py
│   └── test_users.py
├── .gitignore
├── package.json
├── requirements.txt
├── sst.config.ts
└── README.md
```

## Performance Requirements

- API response time: <200ms (p95)
- Cold start latency: <300ms
- Database read capacity: 10 RCU (auto-scaling)
- Database write capacity: 5 WCU (auto-scaling)
- Maximum concurrent Lambda executions: 100

## Scalability Considerations

- DynamoDB auto-scaling for handling traffic spikes
- Lambda concurrency management
- API Gateway throttling to prevent abuse
- Efficient data access patterns to minimize costs

## Security Requirements

- JWT token validation for all authenticated endpoints
- IAM roles with least privilege principle
- Input validation on all API endpoints
- DynamoDB encryption at rest
- API Gateway request validation

## Monitoring and Logging

- CloudWatch Logs for Lambda functions
- CloudWatch Metrics for performance monitoring
- X-Ray for tracing requests
- Custom metrics for business KPIs

## Cost Projections

- Lambda: ~$3/month (20k MAU)
- DynamoDB: ~$2/month (20k MAU)
- API Gateway: ~$1/month (20k MAU)
- Cognito: ~$0/month (free tier)
- CloudWatch: ~$2/month
- Total: ~$8/month (20k MAU)

## Development Guidelines

- Follow PEP 8 style guide for Python code
- Write unit tests for all Lambda functions
- Document all API endpoints with OpenAPI
- Use type hints in Python code
- Implement error handling and logging in all functions

## Deployment Process

1. Install dependencies: `npm install`
2. Install Python requirements: `pip install -r requirements.txt`
3. Deploy to development: `sst deploy --stage dev`
4. Run tests: `pytest`
5. Deploy to staging: `sst deploy --stage staging`
6. Verify in staging environment
7. Deploy to production: `sst deploy --stage prod`

## Environment Configuration

### Multi-Environment Support
- **Development (dev)**: For active development and testing
  - Separate Cognito User Pool
  - Reduced rate limits
  - Debug logging enabled

- **Staging**: For pre-production verification
  - Mirrors production configuration
  - Used for integration testing and UAT
  - Isolated from production data

- **Production (prod)**: Live environment
  - Full rate limits applied
  - Enhanced security settings
  - Production monitoring and alerts

### Environment Variables
- Environment-specific variables managed through SST's `.env.[stage]` files
- Secrets managed through AWS Secrets Manager
- API endpoints configured per environment

---

*This document will evolve as the project progresses. Updates will be communicated to the development team.*