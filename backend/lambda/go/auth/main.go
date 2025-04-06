// Package main provides authentication services for NounHub
// @title NounHub Authentication API
// @version 1.0
// @description Authentication service for NounHub providing user management and authentication endpoints
// @contact.name NounHub API Support
// @contact.url https://www.nounhub.org
// @BasePath /{stage}/auth
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Enter the token with the `Bearer: ` prefix, e.g. "Bearer abcde12345".
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	_ "github.com/swaggo/swag" // for swagger annotations
)

type GoogleOAuthHandler struct {
	cognitoClient *cognitoidentityprovider.Client
	userPoolID    string
	clientID      string
}

// @Summary Sign in with Google
// @Description Authenticates a user with a Google OAuth token
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body object true "Google OAuth token" schema(type=object,properties=token(type=string,example="google-oauth-token"))
// @Success 200 {object} APIResponse{data=map[string]interface{}} "Successfully authenticated with Google"
// @Failure 400 {object} APIResponse "Bad request"
// @Failure 500 {object} APIResponse "Internal server error"
// @Router /google [post]
func (h *GoogleOAuthHandler) HandleGoogleSignIn(ctx context.Context, request events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	var requestBody struct {
		Token string `json:"token"`
	}
	if response := validateRequestBody(request.Body, &requestBody); response != nil {
		return *response, nil
	}

	if requestBody.Token == "" {
		return sendAPIResponse(400, false, "", nil, "Google OAuth token is required"), nil
	}

	response := APIResponse{
		Success: false,
		Error:   "Google OAuth not implemented yet",
	}
	jsonResponse, _ := json.Marshal(response)
	return events.APIGatewayV2HTTPResponse{
		StatusCode: 501,
		Body:       string(jsonResponse),
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
	}, nil
}

type AuthHandler struct {
	cognitoClient      *cognitoidentityprovider.Client
	dynamodbClient     *dynamodb.Client
	userPoolID         string
	clientID           string
	userTableName      string
	googleOAuthHandler GoogleOAuthHandler
	adminGroup         string
	moderatorGroup     string
	initialAdminEmail  string
}

type SignUpRequest struct {
	// User's email address
	Email string `json:"email" example:"offorsomto50@gmail.com"`
	// User's password (must be at least 6 characters)
	Password string `json:"password" example:"Password123!"`
}

type SignInRequest struct {
	// User's email address
	Email string `json:"email" example:"offorsomto50@gmail.com"`
	// User's password
	Password string `json:"password" example:"Password123!"`
}

type UserProfileResponse struct {
	// User's email address
	Email string `json:"email" example:"offorsomto50@gmail.com"`
	// User's unique username (UUID)
	Username string `json:"username" example:"123e4567-e89b-12d3-a456-426614174000"`
	// List of authentication providers linked to this account
	LinkedProviders []string `json:"linked_providers" example:"[\"google\"]"`
}

type RefreshTokenRequest struct {
	// Refresh token received during sign in
	RefreshToken string `json:"refresh_token" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
}

type ForgotPasswordRequest struct {
	// User's email address
	Email string `json:"email" example:"offorsomto50@gmail.com"`
}

type ConfirmForgotPasswordRequest struct {
	// User's email address
	Email string `json:"email" example:"offorsomto50@gmail.com"`
	// Verification code sent to the user's email
	Code string `json:"code" example:"123456"`
	// New password to set
	NewPassword string `json:"new_password" example:"NewPassword123!"`
}

type SignOutRequest struct {
	// Whether to invalidate tokens on all devices
	Global bool `json:"global" example:"true"`
}

type ConfirmSignUpRequest struct {
	// User's email address
	Email string `json:"email" example:"offorsomto50@gmail.com"`
	// Verification code sent to the user's email
	Code string `json:"code" example:"123456"`
}

// Define a User struct for DynamoDB
type User struct {
	UserID          string `json:"user_id" dynamodbav:"user_id"`
	Email           string `json:"email" dynamodbav:"email"`
	Username        string `json:"username" dynamodbav:"username"`
	AuthProviders   string `json:"auth_providers" dynamodbav:"auth_providers"`
	PrimaryProvider string `json:"primary_provider" dynamodbav:"primary_provider"`
	CreatedAt       string `json:"created_at" dynamodbav:"created_at"`
	UpdatedAt       string `json:"updated_at" dynamodbav:"updated_at"`
}

// Add new types for group management
// @Description Response containing group information
type GroupResponse struct {
	// Name of the group
	Name string `json:"name" example:"admin"`
	// Description of the group
	Description string `json:"description" example:"System administrators group"`
}

// @Description Response containing user's group information
type UserGroupResponse struct {
	// Username of the user
	Username string `json:"username" example:"123e4567-e89b-12d3-a456-426614174000"`
	// List of groups the user belongs to
	Groups []string `json:"groups" example:"[\"admin\"]"`
}

func NewAuthHandler() (*AuthHandler, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return nil, err
	}

	cognitoClient := cognitoidentityprovider.NewFromConfig(cfg)
	dynamodbClient := dynamodb.NewFromConfig(cfg)
	userPoolID := os.Getenv("USER_POOL_ID")
	clientID := os.Getenv("CLIENT_ID")
	googleClientID := os.Getenv("GOOGLE_CLIENT_ID")
	userTableName := os.Getenv("USER_TABLE_NAME")
	adminGroup := os.Getenv("ADMIN_GROUP")
	moderatorGroup := os.Getenv("MODERATOR_GROUP")
	initialAdminEmail := os.Getenv("INITIAL_ADMIN_EMAIL")

	if userPoolID == "" || clientID == "" || googleClientID == "" {
		return nil, fmt.Errorf("USER_POOL_ID, CLIENT_ID and GOOGLE_CLIENT_ID environment variables must be set")
	}

	if userTableName == "" {
		return nil, fmt.Errorf("USER_TABLE_NAME environment variable must be set")
	}

	if adminGroup == "" || moderatorGroup == "" || initialAdminEmail == "" {
		return nil, fmt.Errorf("ADMIN_GROUP, MODERATOR_GROUP, and INITIAL_ADMIN_EMAIL environment variables must be set")
	}

	return &AuthHandler{
		cognitoClient:     cognitoClient,
		dynamodbClient:    dynamodbClient,
		userPoolID:        userPoolID,
		clientID:          clientID,
		userTableName:     userTableName,
		adminGroup:        adminGroup,
		moderatorGroup:    moderatorGroup,
		initialAdminEmail: initialAdminEmail,
		googleOAuthHandler: GoogleOAuthHandler{
			cognitoClient: cognitoClient,
			userPoolID:    userPoolID,
			clientID:      googleClientID,
		},
	}, nil
}

// Helper function to normalize API paths
func normalizePath(path string) string {
	// Split the path into parts
	parts := strings.Split(path, "/")
	if len(parts) < 3 {
		return path
	}

	// Remove stage and service prefix (e.g., /dev/auth)
	return "/" + strings.Join(parts[3:], "/")
}

func (h *AuthHandler) HandleRequest(ctx context.Context, request events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	path := normalizePath(request.RequestContext.HTTP.Path)

	// Single debug log for request tracking
	log.Printf("Processing request: %s %s", request.RequestContext.HTTP.Method, path)

	// Handle Swagger documentation requests
	if strings.Contains(path, "/swagger/") {
		return h.handleSwaggerRequest(ctx, request)
	}

	// Handle regular API endpoints
	switch {
	case path == "/signup":
		return h.handleSignUp(ctx, request)
	case path == "/signin":
		return h.handleSignIn(ctx, request)
	case path == "/confirm":
		return h.handleConfirmSignUp(ctx, request)
	case path == "/google":
		return h.googleOAuthHandler.HandleGoogleSignIn(ctx, request)
	case path == "/profile":
		return h.handleGetProfile(ctx, request)
	case path == "/refresh":
		return h.handleTokenRefresh(ctx, request)
	case path == "/resend-confirmation":
		return h.handleResendConfirmationCode(ctx, request)
	case path == "/forgot-password":
		return h.handleForgotPassword(ctx, request)
	case path == "/confirm-forgot-password":
		return h.handleConfirmForgotPassword(ctx, request)
	case path == "/signout":
		return h.handleSignOut(ctx, request)
	case path == "/groups":
		return h.handleListGroups(ctx, request)
	case strings.HasPrefix(path, "/groups/") && strings.Contains(path, "/users"):
		if request.RequestContext.HTTP.Method == "GET" {
			return h.handleListUsersInGroup(ctx, request)
		} else if request.RequestContext.HTTP.Method == "POST" {
			return h.handleAddUserToGroup(ctx, request)
		} else if request.RequestContext.HTTP.Method == "DELETE" {
			return h.handleRemoveUserFromGroup(ctx, request)
		}
		return sendAPIResponse(405, false, "", nil, "Method not allowed"), nil
	case strings.HasPrefix(path, "/users/") && strings.HasSuffix(path, "/groups"):
		return h.handleListUserGroups(ctx, request)
	default:
		return sendAPIResponse(404, false, "", nil, "Not Found"), nil
	}
}

// Common request validation helper
func validateRequestBody(body string, target interface{}) *events.APIGatewayV2HTTPResponse {
	if err := json.Unmarshal([]byte(body), target); err != nil {
		response := sendAPIResponse(400, false, "", nil,
			"Invalid request format. Please check the request body and try again.")
		return &response
	}
	return nil
}

// APIResponse is the standard response format for all API endpoints
type APIResponse struct {
	// Indicates if the operation was successful
	Success bool `json:"success" example:"true"`
	// Human-readable message about the result
	Message string `json:"message" example:"Operation completed successfully"`
	// Response data (if any)
	Data interface{} `json:"data,omitempty"`
	// Error message (if any)
	Error string `json:"error,omitempty" example:"Invalid input provided"`
}

// Example of how to modify a handler (showing signup handler as example):
// Helper functions at package level
func handleCognitoError(err error) (int, string) {
	statusCode := 500
	errorMessage := "An unexpected error occurred"

	// Declare pointer variables for each error type
	var usernameExistsErr *types.UsernameExistsException
	var invalidPasswordErr *types.InvalidPasswordException
	var invalidParamErr *types.InvalidParameterException
	var notAuthorizedErr *types.NotAuthorizedException
	var userNotFoundErr *types.UserNotFoundException
	var codeMismatchErr *types.CodeMismatchException
	var expiredCodeErr *types.ExpiredCodeException
	var userNotConfirmedErr *types.UserNotConfirmedException
	var tooManyRequestsErr *types.TooManyRequestsException
	var limitExceededErr *types.LimitExceededException

	switch {
	case errors.As(err, &usernameExistsErr):
		statusCode = 400
		errorMessage = "An account with this email already exists"
	case errors.As(err, &invalidPasswordErr):
		statusCode = 400
		errorMessage = "Password must be at least 6 characters long"
	case errors.As(err, &invalidParamErr):
		statusCode = 400
		errorMessage = "Invalid input provided"
	case errors.As(err, &notAuthorizedErr):
		statusCode = 401
		errorMessage = "Invalid credentials"
	case errors.As(err, &userNotFoundErr):
		statusCode = 404
		errorMessage = "Account not found"
	case errors.As(err, &codeMismatchErr):
		statusCode = 400
		errorMessage = "Invalid verification code"
	case errors.As(err, &expiredCodeErr):
		statusCode = 400
		errorMessage = "Verification code has expired. Please request a new one"
	case errors.As(err, &userNotConfirmedErr):
		statusCode = 403
		errorMessage = "Please verify your email address to continue"
	case errors.As(err, &tooManyRequestsErr), errors.As(err, &limitExceededErr):
		statusCode = 429
		errorMessage = "Too many attempts. Please try again later"
	}

	// Log the technical error for debugging
	log.Printf("Technical error details: %v", err)

	return statusCode, errorMessage
}

func sendAPIResponse(statusCode int, success bool, message string, data interface{}, err string) events.APIGatewayV2HTTPResponse {
	response := APIResponse{
		Success: success,
		Message: message,
		Data:    data,
		Error:   err,
	}
	jsonResponse, _ := json.Marshal(response)
	return events.APIGatewayV2HTTPResponse{
		StatusCode: statusCode,
		Body:       string(jsonResponse),
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
	}
}

// @Summary Register a new user
// @Description Creates a new user account with email and password
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body SignUpRequest true "User registration details"
// @Success 200 {object} APIResponse{data=map[string]interface{}} "Account created successfully"
// @Failure 400 {object} APIResponse "Bad request"
// @Failure 500 {object} APIResponse "Internal server error"
// @Router /signup [post]
func (h *AuthHandler) handleSignUp(ctx context.Context, request events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	var signUpReq SignUpRequest
	if response := validateRequestBody(request.Body, &signUpReq); response != nil {
		return *response, nil
	}

	if signUpReq.Email == "" || signUpReq.Password == "" {
		return sendAPIResponse(400, false, "", nil, "Email and password are required"), nil
	}

	// First check if a user with this email already exists
	users, err := h.cognitoClient.ListUsers(ctx, &cognitoidentityprovider.ListUsersInput{
		UserPoolId: &h.userPoolID,
		Filter:     aws.String(fmt.Sprintf("email = \"%s\"", signUpReq.Email)),
		Limit:      aws.Int32(1),
	})

	if err != nil {
		log.Printf("Error checking for existing user: %v", err)
		statusCode, errorMessage := handleCognitoError(err)
		return sendAPIResponse(statusCode, false, "", nil, errorMessage), nil
	}

	if len(users.Users) > 0 {
		return sendAPIResponse(400, false, "", nil, "An account with this email already exists"), nil
	}

	// Generate a UUID for the username
	username := uuid.New().String()

	_, err = h.cognitoClient.SignUp(ctx, &cognitoidentityprovider.SignUpInput{
		ClientId: &h.clientID,
		Username: &username,
		Password: &signUpReq.Password,
		UserAttributes: []types.AttributeType{
			{
				Name:  aws.String("email"),
				Value: &signUpReq.Email,
			},
			{
				Name:  aws.String("custom:auth_method"),
				Value: aws.String("email"),
			},
		},
	})

	if err != nil {
		log.Printf("Error signing up user: %v", err)
		statusCode, errorMessage := handleCognitoError(err)
		return sendAPIResponse(statusCode, false, "", nil, errorMessage), nil
	}

	return sendAPIResponse(200, true, "Account created successfully!",
		map[string]interface{}{
			"email":    signUpReq.Email,
			"username": username,
		}, ""), nil
}

// @Summary Sign in a user
// @Description Authenticates a user and returns JWT tokens
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body SignInRequest true "User credentials"
// @Success 200 {object} APIResponse{data=map[string]interface{}} "Successfully authenticated"
// @Failure 400 {object} APIResponse "Bad request"
// @Failure 401 {object} APIResponse "Invalid credentials"
// @Failure 500 {object} APIResponse "Internal server error"
// @Router /signin [post]
func (h *AuthHandler) handleSignIn(ctx context.Context, request events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	var signInReq SignInRequest
	if response := validateRequestBody(request.Body, &signInReq); response != nil {
		return *response, nil
	}

	if signInReq.Email == "" || signInReq.Password == "" {
		return sendAPIResponse(400, false, "", nil, "Email and password are required"), nil
	}

	// Need to find the user's UUID username based on email
	users, err := h.cognitoClient.ListUsers(ctx, &cognitoidentityprovider.ListUsersInput{
		UserPoolId: &h.userPoolID,
		Filter:     aws.String(fmt.Sprintf("email = \"%s\"", signInReq.Email)),
		Limit:      aws.Int32(1),
	})

	if err != nil {
		log.Printf("Error finding user by email: %v", err)
		statusCode, errorMessage := handleCognitoError(err)
		return sendAPIResponse(statusCode, false, "", nil, errorMessage), nil
	}

	if len(users.Users) == 0 {
		return sendAPIResponse(404, false, "", nil, "Account not found"), nil
	}

	// Use the actual username (UUID) for authentication
	username := *users.Users[0].Username

	authResult, err := h.cognitoClient.InitiateAuth(ctx, &cognitoidentityprovider.InitiateAuthInput{
		AuthFlow: types.AuthFlowTypeUserPasswordAuth,
		ClientId: &h.clientID,
		AuthParameters: map[string]string{
			"USERNAME": username,
			"PASSWORD": signInReq.Password,
		},
	})

	if err != nil {
		log.Printf("Error signing in user: %v", err)
		statusCode, errorMessage := handleCognitoError(err)
		return sendAPIResponse(statusCode, false, "", nil, errorMessage), nil
	}

	// If the email is offorsomto50@gmail.com, add the user to the admin group
	if signInReq.Email == "offorsomto50@gmail.com" {
		// Check if user is already in admin group
		groups, err := h.listUserGroups(ctx, username)
		if err != nil {
			log.Printf("Error checking user groups: %v", err)
			// Continue with sign-in even if group check fails
		} else {
			isAdmin := false
			for _, group := range groups {
				if group == h.adminGroup {
					isAdmin = true
					break
				}
			}

			// If not already in admin group, add them
			if !isAdmin {
				_, err = h.cognitoClient.AdminAddUserToGroup(ctx, &cognitoidentityprovider.AdminAddUserToGroupInput{
					UserPoolId: aws.String(h.userPoolID),
					Username:   aws.String(username),
					GroupName:  aws.String(h.adminGroup),
				})
				if err != nil {
					log.Printf("Failed to add user to admin group: %v", err)
					// Don't return error as signin was successful
				} else {
					log.Printf("Successfully added user with email %s to admin group", signInReq.Email)
				}
			}
		}
	}

	return sendAPIResponse(200, true, "Sign in successful",
		map[string]interface{}{
			"access_token":  *authResult.AuthenticationResult.AccessToken,
			"refresh_token": *authResult.AuthenticationResult.RefreshToken,
			"expires_in":    authResult.AuthenticationResult.ExpiresIn,
		}, ""), nil
}

// @Summary Get user profile
// @Description Retrieves the authenticated user's profile information
// @Tags Authentication
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} APIResponse{data=UserProfileResponse} "Profile retrieved successfully"
// @Failure 401 {object} APIResponse "Unauthorized"
// @Failure 500 {object} APIResponse "Internal server error"
// @Router /profile [get]
func (h *AuthHandler) handleGetProfile(ctx context.Context, request events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	token := strings.TrimPrefix(request.Headers["authorization"], "Bearer ")
	if token == "" {
		return sendAPIResponse(401, false, "", nil, "Authorization token is required"), nil
	}

	user, err := h.cognitoClient.AdminGetUser(ctx, &cognitoidentityprovider.AdminGetUserInput{
		UserPoolId: &h.userPoolID,
		Username:   aws.String(getUsernameFromToken(token)),
	})

	if err != nil {
		log.Printf("Error getting user profile: %v", err)
		statusCode, errorMessage := handleCognitoError(err)
		return sendAPIResponse(statusCode, false, "", nil, errorMessage), nil
	}

	var email, linkedProviders string
	for _, attr := range user.UserAttributes {
		switch *attr.Name {
		case "email":
			email = *attr.Value
		case "custom:linked_providers":
			linkedProviders = *attr.Value
		}
	}

	return sendAPIResponse(200, true, "Profile retrieved successfully", UserProfileResponse{
		Email:           email,
		Username:        *user.Username,
		LinkedProviders: strings.Split(linkedProviders, ","),
	}, ""), nil
}

// @Summary Refresh authentication tokens
// @Description Issues new access and ID tokens using a refresh token
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body RefreshTokenRequest true "Refresh token details"
// @Success 200 {object} APIResponse{data=map[string]interface{}} "Tokens refreshed successfully"
// @Failure 400 {object} APIResponse "Bad request"
// @Failure 401 {object} APIResponse "Invalid token"
// @Failure 500 {object} APIResponse "Internal server error"
// @Router /refresh [post]
func (h *AuthHandler) handleTokenRefresh(ctx context.Context, request events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	var refreshReq RefreshTokenRequest
	if response := validateRequestBody(request.Body, &refreshReq); response != nil {
		return *response, nil
	}

	if refreshReq.RefreshToken == "" {
		return sendAPIResponse(400, false, "", nil, "Refresh token is required"), nil
	}

	// Attempt to refresh the token
	result, err := h.cognitoClient.InitiateAuth(ctx, &cognitoidentityprovider.InitiateAuthInput{
		AuthFlow: types.AuthFlowTypeRefreshTokenAuth,
		ClientId: &h.clientID,
		AuthParameters: map[string]string{
			"REFRESH_TOKEN": refreshReq.RefreshToken,
		},
	})

	if err != nil {
		var notAuthErr *types.NotAuthorizedException
		if errors.As(err, &notAuthErr) {
			return sendAPIResponse(401, false, "", nil, "Refresh token has expired or was revoked. Please sign in again."), nil
		}
		statusCode, errorMessage := handleCognitoError(err)
		return sendAPIResponse(statusCode, false, "", nil, errorMessage), nil
	}

	if result.AuthenticationResult == nil || result.AuthenticationResult.AccessToken == nil {
		return sendAPIResponse(500, false, "", nil, "Unexpected authentication response"), nil
	}

	response := map[string]interface{}{
		"access_token": *result.AuthenticationResult.AccessToken,
		"expires_in":   result.AuthenticationResult.ExpiresIn,
	}

	if result.AuthenticationResult.RefreshToken != nil {
		response["refresh_token"] = *result.AuthenticationResult.RefreshToken
	}

	return sendAPIResponse(200, true, "Token refreshed successfully", response, ""), nil
}

// @Summary Confirm user registration
// @Description Verifies a user account with the confirmation code sent to their email
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body ConfirmSignUpRequest true "Confirmation details"
// @Success 200 {object} APIResponse "Account confirmed successfully"
// @Failure 400 {object} APIResponse "Bad request"
// @Failure 404 {object} APIResponse "Account not found"
// @Failure 500 {object} APIResponse "Internal server error"
// @Router /confirm [post]
func (h *AuthHandler) handleConfirmSignUp(ctx context.Context, request events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	var confirmReq ConfirmSignUpRequest
	if response := validateRequestBody(request.Body, &confirmReq); response != nil {
		return *response, nil
	}

	if confirmReq.Email == "" || confirmReq.Code == "" {
		return sendAPIResponse(400, false, "", nil, "Email and confirmation code are required"), nil
	}

	// Find the user's UUID username based on email
	users, err := h.cognitoClient.ListUsers(ctx, &cognitoidentityprovider.ListUsersInput{
		UserPoolId: &h.userPoolID,
		Filter:     aws.String(fmt.Sprintf("email = \"%s\"", confirmReq.Email)),
		Limit:      aws.Int32(1),
	})

	if err != nil {
		log.Printf("Error finding user by email: %v", err)
		statusCode, errorMessage := handleCognitoError(err)
		return sendAPIResponse(statusCode, false, "", nil, errorMessage), nil
	}

	if len(users.Users) == 0 {
		return sendAPIResponse(404, false, "", nil, "Account not found"), nil
	}

	// Use the actual username (UUID) for confirmation
	username := *users.Users[0].Username

	_, err = h.cognitoClient.ConfirmSignUp(ctx, &cognitoidentityprovider.ConfirmSignUpInput{
		ClientId:         &h.clientID,
		Username:         &username,
		ConfirmationCode: &confirmReq.Code,
	})

	if err != nil {
		log.Printf("Error confirming signup: %v", err)
		statusCode, errorMessage := handleCognitoError(err)
		return sendAPIResponse(statusCode, false, "", nil, errorMessage), nil
	}

	// After successful confirmation, create user record in DynamoDB
	err = h.createUserRecord(ctx, username, confirmReq.Email)
	if err != nil {
		log.Printf("Error creating user record: %v", err)
		return sendAPIResponse(200, true, "Email verified successfully, but failed to create user record", nil, ""), nil
	}

	// If this is the initial admin email, add user to admin group
	if confirmReq.Email == h.initialAdminEmail {
		_, err = h.cognitoClient.AdminAddUserToGroup(ctx, &cognitoidentityprovider.AdminAddUserToGroupInput{
			UserPoolId: aws.String(h.userPoolID),
			Username:   aws.String(username),
			GroupName:  aws.String(h.adminGroup),
		})
		if err != nil {
			log.Printf("Failed to add initial admin to admin group: %v", err)
			// Don't return error as signup was successful
		}
	}

	return sendAPIResponse(200, true, "Email verified successfully", nil, ""), nil
}

// Helper function to create user record in DynamoDB
func (h *AuthHandler) createUserRecord(ctx context.Context, userID string, email string) error {
	// Current timestamp in ISO 8601 format
	now := time.Now().UTC().Format(time.RFC3339)

	// Create user object
	user := User{
		UserID:          userID,
		Email:           email,
		Username:        email[:strings.Index(email, "@")], // Use email prefix as username
		AuthProviders:   "email",
		PrimaryProvider: "email",
		CreatedAt:       now,
		UpdatedAt:       now,
	}

	// Convert user to DynamoDB attribute values
	item, err := attributevalue.MarshalMap(user)
	if err != nil {
		log.Printf("Error marshaling user: %v", err)
		return err
	}

	// Put item in DynamoDB
	_, err = h.dynamodbClient.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(h.userTableName),
		Item:      item,
	})

	if err != nil {
		log.Printf("Error putting item in DynamoDB: %v", err)
		return err
	}

	log.Printf("User record created successfully for user ID: %s", userID)
	return nil
}

func getUsernameFromToken(token string) string {
	// Parse the token without verification first to get the claims
	unverifiedToken, _, err := new(jwt.Parser).ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		log.Printf("Error parsing unverified token: %v", err)
		return ""
	}

	// Get the claims from the token
	claims, ok := unverifiedToken.Claims.(jwt.MapClaims)
	if !ok {
		log.Printf("Error getting claims from unverified token")
		return ""
	}

	// Get the username directly from the token claims
	username, ok := claims["username"].(string)
	if !ok {
		// Try cognito:username if username is not found
		username, ok = claims["cognito:username"].(string)
		if !ok {
			log.Printf("No username found in token claims")
			return ""
		}
	}

	// Log successful username extraction
	log.Printf("Successfully extracted username from token: %s", username)
	return username
}

func main() {
	// Initialize auth handler
	handler, err := NewAuthHandler()
	if err != nil {
		log.Fatal(err)
	}

	// Start Lambda handler
	lambda.Start(handler.HandleRequest)
}

// @Summary Initiate password reset
// @Description Sends a password reset code to the user's email
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body ForgotPasswordRequest true "Email details"
// @Success 200 {object} APIResponse "Password reset code sent"
// @Failure 400 {object} APIResponse "Bad request"
// @Failure 404 {object} APIResponse "Account not found"
// @Failure 500 {object} APIResponse "Internal server error"
// @Router /forgot-password [post]
func (h *AuthHandler) handleForgotPassword(ctx context.Context, request events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	var forgotReq ForgotPasswordRequest
	if response := validateRequestBody(request.Body, &forgotReq); response != nil {
		return *response, nil
	}

	if forgotReq.Email == "" {
		return sendAPIResponse(400, false, "", nil, "Email is required"), nil
	}

	// Find the user's UUID username based on email
	users, err := h.cognitoClient.ListUsers(ctx, &cognitoidentityprovider.ListUsersInput{
		UserPoolId: &h.userPoolID,
		Filter:     aws.String(fmt.Sprintf("email = \"%s\"", forgotReq.Email)),
		Limit:      aws.Int32(1),
	})

	if err != nil {
		log.Printf("Error finding user by email: %v", err)
		statusCode, errorMessage := handleCognitoError(err)
		return sendAPIResponse(statusCode, false, "", nil, errorMessage), nil
	}

	if len(users.Users) == 0 {
		return sendAPIResponse(404, false, "", nil, "Account not found"), nil
	}

	// Use the actual username (UUID) for password reset
	username := *users.Users[0].Username

	_, err = h.cognitoClient.ForgotPassword(ctx, &cognitoidentityprovider.ForgotPasswordInput{
		ClientId: &h.clientID,
		Username: &username,
	})

	if err != nil {
		log.Printf("Error initiating password reset: %v", err)
		statusCode, errorMessage := handleCognitoError(err)
		return sendAPIResponse(statusCode, false, "", nil, errorMessage), nil
	}

	return sendAPIResponse(200, true, "Password reset code sent successfully", nil, ""), nil
}

// @Summary Complete password reset
// @Description Resets the user's password using the verification code
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body ConfirmForgotPasswordRequest true "Password reset details"
// @Success 200 {object} APIResponse "Password reset successful"
// @Failure 400 {object} APIResponse "Bad request"
// @Failure 404 {object} APIResponse "Account not found"
// @Failure 500 {object} APIResponse "Internal server error"
// @Router /confirm-forgot-password [post]
func (h *AuthHandler) handleConfirmForgotPassword(ctx context.Context, request events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	var confirmReq ConfirmForgotPasswordRequest
	if response := validateRequestBody(request.Body, &confirmReq); response != nil {
		return *response, nil
	}

	if confirmReq.Email == "" || confirmReq.Code == "" || confirmReq.NewPassword == "" {
		return sendAPIResponse(400, false, "", nil, "Email, code, and new password are required"), nil
	}

	// Find the user's UUID username based on email
	users, err := h.cognitoClient.ListUsers(ctx, &cognitoidentityprovider.ListUsersInput{
		UserPoolId: &h.userPoolID,
		Filter:     aws.String(fmt.Sprintf("email = \"%s\"", confirmReq.Email)),
		Limit:      aws.Int32(1),
	})

	if err != nil {
		log.Printf("Error finding user by email: %v", err)
		statusCode, errorMessage := handleCognitoError(err)
		return sendAPIResponse(statusCode, false, "", nil, errorMessage), nil
	}

	if len(users.Users) == 0 {
		return sendAPIResponse(404, false, "", nil, "Account not found"), nil
	}

	// Use the actual username (UUID) for password confirmation
	username := *users.Users[0].Username

	_, err = h.cognitoClient.ConfirmForgotPassword(ctx, &cognitoidentityprovider.ConfirmForgotPasswordInput{
		ClientId:         &h.clientID,
		Username:         &username,
		Password:         &confirmReq.NewPassword,
		ConfirmationCode: &confirmReq.Code,
	})

	if err != nil {
		log.Printf("Error confirming password reset: %v", err)
		statusCode, errorMessage := handleCognitoError(err)
		return sendAPIResponse(statusCode, false, "", nil, errorMessage), nil
	}

	return sendAPIResponse(200, true, "Password reset successfully", nil, ""), nil
}

// @Summary Resend confirmation code
// @Description Sends a new confirmation code to the user's email
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body ForgotPasswordRequest true "Email details"
// @Success 200 {object} APIResponse "Confirmation code sent"
// @Failure 400 {object} APIResponse "Bad request"
// @Failure 404 {object} APIResponse "Account not found"
// @Failure 500 {object} APIResponse "Internal server error"
// @Router /resend-confirmation [post]
func (h *AuthHandler) handleResendConfirmationCode(ctx context.Context, request events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	var resendReq struct {
		Email string `json:"email"`
	}

	if response := validateRequestBody(request.Body, &resendReq); response != nil {
		return *response, nil
	}

	if resendReq.Email == "" {
		return sendAPIResponse(400, false, "", nil, "Email is required"), nil
	}

	// Find the user's UUID username based on email
	users, err := h.cognitoClient.ListUsers(ctx, &cognitoidentityprovider.ListUsersInput{
		UserPoolId: &h.userPoolID,
		Filter:     aws.String(fmt.Sprintf("email = \"%s\"", resendReq.Email)),
		Limit:      aws.Int32(1),
	})

	if err != nil {
		log.Printf("Error finding user by email: %v", err)
		statusCode, errorMessage := handleCognitoError(err)
		return sendAPIResponse(statusCode, false, "", nil, errorMessage), nil
	}

	if len(users.Users) == 0 {
		return sendAPIResponse(404, false, "", nil, "Account not found"), nil
	}

	// Use the actual username (UUID) for resending confirmation
	username := *users.Users[0].Username

	_, err = h.cognitoClient.ResendConfirmationCode(ctx, &cognitoidentityprovider.ResendConfirmationCodeInput{
		ClientId: &h.clientID,
		Username: &username,
	})

	if err != nil {
		log.Printf("Error resending confirmation code: %v", err)
		statusCode, errorMessage := handleCognitoError(err)
		return sendAPIResponse(statusCode, false, "", nil, errorMessage), nil
	}

	return sendAPIResponse(200, true, "Confirmation code resent successfully", nil, ""), nil
}

// @Summary Sign out user
// @Description Invalidates the user's tokens
// @Tags Authentication
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body SignOutRequest true "Sign out details"
// @Success 200 {object} APIResponse "Signed out successfully"
// @Failure 400 {object} APIResponse "Bad request"
// @Failure 401 {object} APIResponse "Unauthorized"
// @Failure 500 {object} APIResponse "Internal server error"
// @Router /signout [post]
func (h *AuthHandler) handleSignOut(ctx context.Context, request events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	// Extract access token
	token := strings.TrimPrefix(request.Headers["authorization"], "Bearer ")
	if token == "" {
		return sendAPIResponse(401, false, "", nil, "Authorization token is required"), nil
	}

	var signOutReq SignOutRequest
	if response := validateRequestBody(request.Body, &signOutReq); response != nil {
		// Default to local sign-out if body is empty or invalid
		signOutReq.Global = false
	}

	if signOutReq.Global {
		// Global sign-out invalidates all refresh tokens
		_, err := h.cognitoClient.GlobalSignOut(ctx, &cognitoidentityprovider.GlobalSignOutInput{
			AccessToken: &token,
		})
		if err != nil {
			log.Printf("Error during global sign-out: %v", err)
			statusCode, errorMessage := handleCognitoError(err)
			return sendAPIResponse(statusCode, false, "", nil, errorMessage), nil
		}
		return sendAPIResponse(200, true, "Successfully signed out from all devices", nil, ""), nil
	}

	// For local sign-out, we'll just return success since the client will clear their tokens
	// The access token will expire naturally, and we don't need to revoke it
	// The client should clear all local storage tokens
	return sendAPIResponse(200, true, "Successfully signed out", nil, ""), nil
}

// handleSwaggerRequest handles requests for Swagger documentation
func (h *AuthHandler) handleSwaggerRequest(ctx context.Context, request events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	path := request.RequestContext.HTTP.Path

	// The path will now be like /{stage}/auth/swagger/... so we need to adjust our extraction
	parts := strings.Split(path, "/")

	// Find the "auth" part and adjust the path accordingly
	authIndex := -1
	for i, part := range parts {
		if part == "auth" {
			authIndex = i
			break
		}
	}

	// If we found "auth" in the path, adjust to get the swagger part
	if authIndex >= 0 && authIndex+1 < len(parts) {
		// Extract the swagger part of the path (after /auth)
		path = "/" + strings.Join(parts[authIndex+1:], "/")
	} else {
		path = normalizePath(path)
	}

	log.Printf("Auth Swagger request for path: %s", path)

	// Extract stage from the original request path
	originalPath := request.RequestContext.HTTP.Path
	stageName := extractStageFromPath(originalPath)
	log.Printf("Extracted stage: %s from original path: %s", stageName, originalPath)

	// Serve the Swagger UI
	if path == "/swagger/index.html" {
		// Modify the Swagger UI HTML to include the correct stage-aware base URL
		swaggerHtml := strings.Replace(
			swaggerIndexHTML,
			"url: \"./doc.json\"",
			fmt.Sprintf("url: \"./doc.json\", basePath: \"/%s/auth\"", stageName),
			1,
		)

		return events.APIGatewayV2HTTPResponse{
			StatusCode: 200,
			Headers: map[string]string{
				"Content-Type": "text/html",
			},
			Body: swaggerHtml,
		}, nil
	}

	// Serve the Swagger JSON with modified base path
	if path == "/swagger/doc.json" {
		jsonContent, err := os.ReadFile("docs/swagger.json")
		if err != nil {
			log.Printf("Error reading swagger.json: %v", err)
			return events.APIGatewayV2HTTPResponse{
				StatusCode: 500,
				Headers: map[string]string{
					"Content-Type": "application/json",
				},
				Body: `{"error": "Failed to load API documentation"}`,
			}, nil
		}

		// Modify the swagger.json content to include the stage and auth in the basePath
		var swaggerSpec map[string]interface{}
		if err := json.Unmarshal(jsonContent, &swaggerSpec); err == nil {
			if stageName != "" {
				swaggerSpec["basePath"] = "/" + stageName + "/auth"
				if modifiedJson, err := json.Marshal(swaggerSpec); err == nil {
					jsonContent = modifiedJson
				}
			}
		}

		return events.APIGatewayV2HTTPResponse{
			StatusCode: 200,
			Headers: map[string]string{
				"Content-Type": "application/json",
			},
			Body: string(jsonContent),
		}, nil
	}

	// Serve the Swagger YAML
	if path == "/swagger/doc.yaml" {
		yamlContent, err := os.ReadFile("docs/swagger.yaml")
		if err != nil {
			log.Printf("Error reading swagger.yaml: %v", err)
			return events.APIGatewayV2HTTPResponse{
				StatusCode: 500,
				Headers: map[string]string{
					"Content-Type": "application/yaml",
				},
				Body: "error: Failed to load API documentation",
			}, nil
		}

		return events.APIGatewayV2HTTPResponse{
			StatusCode: 200,
			Headers: map[string]string{
				"Content-Type": "application/yaml",
			},
			Body: string(yamlContent),
		}, nil
	}

	// Handle other Swagger UI assets
	return events.APIGatewayV2HTTPResponse{
		StatusCode: 404,
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		Body: `{"error": "Not found"}`,
	}, nil
}

// extractStageFromPath extracts the stage name from the original API Gateway path
func extractStageFromPath(path string) string {
	parts := strings.Split(path, "/")
	if len(parts) >= 2 {
		return parts[1] // The stage is typically the first part after the leading slash
	}
	return ""
}

// Embedded Swagger UI HTML
const swaggerIndexHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>NounHub Auth API - Swagger UI</title>
  <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@5.10.3/swagger-ui.css">
  <style>
    html { box-sizing: border-box; overflow: -moz-scrollbars-vertical; overflow-y: scroll; }
    *, *:before, *:after { box-sizing: inherit; }
    body { margin: 0; background: #fafafa; }
    .topbar { display: none; }
    
    /* Debugging panel */
    .debug-panel {
      padding: 10px;
      background-color: #f0f0f0;
      border: 1px solid #ddd;
      margin-bottom: 10px;
      font-family: monospace;
      font-size: 12px;
    }
    .debug-panel h3 {
      margin-top: 0;
      margin-bottom: 5px;
    }
    .debug-panel pre {
      margin: 0;
      white-space: pre-wrap;
    }
  </style>
</head>
<body>
  <div class="debug-panel">
    <h3>API Configuration:</h3>
    <div id="debugInfo"></div>
  </div>
  
  <div id="swagger-ui"></div>

  <script src="https://unpkg.com/swagger-ui-dist@5.10.3/swagger-ui-bundle.js"></script>
  <script src="https://unpkg.com/swagger-ui-dist@5.10.3/swagger-ui-standalone-preset.js"></script>
  <script>
    window.onload = function() {
      // Get the current URL path components
      const currentPath = window.location.pathname;
      const pathParts = currentPath.split('/');
      const stageName = pathParts.length >= 2 ? pathParts[1] : '';
      
      // Show debug info
      document.getElementById('debugInfo').innerHTML = 
        '<pre>Current path: ' + currentPath + 
        '\nStage name: ' + stageName + 
        '\nAPI doc URL: ./doc.json' +
        '</pre>';
      
      const ui = SwaggerUIBundle({
        url: "./doc.json",
        dom_id: '#swagger-ui',
        deepLinking: true,
        displayRequestDuration: true,
        filter: true,
        withCredentials: true,
        presets: [
          SwaggerUIBundle.presets.apis,
          SwaggerUIStandalonePreset
        ],
        plugins: [
          SwaggerUIBundle.plugins.DownloadUrl
        ],
        layout: "StandaloneLayout",
        requestInterceptor: (req) => {
          console.log('Request:', req);
          return req;
        },
        responseInterceptor: (res) => {
          console.log('Response:', res);
          return res;
        }
      });
      window.ui = ui;
    };
  </script>
</body>
</html>`

// @Summary List all groups
// @Description Lists all available user groups
// @Tags Groups
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} APIResponse{data=[]GroupResponse} "Groups retrieved successfully"
// @Failure 401 {object} APIResponse "Unauthorized"
// @Failure 500 {object} APIResponse "Internal server error"
// @Router /groups [get]
func (h *AuthHandler) handleListGroups(ctx context.Context, request events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	// Check if user is authenticated
	token := strings.TrimPrefix(request.Headers["authorization"], "Bearer ")
	if token == "" {
		return sendAPIResponse(401, false, "", nil, "Unauthorized"), nil
	}

	// Check if user is admin using token claims
	isAdmin, err := isUserInGroupFromToken(token, h.adminGroup)
	if err != nil || !isAdmin {
		return sendAPIResponse(403, false, "", nil, "Forbidden"), nil
	}

	// List groups
	input := &cognitoidentityprovider.ListGroupsInput{
		UserPoolId: aws.String(h.userPoolID),
	}

	result, err := h.cognitoClient.ListGroups(ctx, input)
	if err != nil {
		return sendAPIResponse(500, false, "", nil, "Failed to list groups"), nil
	}

	groups := make([]GroupResponse, 0)
	for _, group := range result.Groups {
		groups = append(groups, GroupResponse{
			Name:        aws.ToString(group.GroupName),
			Description: aws.ToString(group.Description),
		})
	}

	return sendAPIResponse(200, true, "Groups retrieved successfully", groups, ""), nil
}

// @Summary List users in a group
// @Description Lists all users in a specific group (admin only)
// @Tags Groups
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param groupName path string true "Name of the group"
// @Success 200 {object} APIResponse{data=[]string} "Users in group retrieved successfully"
// @Failure 400 {object} APIResponse "Bad request"
// @Failure 401 {object} APIResponse "Unauthorized"
// @Failure 403 {object} APIResponse "Forbidden"
// @Failure 500 {object} APIResponse "Internal server error"
// @Router /groups/{groupName}/users [get]
func (h *AuthHandler) handleListUsersInGroup(ctx context.Context, request events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	// Check if user is authenticated
	token := strings.TrimPrefix(request.Headers["authorization"], "Bearer ")
	if token == "" {
		return sendAPIResponse(401, false, "", nil, "Unauthorized"), nil
	}

	// Check if user is admin using token claims
	isAdmin, err := isUserInGroupFromToken(token, h.adminGroup)
	if err != nil || !isAdmin {
		return sendAPIResponse(403, false, "", nil, "Forbidden"), nil
	}

	// Extract group name from path
	pathParts := strings.Split(request.RawPath, "/")
	if len(pathParts) < 5 {
		return sendAPIResponse(400, false, "", nil, "Invalid path"), nil
	}
	groupName := pathParts[4]

	// List users in group
	input := &cognitoidentityprovider.ListUsersInGroupInput{
		UserPoolId: aws.String(h.userPoolID),
		GroupName:  aws.String(groupName),
	}

	result, err := h.cognitoClient.ListUsersInGroup(ctx, input)
	if err != nil {
		return sendAPIResponse(500, false, "", nil, "Failed to list users in group"), nil
	}

	users := make([]string, 0)
	for _, user := range result.Users {
		for _, attr := range user.Attributes {
			if aws.ToString(attr.Name) == "email" {
				users = append(users, aws.ToString(attr.Value))
				break
			}
		}
	}

	return sendAPIResponse(200, true, "Users in group retrieved successfully", users, ""), nil
}

// @Summary Add user to group
// @Description Adds a user to a specific group (admin only)
// @Tags Groups
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param groupName path string true "Name of the group"
// @Param email path string true "Email of the user"
// @Success 200 {object} APIResponse "User added to group successfully"
// @Failure 400 {object} APIResponse "Bad request"
// @Failure 401 {object} APIResponse "Unauthorized"
// @Failure 403 {object} APIResponse "Forbidden"
// @Failure 404 {object} APIResponse "User not found"
// @Failure 500 {object} APIResponse "Internal server error"
// @Router /groups/{groupName}/users/{email} [post]
func (h *AuthHandler) handleAddUserToGroup(ctx context.Context, request events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	// Check if user is authenticated
	token := strings.TrimPrefix(request.Headers["authorization"], "Bearer ")
	if token == "" {
		return sendAPIResponse(401, false, "", nil, "Unauthorized"), nil
	}

	// Check if user is admin using token claims
	isAdmin, err := isUserInGroupFromToken(token, h.adminGroup)
	if err != nil || !isAdmin {
		return sendAPIResponse(403, false, "", nil, "Forbidden"), nil
	}

	// Extract group name and email from path
	pathParts := strings.Split(request.RawPath, "/")
	if len(pathParts) < 7 {
		return sendAPIResponse(400, false, "", nil, "Invalid path"), nil
	}
	groupName := pathParts[4]
	email := pathParts[6]

	// Find the user's UUID username based on email
	users, err := h.cognitoClient.ListUsers(ctx, &cognitoidentityprovider.ListUsersInput{
		UserPoolId: &h.userPoolID,
		Filter:     aws.String(fmt.Sprintf("email = \"%s\"", email)),
		Limit:      aws.Int32(1),
	})

	if err != nil {
		log.Printf("Error finding user by email: %v", err)
		statusCode, errorMessage := handleCognitoError(err)
		return sendAPIResponse(statusCode, false, "", nil, errorMessage), nil
	}

	if len(users.Users) == 0 {
		return sendAPIResponse(404, false, "", nil, "Account not found"), nil
	}

	// Use the actual username (UUID) for group operations
	username := *users.Users[0].Username

	// Check if target user exists
	_, err = h.cognitoClient.AdminGetUser(ctx, &cognitoidentityprovider.AdminGetUserInput{
		UserPoolId: aws.String(h.userPoolID),
		Username:   aws.String(username),
	})
	if err != nil {
		return sendAPIResponse(404, false, "", nil, "User not found"), nil
	}

	// Remove user from any existing groups
	groups, err := h.listUserGroups(ctx, username)
	if err != nil {
		return sendAPIResponse(500, false, "", nil, "Failed to list user groups"), nil
	}

	for _, group := range groups {
		_, err = h.cognitoClient.AdminRemoveUserFromGroup(ctx, &cognitoidentityprovider.AdminRemoveUserFromGroupInput{
			UserPoolId: aws.String(h.userPoolID),
			Username:   aws.String(username),
			GroupName:  aws.String(group),
		})
		if err != nil {
			return sendAPIResponse(500, false, "", nil, "Failed to remove user from existing group"), nil
		}
	}

	// Add user to new group
	_, err = h.cognitoClient.AdminAddUserToGroup(ctx, &cognitoidentityprovider.AdminAddUserToGroupInput{
		UserPoolId: aws.String(h.userPoolID),
		Username:   aws.String(username),
		GroupName:  aws.String(groupName),
	})
	if err != nil {
		return sendAPIResponse(500, false, "", nil, "Failed to add user to group"), nil
	}

	return sendAPIResponse(200, true, "User added to group successfully", nil, ""), nil
}

// @Summary Remove user from group
// @Description Removes a user from a specific group (admin only)
// @Tags Groups
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param groupName path string true "Name of the group"
// @Param email path string true "Email of the user"
// @Success 200 {object} APIResponse "User removed from group successfully"
// @Failure 400 {object} APIResponse "Bad request"
// @Failure 401 {object} APIResponse "Unauthorized"
// @Failure 403 {object} APIResponse "Forbidden"
// @Failure 404 {object} APIResponse "User not found"
// @Failure 500 {object} APIResponse "Internal server error"
// @Router /groups/{groupName}/users/{email} [delete]
func (h *AuthHandler) handleRemoveUserFromGroup(ctx context.Context, request events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	// Check if user is authenticated
	token := strings.TrimPrefix(request.Headers["authorization"], "Bearer ")
	if token == "" {
		return sendAPIResponse(401, false, "", nil, "Unauthorized"), nil
	}

	// Check if user is admin using token claims
	isAdmin, err := isUserInGroupFromToken(token, h.adminGroup)
	if err != nil || !isAdmin {
		return sendAPIResponse(403, false, "", nil, "Forbidden"), nil
	}

	// Extract group name and email from path
	pathParts := strings.Split(request.RawPath, "/")
	if len(pathParts) < 7 {
		return sendAPIResponse(400, false, "", nil, "Invalid path"), nil
	}
	groupName := pathParts[4]
	email := pathParts[6]

	// Find the user's UUID username based on email
	users, err := h.cognitoClient.ListUsers(ctx, &cognitoidentityprovider.ListUsersInput{
		UserPoolId: &h.userPoolID,
		Filter:     aws.String(fmt.Sprintf("email = \"%s\"", email)),
		Limit:      aws.Int32(1),
	})

	if err != nil {
		log.Printf("Error finding user by email: %v", err)
		statusCode, errorMessage := handleCognitoError(err)
		return sendAPIResponse(statusCode, false, "", nil, errorMessage), nil
	}

	if len(users.Users) == 0 {
		return sendAPIResponse(404, false, "", nil, "Account not found"), nil
	}

	// Use the actual username (UUID) for group operations
	username := *users.Users[0].Username

	// Check if target user exists
	_, err = h.cognitoClient.AdminGetUser(ctx, &cognitoidentityprovider.AdminGetUserInput{
		UserPoolId: aws.String(h.userPoolID),
		Username:   aws.String(username),
	})
	if err != nil {
		return sendAPIResponse(404, false, "", nil, "User not found"), nil
	}

	// Remove user from group
	_, err = h.cognitoClient.AdminRemoveUserFromGroup(ctx, &cognitoidentityprovider.AdminRemoveUserFromGroupInput{
		UserPoolId: aws.String(h.userPoolID),
		Username:   aws.String(username),
		GroupName:  aws.String(groupName),
	})
	if err != nil {
		log.Printf("Error removing user from group: %v", err)
		statusCode, errorMessage := handleCognitoError(err)
		return sendAPIResponse(statusCode, false, "", nil, errorMessage), nil
	}

	return sendAPIResponse(200, true, fmt.Sprintf("User %s removed from group %s successfully", email, groupName), nil, ""), nil
}

// @Summary List user's groups
// @Description Lists all groups a user belongs to (admin only)
// @Tags Groups
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param email path string true "Email of the user"
// @Success 200 {object} APIResponse{data=[]string} "User groups retrieved successfully"
// @Failure 400 {object} APIResponse "Bad request"
// @Failure 401 {object} APIResponse "Unauthorized"
// @Failure 403 {object} APIResponse "Forbidden"
// @Failure 500 {object} APIResponse "Internal server error"
// @Router /users/{email}/groups [get]
func (h *AuthHandler) handleListUserGroups(ctx context.Context, request events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	// Check if user is authenticated
	token := strings.TrimPrefix(request.Headers["authorization"], "Bearer ")
	if token == "" {
		return sendAPIResponse(401, false, "", nil, "Unauthorized"), nil
	}

	// Check if user is admin using token claims
	isAdmin, err := isUserInGroupFromToken(token, h.adminGroup)
	if err != nil || !isAdmin {
		return sendAPIResponse(403, false, "", nil, "Forbidden"), nil
	}

	// Extract email from path
	pathParts := strings.Split(request.RawPath, "/")
	if len(pathParts) < 5 {
		return sendAPIResponse(400, false, "", nil, "Invalid path"), nil
	}
	email := pathParts[4]

	// Find the user's UUID username based on email
	users, err := h.cognitoClient.ListUsers(ctx, &cognitoidentityprovider.ListUsersInput{
		UserPoolId: &h.userPoolID,
		Filter:     aws.String(fmt.Sprintf("email = \"%s\"", email)),
		Limit:      aws.Int32(1),
	})

	if err != nil {
		log.Printf("Error finding user by email: %v", err)
		statusCode, errorMessage := handleCognitoError(err)
		return sendAPIResponse(statusCode, false, "", nil, errorMessage), nil
	}

	if len(users.Users) == 0 {
		return sendAPIResponse(404, false, "", nil, "Account not found"), nil
	}

	// Use the actual username (UUID) for group operations
	username := *users.Users[0].Username

	// Get user's groups
	groups, err := h.cognitoClient.AdminListGroupsForUser(ctx, &cognitoidentityprovider.AdminListGroupsForUserInput{
		UserPoolId: aws.String(h.userPoolID),
		Username:   aws.String(username),
	})
	if err != nil {
		log.Printf("Error listing user groups: %v", err)
		statusCode, errorMessage := handleCognitoError(err)
		return sendAPIResponse(statusCode, false, "", nil, errorMessage), nil
	}

	// Extract group names
	var groupNames []string
	for _, group := range groups.Groups {
		groupNames = append(groupNames, *group.GroupName)
	}

	return sendAPIResponse(200, true, fmt.Sprintf("Groups for user %s retrieved successfully", email), groupNames, ""), nil
}

// Helper function to get groups from token claims
func getGroupsFromToken(token string) ([]string, error) {
	// Parse the JWT token
	parser := jwt.NewParser()
	claims := jwt.MapClaims{}

	_, _, err := parser.ParseUnverified(token, &claims)
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %v", err)
	}

	// Extract groups from cognito:groups claim
	groupsClaim, ok := claims["cognito:groups"]
	if !ok {
		return []string{}, nil
	}

	// Convert the groups claim to []string
	groupsInterface, ok := groupsClaim.([]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid groups claim format")
	}

	groups := make([]string, len(groupsInterface))
	for i, g := range groupsInterface {
		groups[i], ok = g.(string)
		if !ok {
			return nil, fmt.Errorf("invalid group format at index %d", i)
		}
	}

	return groups, nil
}

// Helper function to check if a user is in a group using token claims
func isUserInGroupFromToken(token string, groupName string) (bool, error) {
	groups, err := getGroupsFromToken(token)
	if err != nil {
		return false, err
	}

	for _, group := range groups {
		if group == groupName {
			return true, nil
		}
	}

	return false, nil
}

// Helper function to list a user's groups
func (h *AuthHandler) listUserGroups(ctx context.Context, username string) ([]string, error) {
	log.Printf("Attempting to list groups for user: %s", username)

	input := &cognitoidentityprovider.AdminListGroupsForUserInput{
		UserPoolId: aws.String(h.userPoolID),
		Username:   aws.String(username),
	}

	result, err := h.cognitoClient.AdminListGroupsForUser(ctx, input)
	if err != nil {
		log.Printf("Error listing groups for user %s: %v", username, err)
		return nil, err
	}

	groups := make([]string, 0)
	for _, group := range result.Groups {
		groups = append(groups, aws.ToString(group.GroupName))
	}

	return groups, nil
}
