package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
	"github.com/golang-jwt/jwt/v5"
)

type GoogleOAuthHandler struct {
	cognitoClient *cognitoidentityprovider.Client
	userPoolID    string
	clientID      string
}

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
	userPoolID         string
	clientID           string
	googleOAuthHandler GoogleOAuthHandler
}

type SignUpRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type SignInRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type UserProfileResponse struct {
	Email           string   `json:"email"`
	Username        string   `json:"username"`
	LinkedProviders []string `json:"linked_providers"`
}

type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type ForgotPasswordRequest struct {
	Email string `json:"email"`
}

type ConfirmForgotPasswordRequest struct {
	Email       string `json:"email"`
	Code        string `json:"code"`
	NewPassword string `json:"new_password"`
}

type SignOutRequest struct {
	Global bool `json:"global"`
}

func NewAuthHandler() (*AuthHandler, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return nil, err
	}

	cognitoClient := cognitoidentityprovider.NewFromConfig(cfg)
	userPoolID := os.Getenv("USER_POOL_ID")
	clientID := os.Getenv("CLIENT_ID")
	googleClientID := os.Getenv("GOOGLE_CLIENT_ID")

	if userPoolID == "" || clientID == "" || googleClientID == "" {
		return nil, fmt.Errorf("USER_POOL_ID, CLIENT_ID and GOOGLE_CLIENT_ID environment variables must be set")
	}

	return &AuthHandler{
		cognitoClient: cognitoClient,
		userPoolID:    userPoolID,
		clientID:      clientID,
		googleOAuthHandler: GoogleOAuthHandler{
			cognitoClient: cognitoClient,
			userPoolID:    userPoolID,
			clientID:      googleClientID,
		},
	}, nil
}

// Helper function to normalize API paths
func normalizePath(path string) string {
	if parts := strings.Split(path, "/"); len(parts) > 2 {
		return "/" + strings.Join(parts[2:], "/")
	}
	return path
}

func (h *AuthHandler) HandleRequest(ctx context.Context, request events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	path := normalizePath(request.RequestContext.HTTP.Path)

	// Single debug log for request tracking
	log.Printf("Processing request: %s %s", request.RequestContext.HTTP.Method, path)

	switch path {
	case "/auth/signup":
		return h.handleSignUp(ctx, request)
	case "/auth/signin":
		return h.handleSignIn(ctx, request)
	case "/auth/confirm":
		return h.handleConfirmSignUp(ctx, request)
	case "/auth/google":
		return h.googleOAuthHandler.HandleGoogleSignIn(ctx, request)
	case "/auth/profile":
		return h.handleGetProfile(ctx, request)
	case "/auth/refresh":
		return h.handleTokenRefresh(ctx, request)
	case "/auth/resend-confirmation":
		return h.handleResendConfirmationCode(ctx, request)
	case "/auth/forgot-password":
		return h.handleForgotPassword(ctx, request)
	case "/auth/confirm-forgot-password":
		return h.handleConfirmForgotPassword(ctx, request)
	case "/auth/signout":
		return h.handleSignOut(ctx, request)
	default:
		return sendAPIResponse(404, false, "", nil,
			fmt.Sprintf("The requested endpoint '%s' does not exist. Please check the documentation for available endpoints.", path)), nil
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

// Add this type at the top with other type definitions
type APIResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
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

// Then your handlers become much cleaner
func (h *AuthHandler) handleSignUp(ctx context.Context, request events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	var signUpReq SignUpRequest
	if response := validateRequestBody(request.Body, &signUpReq); response != nil {
		return *response, nil
	}

	if signUpReq.Email == "" || signUpReq.Password == "" {
		return sendAPIResponse(400, false, "", nil, "Email and password are required"), nil
	}

	_, err := h.cognitoClient.SignUp(ctx, &cognitoidentityprovider.SignUpInput{
		ClientId: &h.clientID,
		Username: &signUpReq.Email,
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
		map[string]interface{}{"email": signUpReq.Email}, ""), nil
}

// Example updates for handleSignIn:
func (h *AuthHandler) handleSignIn(ctx context.Context, request events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	var signInReq SignInRequest
	if response := validateRequestBody(request.Body, &signInReq); response != nil {
		return *response, nil
	}

	if signInReq.Email == "" || signInReq.Password == "" {
		return sendAPIResponse(400, false, "", nil, "Email and password are required"), nil
	}

	authResult, err := h.cognitoClient.InitiateAuth(ctx, &cognitoidentityprovider.InitiateAuthInput{
		AuthFlow: types.AuthFlowTypeUserPasswordAuth,
		ClientId: &h.clientID,
		AuthParameters: map[string]string{
			"USERNAME": signInReq.Email,
			"PASSWORD": signInReq.Password,
		},
	})

	if err != nil {
		log.Printf("Error signing in user: %v", err)
		statusCode, errorMessage := handleCognitoError(err)
		return sendAPIResponse(statusCode, false, "", nil, errorMessage), nil
	}

	return sendAPIResponse(200, true, "Sign in successful",
		map[string]interface{}{
			"access_token":  *authResult.AuthenticationResult.AccessToken,
			"refresh_token": *authResult.AuthenticationResult.RefreshToken,
			"expires_in":    authResult.AuthenticationResult.ExpiresIn,
		}, ""), nil
}

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

func (h *AuthHandler) handleConfirmSignUp(ctx context.Context, request events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	var confirmReq ConfirmSignUpRequest
	if response := validateRequestBody(request.Body, &confirmReq); response != nil {
		return *response, nil
	}

	if confirmReq.Email == "" || confirmReq.Code == "" {
		return sendAPIResponse(400, false, "", nil, "Email and confirmation code are required"), nil
	}

	_, err := h.cognitoClient.ConfirmSignUp(ctx, &cognitoidentityprovider.ConfirmSignUpInput{
		ClientId:         &h.clientID,
		Username:         &confirmReq.Email,
		ConfirmationCode: &confirmReq.Code,
	})

	if err != nil {
		log.Printf("Error confirming signup: %v", err)
		statusCode, errorMessage := handleCognitoError(err)
		return sendAPIResponse(statusCode, false, "", nil, errorMessage), nil
	}

	return sendAPIResponse(200, true, "Email verified successfully", nil, ""), nil
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
	handler, err := NewAuthHandler()
	if err != nil {
		log.Fatal(err)
	}
	lambda.Start(handler.HandleRequest)
}

// Add this after your other request types
type ConfirmSignUpRequest struct {
	Email string `json:"email"`
	Code  string `json:"code"`
}

// Add this new handler function
func (h *AuthHandler) handleForgotPassword(ctx context.Context, request events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	var forgotReq ForgotPasswordRequest
	if response := validateRequestBody(request.Body, &forgotReq); response != nil {
		return *response, nil
	}

	if forgotReq.Email == "" {
		return sendAPIResponse(400, false, "", nil, "Email is required"), nil
	}

	_, err := h.cognitoClient.ForgotPassword(ctx, &cognitoidentityprovider.ForgotPasswordInput{
		ClientId: &h.clientID,
		Username: &forgotReq.Email,
	})

	if err != nil {
		log.Printf("Error initiating password reset: %v", err)
		statusCode, errorMessage := handleCognitoError(err)
		return sendAPIResponse(statusCode, false, "", nil, errorMessage), nil
	}

	return sendAPIResponse(200, true, "Password reset code sent successfully", nil, ""), nil
}

func (h *AuthHandler) handleConfirmForgotPassword(ctx context.Context, request events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	var confirmReq ConfirmForgotPasswordRequest
	if response := validateRequestBody(request.Body, &confirmReq); response != nil {
		return *response, nil
	}

	if confirmReq.Email == "" || confirmReq.Code == "" || confirmReq.NewPassword == "" {
		return sendAPIResponse(400, false, "", nil, "Email, code, and new password are required"), nil
	}

	_, err := h.cognitoClient.ConfirmForgotPassword(ctx, &cognitoidentityprovider.ConfirmForgotPasswordInput{
		ClientId:         &h.clientID,
		Username:         &confirmReq.Email,
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

	_, err := h.cognitoClient.ResendConfirmationCode(ctx, &cognitoidentityprovider.ResendConfirmationCodeInput{
		ClientId: &h.clientID,
		Username: &resendReq.Email,
	})

	if err != nil {
		log.Printf("Error resending confirmation code: %v", err)
		statusCode, errorMessage := handleCognitoError(err)
		return sendAPIResponse(statusCode, false, "", nil, errorMessage), nil
	}

	return sendAPIResponse(200, true, "Confirmation code resent successfully", nil, ""), nil
}

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
