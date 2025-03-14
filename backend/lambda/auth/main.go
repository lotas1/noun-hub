package main

import (
	"context"
	"encoding/json"
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
)

type GoogleOAuthHandler struct {
	cognitoClient *cognitoidentityprovider.Client
	userPoolID    string
	clientID      string
}

func (h *GoogleOAuthHandler) HandleGoogleSignIn(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	// TODO: Implement Google OAuth flow
	return events.APIGatewayProxyResponse{
		StatusCode: 501,
		Body:       "Google OAuth not implemented yet",
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

func (h *AuthHandler) HandleRequest(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	switch request.Path {
	case "/auth/signup":
		return h.handleSignUp(ctx, request)
	case "/auth/signin":
		return h.handleSignIn(ctx, request)
	case "/auth/confirm": // Add this case
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
	default:
		return events.APIGatewayProxyResponse{
			StatusCode: 404,
			Body:       "Not Found",
		}, nil
	}
}

func (h *AuthHandler) handleSignUp(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	var signUpReq SignUpRequest
	if err := json.Unmarshal([]byte(request.Body), &signUpReq); err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       "Invalid request body",
		}, nil
	}

	// Use email as username directly
	_, err := h.cognitoClient.SignUp(ctx, &cognitoidentityprovider.SignUpInput{
		ClientId: &h.clientID,
		Username: &signUpReq.Email, // Use email as username
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
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Body:       "Error signing up user",
		}, nil
	}

	return events.APIGatewayProxyResponse{
		StatusCode: 200,
		Body:       "User signed up successfully",
	}, nil
}

func (h *AuthHandler) handleSignIn(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	var signInReq SignInRequest
	if err := json.Unmarshal([]byte(request.Body), &signInReq); err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       "Invalid request body",
		}, nil
	}

	// Use email directly as username
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
		return events.APIGatewayProxyResponse{
			StatusCode: 401,
			Body:       "Invalid credentials",
		}, nil
	}

	response := map[string]interface{}{
		"access_token":  *authResult.AuthenticationResult.AccessToken,
		"refresh_token": *authResult.AuthenticationResult.RefreshToken,
		"expires_in":    authResult.AuthenticationResult.ExpiresIn,
	}

	responseJSON, _ := json.Marshal(response)
	return events.APIGatewayProxyResponse{
		StatusCode: 200,
		Body:       string(responseJSON),
	}, nil
}

func (h *AuthHandler) handleGetProfile(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	// Extract user from token
	token := strings.TrimPrefix(request.Headers["Authorization"], "Bearer ")
	if token == "" {
		return events.APIGatewayProxyResponse{
			StatusCode: 401,
			Body:       "Unauthorized",
		}, nil
	}

	// Get user info from Cognito
	user, err := h.cognitoClient.AdminGetUser(ctx, &cognitoidentityprovider.AdminGetUserInput{
		UserPoolId: &h.userPoolID,
		Username:   aws.String(getUsernameFromToken(token)),
	})
	if err != nil {
		log.Printf("Error getting user profile: %v", err)
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Body:       "Error retrieving user profile",
		}, nil
	}

	// Extract user attributes
	var email, linkedProviders string
	for _, attr := range user.UserAttributes {
		switch *attr.Name {
		case "email":
			email = *attr.Value
		case "custom:linked_providers":
			linkedProviders = *attr.Value
		}
	}

	response := UserProfileResponse{
		Email:           email,
		Username:        *user.Username,
		LinkedProviders: strings.Split(linkedProviders, ","),
	}

	responseJSON, _ := json.Marshal(response)
	return events.APIGatewayProxyResponse{
		StatusCode: 200,
		Body:       string(responseJSON),
	}, nil
}

func (h *AuthHandler) handleTokenRefresh(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	var refreshReq RefreshTokenRequest
	if err := json.Unmarshal([]byte(request.Body), &refreshReq); err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       "Invalid request body",
		}, nil
	}

	// Initiate auth refresh
	result, err := h.cognitoClient.InitiateAuth(ctx, &cognitoidentityprovider.InitiateAuthInput{
		AuthFlow: types.AuthFlowTypeRefreshToken,
		ClientId: &h.clientID,
		AuthParameters: map[string]string{
			"REFRESH_TOKEN": refreshReq.RefreshToken,
		},
	})

	if err != nil {
		log.Printf("Error refreshing token: %v", err)
		return events.APIGatewayProxyResponse{
			StatusCode: 401,
			Body:       "Invalid refresh token",
		}, nil
	}

	response := map[string]interface{}{
		"access_token": *result.AuthenticationResult.AccessToken,
		"expires_in":   result.AuthenticationResult.ExpiresIn,
	}

	responseJSON, _ := json.Marshal(response)
	return events.APIGatewayProxyResponse{
		StatusCode: 200,
		Body:       string(responseJSON),
	}, nil
}

func (h *AuthHandler) handleConfirmSignUp(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	var confirmReq ConfirmSignUpRequest
	if err := json.Unmarshal([]byte(request.Body), &confirmReq); err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       "Invalid request body",
		}, nil
	}

	// Use email directly as username
	_, err := h.cognitoClient.ConfirmSignUp(ctx, &cognitoidentityprovider.ConfirmSignUpInput{
		ClientId:         &h.clientID,
		Username:         &confirmReq.Email,
		ConfirmationCode: &confirmReq.Code,
	})

	if err != nil {
		log.Printf("Error confirming signup: %v", err)
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       "Invalid confirmation code",
		}, nil
	}

	return events.APIGatewayProxyResponse{
		StatusCode: 200,
		Body:       "Email confirmed successfully",
	}, nil
}

func getUsernameFromToken(token string) string {
	// In a real implementation, this would decode the JWT and extract the username
	// For now, we'll return a placeholder
	return "placeholder_username"
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
func (h *AuthHandler) handleForgotPassword(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	var forgotReq ForgotPasswordRequest
	if err := json.Unmarshal([]byte(request.Body), &forgotReq); err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       "Invalid request body",
		}, nil
	}

	_, err := h.cognitoClient.ForgotPassword(ctx, &cognitoidentityprovider.ForgotPasswordInput{
		ClientId: &h.clientID,
		Username: &forgotReq.Email,
	})

	if err != nil {
		log.Printf("Error initiating password reset: %v", err)
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Body:       "Error initiating password reset",
		}, nil
	}

	return events.APIGatewayProxyResponse{
		StatusCode: 200,
		Body:       "Password reset code sent successfully",
	}, nil
}

func (h *AuthHandler) handleConfirmForgotPassword(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	var confirmReq ConfirmForgotPasswordRequest
	if err := json.Unmarshal([]byte(request.Body), &confirmReq); err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       "Invalid request body",
		}, nil
	}

	_, err := h.cognitoClient.ConfirmForgotPassword(ctx, &cognitoidentityprovider.ConfirmForgotPasswordInput{
		ClientId:         &h.clientID,
		Username:         &confirmReq.Email,
		Password:         &confirmReq.NewPassword,
		ConfirmationCode: &confirmReq.Code,
	})

	if err != nil {
		log.Printf("Error confirming password reset: %v", err)
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       "Invalid confirmation code or password",
		}, nil
	}

	return events.APIGatewayProxyResponse{
		StatusCode: 200,
		Body:       "Password reset successfully",
	}, nil
}

func (h *AuthHandler) handleResendConfirmationCode(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	var resendReq struct {
		Email string `json:"email"`
	}

	if err := json.Unmarshal([]byte(request.Body), &resendReq); err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       "Invalid request body",
		}, nil
	}

	// Use email directly as username
	_, err := h.cognitoClient.ResendConfirmationCode(ctx, &cognitoidentityprovider.ResendConfirmationCodeInput{
		ClientId: &h.clientID,
		Username: &resendReq.Email,
	})

	if err != nil {
		log.Printf("Error resending confirmation code: %v", err)
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Body:       "Error resending confirmation code",
		}, nil
	}

	return events.APIGatewayProxyResponse{
		StatusCode: 200,
		Body:       "Confirmation code resent successfully",
	}, nil
}
