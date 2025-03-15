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

func (h *GoogleOAuthHandler) HandleGoogleSignIn(ctx context.Context, request events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
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

func (h *AuthHandler) HandleRequest(ctx context.Context, request events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	// Add debug logging
	log.Printf("Received request path: %s", request.RequestContext.HTTP.Path)
	log.Printf("Raw path: %s", request.RawPath)

	// Remove stage prefix from path
	path := request.RequestContext.HTTP.Path
	if parts := strings.Split(path, "/"); len(parts) > 2 {
		// Reconstruct the path without the stage name
		path = "/" + strings.Join(parts[2:], "/")
	}

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
	// In HandleRequest function, update the default case
	default:
		response := APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Not Found. Path received: %s", path),
		}
		jsonResponse, _ := json.Marshal(response)
		return events.APIGatewayV2HTTPResponse{
			StatusCode: 404,
			Body:       string(jsonResponse),
			Headers: map[string]string{
				"Content-Type": "application/json",
			},
		}, nil
	}
}

// Add this type at the top with other type definitions
type APIResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

// Example of how to modify a handler (showing signup handler as example):
func (h *AuthHandler) handleSignUp(ctx context.Context, request events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	var signUpReq SignUpRequest
	if err := json.Unmarshal([]byte(request.Body), &signUpReq); err != nil {
		response := APIResponse{
			Success: false,
			Error:   "Invalid request body",
		}
		jsonResponse, _ := json.Marshal(response)
		return events.APIGatewayV2HTTPResponse{
			StatusCode: 400,
			Body:       string(jsonResponse),
			Headers: map[string]string{
				"Content-Type": "application/json",
			},
		}, nil
	}

	// Use email as username directly
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
		response := APIResponse{
			Success: false,
			Error:   "Error signing up user",
		}
		jsonResponse, _ := json.Marshal(response)
		return events.APIGatewayV2HTTPResponse{
			StatusCode: 500,
			Body:       string(jsonResponse),
			Headers: map[string]string{
				"Content-Type": "application/json",
			},
		}, nil
	}

	// Update the success response to use APIResponse format
	response := APIResponse{
		Success: true,
		Message: "User signed up successfully",
		Data: map[string]interface{}{
			"email": signUpReq.Email,
		},
	}
	jsonResponse, _ := json.Marshal(response)
	return events.APIGatewayV2HTTPResponse{
		StatusCode: 200,
		Body:       string(jsonResponse),
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
	}, nil
}

// Example updates for handleSignIn:
func (h *AuthHandler) handleSignIn(ctx context.Context, request events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	var signInReq SignInRequest
	if err := json.Unmarshal([]byte(request.Body), &signInReq); err != nil {
		response := APIResponse{
			Success: false,
			Error:   "Invalid request body",
		}
		jsonResponse, _ := json.Marshal(response)
		return events.APIGatewayV2HTTPResponse{
			StatusCode: 400,
			Body:       string(jsonResponse),
			Headers: map[string]string{
				"Content-Type": "application/json",
			},
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
		response := APIResponse{
			Success: false,
			Error:   "Invalid credentials",
		}
		jsonResponse, _ := json.Marshal(response)
		return events.APIGatewayV2HTTPResponse{
			StatusCode: 401,
			Body:       string(jsonResponse),
			Headers: map[string]string{
				"Content-Type": "application/json",
			},
		}, nil
	}

	response := APIResponse{
		Success: true,
		Message: "Sign in successful",
		Data: map[string]interface{}{
			"access_token":  *authResult.AuthenticationResult.AccessToken,
			"refresh_token": *authResult.AuthenticationResult.RefreshToken,
			"expires_in":    authResult.AuthenticationResult.ExpiresIn,
		},
	}
	jsonResponse, _ := json.Marshal(response)
	return events.APIGatewayV2HTTPResponse{
		StatusCode: 200,
		Body:       string(jsonResponse),
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
	}, nil
}

func (h *AuthHandler) handleGetProfile(ctx context.Context, request events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	token := strings.TrimPrefix(request.Headers["authorization"], "Bearer ")
	if token == "" {
		response := APIResponse{
			Success: false,
			Error:   "Unauthorized",
		}
		jsonResponse, _ := json.Marshal(response)
		return events.APIGatewayV2HTTPResponse{
			StatusCode: 401,
			Body:       string(jsonResponse),
			Headers: map[string]string{
				"Content-Type": "application/json",
			},
		}, nil
	}

	// Get user info from Cognito
	user, err := h.cognitoClient.AdminGetUser(ctx, &cognitoidentityprovider.AdminGetUserInput{
		UserPoolId: &h.userPoolID,
		Username:   aws.String(getUsernameFromToken(token)),
	})
	if err != nil {
		log.Printf("Error getting user profile: %v", err)
		response := APIResponse{
			Success: false,
			Error:   "Error retrieving user profile",
		}
		jsonResponse, _ := json.Marshal(response)
		return events.APIGatewayV2HTTPResponse{
			StatusCode: 500,
			Body:       string(jsonResponse),
			Headers: map[string]string{
				"Content-Type": "application/json",
			},
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
	return events.APIGatewayV2HTTPResponse{
		StatusCode: 200,
		Body:       string(responseJSON),
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
	}, nil
}

func (h *AuthHandler) handleTokenRefresh(ctx context.Context, request events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	var refreshReq RefreshTokenRequest
	if err := json.Unmarshal([]byte(request.Body), &refreshReq); err != nil {
		response := APIResponse{
			Success: false,
			Error:   "Invalid request body",
		}
		jsonResponse, _ := json.Marshal(response)
		return events.APIGatewayV2HTTPResponse{
			StatusCode: 400,
			Body:       string(jsonResponse),
			Headers: map[string]string{
				"Content-Type": "application/json",
			},
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
		return events.APIGatewayV2HTTPResponse{
			StatusCode: 401,
			Body:       "Invalid refresh token",
		}, nil
	}

	response := map[string]interface{}{
		"access_token": *result.AuthenticationResult.AccessToken,
		"expires_in":   result.AuthenticationResult.ExpiresIn,
	}

	responseJSON, _ := json.Marshal(response)
	return events.APIGatewayV2HTTPResponse{
		StatusCode: 200,
		Body:       string(responseJSON),
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
	}, nil
}

func (h *AuthHandler) handleConfirmSignUp(ctx context.Context, request events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	var confirmReq ConfirmSignUpRequest
	if err := json.Unmarshal([]byte(request.Body), &confirmReq); err != nil {
		response := APIResponse{
			Success: false,
			Error:   "Invalid request body",
		}
		jsonResponse, _ := json.Marshal(response)
		return events.APIGatewayV2HTTPResponse{
			StatusCode: 400,
			Body:       string(jsonResponse),
			Headers: map[string]string{
				"Content-Type": "application/json",
			},
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
		response := APIResponse{
			Success: false,
			Error:   "Invalid confirmation code",
		}
		jsonResponse, _ := json.Marshal(response)
		return events.APIGatewayV2HTTPResponse{
			StatusCode: 400,
			Body:       string(jsonResponse),
			Headers: map[string]string{
				"Content-Type": "application/json",
			},
		}, nil
	}

	// In handleSignUp, update the success response:
	response := APIResponse{
		Success: true,
		Message: "User signed up successfully",
	}
	jsonResponse, _ := json.Marshal(response)
	return events.APIGatewayV2HTTPResponse{
		StatusCode: 200,
		Body:       string(jsonResponse),
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
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
func (h *AuthHandler) handleForgotPassword(ctx context.Context, request events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	var forgotReq ForgotPasswordRequest
	if err := json.Unmarshal([]byte(request.Body), &forgotReq); err != nil {
		return events.APIGatewayV2HTTPResponse{
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
		response := APIResponse{
			Success: false,
			Error:   "Error initiating password reset",
		}
		jsonResponse, _ := json.Marshal(response)
		return events.APIGatewayV2HTTPResponse{
			StatusCode: 500,
			Body:       string(jsonResponse),
			Headers: map[string]string{
				"Content-Type": "application/json",
			},
		}, nil
	}

	response := APIResponse{
		Success: true,
		Message: "Password reset code sent successfully",
	}
	jsonResponse, _ := json.Marshal(response)
	return events.APIGatewayV2HTTPResponse{
		StatusCode: 200,
		Body:       string(jsonResponse),
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
	}, nil
}

func (h *AuthHandler) handleConfirmForgotPassword(ctx context.Context, request events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	var confirmReq ConfirmForgotPasswordRequest
	if err := json.Unmarshal([]byte(request.Body), &confirmReq); err != nil {
		response := APIResponse{
			Success: false,
			Error:   "Invalid request body",
		}
		jsonResponse, _ := json.Marshal(response)
		return events.APIGatewayV2HTTPResponse{
			StatusCode: 400,
			Body:       string(jsonResponse),
			Headers: map[string]string{
				"Content-Type": "application/json",
			},
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
		response := APIResponse{
			Success: false,
			Error:   "Invalid confirmation code or password",
		}
		jsonResponse, _ := json.Marshal(response)
		return events.APIGatewayV2HTTPResponse{
			StatusCode: 400,
			Body:       string(jsonResponse),
			Headers: map[string]string{
				"Content-Type": "application/json",
			},
		}, nil
	}

	response := APIResponse{
		Success: true,
		Message: "Password reset successfully",
	}
	jsonResponse, _ := json.Marshal(response)
	return events.APIGatewayV2HTTPResponse{
		StatusCode: 200,
		Body:       string(jsonResponse),
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
	}, nil
}

func (h *AuthHandler) handleResendConfirmationCode(ctx context.Context, request events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	var resendReq struct {
		Email string `json:"email"`
	}

	if err := json.Unmarshal([]byte(request.Body), &resendReq); err != nil {
		response := APIResponse{
			Success: false,
			Error:   "Invalid request body",
		}
		jsonResponse, _ := json.Marshal(response)
		return events.APIGatewayV2HTTPResponse{
			StatusCode: 400,
			Body:       string(jsonResponse),
			Headers: map[string]string{
				"Content-Type": "application/json",
			},
		}, nil
	}

	// Use email directly as username
	_, err := h.cognitoClient.ResendConfirmationCode(ctx, &cognitoidentityprovider.ResendConfirmationCodeInput{
		ClientId: &h.clientID,
		Username: &resendReq.Email,
	})

	if err != nil {
		response := APIResponse{
			Success: false,
			Error:   "Error resending confirmation code",
		}
		jsonResponse, _ := json.Marshal(response)
		return events.APIGatewayV2HTTPResponse{
			StatusCode: 500,
			Body:       string(jsonResponse),
			Headers: map[string]string{
				"Content-Type": "application/json",
			},
		}, nil
	}

	response := APIResponse{
		Success: true,
		Message: "Confirmation code resent successfully",
	}
	jsonResponse, _ := json.Marshal(response)
	return events.APIGatewayV2HTTPResponse{
		StatusCode: 200,
		Body:       string(jsonResponse),
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
	}, nil
}
