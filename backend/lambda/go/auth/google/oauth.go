package google

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
	"github.com/google/uuid"
)

type GoogleOAuthHandler struct {
	cognitoClient *cognitoidentityprovider.Client
	userPoolID    string
	clientID      string
}

type GoogleUserInfo struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Picture       string `json:"picture"`
	Locale        string `json:"locale"`
}

func NewGoogleOAuthHandler(cognitoClient *cognitoidentityprovider.Client, userPoolID, clientID string) *GoogleOAuthHandler {
	return &GoogleOAuthHandler{
		cognitoClient: cognitoClient,
		userPoolID:    userPoolID,
		clientID:      clientID,
	}
}

func (h *GoogleOAuthHandler) HandleGoogleSignIn(ctx context.Context, request events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	// Extract Google OAuth token from request
	var requestBody struct {
		Token string `json:"token"`
	}

	if err := json.Unmarshal([]byte(request.Body), &requestBody); err != nil {
		return events.APIGatewayV2HTTPResponse{
			StatusCode: 400,
			Body:       "Invalid request body",
		}, nil
	}

	// Get user info from Google
	userInfo, err := h.getGoogleUserInfo(requestBody.Token)
	if err != nil {
		return events.APIGatewayV2HTTPResponse{
			StatusCode: 401,
			Body:       "Invalid Google token",
		}, nil
	}

	// Check if user exists
	existingUser, err := h.findUserByEmail(ctx, userInfo.Email)
	if err != nil && !errors.Is(err, &types.UserNotFoundException{}) {
		return events.APIGatewayV2HTTPResponse{
			StatusCode: 500,
			Body:       "Error checking user existence",
		}, nil
	}

	var username string
	if existingUser != nil {
		// Link Google auth to existing account
		username = *existingUser.Username
		err = h.linkGoogleAuth(ctx, existingUser.Username, userInfo)
		if err != nil {
			return events.APIGatewayV2HTTPResponse{
				StatusCode: 500,
				Body:       "Error linking Google account",
			}, nil
		}
	} else {
		// Create new user with UUID username
		username, err = h.createGoogleUser(ctx, userInfo)
		if err != nil {
			return events.APIGatewayV2HTTPResponse{
				StatusCode: 500,
				Body:       "Error creating user",
			}, nil
		}
	}

	// Initiate auth session
	result, err := h.cognitoClient.InitiateAuth(ctx, &cognitoidentityprovider.InitiateAuthInput{
		AuthFlow: types.AuthFlowTypeCustomAuth,
		ClientId: &h.clientID,
		AuthParameters: map[string]string{
			"USERNAME": username,
			"PROVIDER": "Google",
		},
	})

	if err != nil {
		return events.APIGatewayV2HTTPResponse{
			StatusCode: 500,
			Body:       "Error initiating auth session",
		}, nil
	}

	response := map[string]interface{}{
		"access_token":  *result.AuthenticationResult.AccessToken,
		"refresh_token": *result.AuthenticationResult.RefreshToken,
		"expires_in":    result.AuthenticationResult.ExpiresIn,
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

func (h *GoogleOAuthHandler) getGoogleUserInfo(token string) (*GoogleUserInfo, error) {
	resp, err := http.Get(fmt.Sprintf("https://www.googleapis.com/oauth2/v2/userinfo?access_token=%s", token))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var userInfo GoogleUserInfo
	if err := json.Unmarshal(body, &userInfo); err != nil {
		return nil, err
	}

	return &userInfo, nil
}

func (h *GoogleOAuthHandler) findUserByEmail(ctx context.Context, email string) (*types.UserType, error) {
	result, err := h.cognitoClient.ListUsers(ctx, &cognitoidentityprovider.ListUsersInput{
		UserPoolId: &h.userPoolID,
		Filter:     aws.String(fmt.Sprintf("email = \"%s\"", email)),
	})

	if err != nil {
		return nil, err
	}

	if len(result.Users) == 0 {
		return nil, &types.UserNotFoundException{}
	}

	return &result.Users[0], nil
}

func (h *GoogleOAuthHandler) linkGoogleAuth(ctx context.Context, username *string, userInfo *GoogleUserInfo) error {
	_, err := h.cognitoClient.AdminUpdateUserAttributes(ctx, &cognitoidentityprovider.AdminUpdateUserAttributesInput{
		UserPoolId: &h.userPoolID,
		Username:   username,
		UserAttributes: []types.AttributeType{
			{
				Name:  aws.String("custom:linked_providers"),
				Value: aws.String("email,google"),
			},
		},
	})

	return err
}

func (h *GoogleOAuthHandler) createGoogleUser(ctx context.Context, userInfo *GoogleUserInfo) (string, error) {
	// Generate a UUID for the username
	username := uuid.New().String()

	result, err := h.cognitoClient.AdminCreateUser(ctx, &cognitoidentityprovider.AdminCreateUserInput{
		UserPoolId: &h.userPoolID,
		Username:   &username,
		UserAttributes: []types.AttributeType{
			{
				Name:  aws.String("email"),
				Value: &userInfo.Email,
			},
			{
				Name:  aws.String("email_verified"),
				Value: aws.String("true"),
			},
			{
				Name:  aws.String("custom:auth_method"),
				Value: aws.String("google"),
			},
			{
				Name:  aws.String("custom:linked_providers"),
				Value: aws.String("google"),
			},
		},
	})

	if err != nil {
		return "", err
	}

	return *result.User.Username, nil
}
