package api

import (
	"encoding/json"

	"github.com/aws/aws-lambda-go/events"
)

// APIResponse is the standard response format for all API endpoints
// @Description Standard response format for all API endpoints
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

// SendResponse creates a standardized API Gateway HTTP response
func SendResponse(statusCode int, success bool, message string, data interface{}, err string) events.APIGatewayV2HTTPResponse {
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
			"Content-Type":                 "application/json",
			"Access-Control-Allow-Origin":  "*", // Enable CORS
			"Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
			"Access-Control-Allow-Headers": "Content-Type, Authorization",
		},
	}
}

// SendError is a convenience function for sending error responses
func SendError(statusCode int, message string, err string) events.APIGatewayV2HTTPResponse {
	return SendResponse(statusCode, false, message, nil, err)
}

// SendSuccess is a convenience function for sending success responses
func SendSuccess(statusCode int, message string, data interface{}) events.APIGatewayV2HTTPResponse {
	return SendResponse(statusCode, true, message, data, "")
}
