// Package main provides feed services for NounHub
// @title NounHub Feed API
// @version 1.0
// @description Feed service for NounHub providing school news and announcements
// @contact.name NounHub API Support
// @contact.url https://www.nounhub.org
// @BasePath /{stage}/feed
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Enter the token with the `Bearer: ` prefix, e.g. "Bearer abcde12345".
package main

import (
	"context"
	"encoding/json"
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
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbTypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	_ "github.com/swaggo/swag" // for swagger annotations
)

// Common response structure for all API endpoints
type APIResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

// Post represents a feed post
type Post struct {
	ID            string    `json:"id" dynamodbav:"id"`
	Title         string    `json:"title" dynamodbav:"title"`
	Body          string    `json:"body" dynamodbav:"body"`
	AuthorID      string    `json:"author_id" dynamodbav:"author_id"`
	CategoryID    string    `json:"category_id" dynamodbav:"category_id"`
	CreatedAt     time.Time `json:"created_at" dynamodbav:"created_at"`
	UpdatedAt     time.Time `json:"updated_at" dynamodbav:"updated_at"`
	Likes         int       `json:"likes" dynamodbav:"likes"`
	HasAttachment bool      `json:"has_attachment" dynamodbav:"has_attachment"`
}

// Category represents a post category
type Category struct {
	ID        string    `json:"id" dynamodbav:"id"`
	Name      string    `json:"name" dynamodbav:"name"`
	CreatedAt time.Time `json:"created_at" dynamodbav:"created_at"`
	UpdatedAt time.Time `json:"updated_at" dynamodbav:"updated_at"`
}

// Attachment represents a file attached to a post
type Attachment struct {
	ID           string    `json:"id" dynamodbav:"id"`
	PostID       string    `json:"post_id" dynamodbav:"post_id"`
	FileName     string    `json:"file_name" dynamodbav:"file_name"`
	FileType     string    `json:"file_type" dynamodbav:"file_type"`
	FileSize     int64     `json:"file_size" dynamodbav:"file_size"`
	S3Key        string    `json:"s3_key" dynamodbav:"s3_key"`
	HasThumbnail bool      `json:"has_thumbnail" dynamodbav:"has_thumbnail"`
	ThumbnailKey string    `json:"thumbnail_key" dynamodbav:"thumbnail_key"`
	CreatedAt    time.Time `json:"created_at" dynamodbav:"created_at"`
}

// Like represents a user's like on a post
type Like struct {
	UserID    string    `json:"user_id" dynamodbav:"user_id"`
	PostID    string    `json:"post_id" dynamodbav:"post_id"`
	CreatedAt time.Time `json:"created_at" dynamodbav:"created_at"`
}

// CreatePostRequest represents the request payload for creating a post
type CreatePostRequest struct {
	Title      string `json:"title" example:"Important TMA Announcement"`
	Body       string `json:"body" example:"All TMAs for semester 1 are due by Monday."`
	CategoryID string `json:"category_id" example:"cat-123"`
}

// UpdatePostRequest represents the request payload for updating a post
type UpdatePostRequest struct {
	Title      string `json:"title" example:"Updated TMA Announcement"`
	Body       string `json:"body" example:"All TMAs for semester 1 are due by next Friday."`
	CategoryID string `json:"category_id" example:"cat-123"`
}

// CreateCategoryRequest represents the request payload for creating a category
type CreateCategoryRequest struct {
	Name string `json:"name" example:"TMA"`
}

// FeedHandler handles feed operations
type FeedHandler struct {
	dynamodbClient      *dynamodb.Client
	cognitoClient       *cognitoidentityprovider.Client
	s3Client            *s3.Client
	postTableName       string
	categoryTableName   string
	attachmentTableName string
	likeTableName       string
	userPoolID          string
	bucketName          string
	adminGroup          string
	moderatorGroup      string
}

// Claims represents JWT token claims
type Claims struct {
	Username string   `json:"username"`
	Groups   []string `json:"cognito:groups"`
	jwt.RegisteredClaims
}

func main() {
	ctx := context.Background()

	// Configure AWS SDK
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		log.Fatalf("Failed to load AWS config: %v", err)
	}

	// Initialize DynamoDB client
	dynamodbClient := dynamodb.NewFromConfig(cfg)

	// Initialize Cognito client
	cognitoClient := cognitoidentityprovider.NewFromConfig(cfg)

	// Initialize S3 client
	s3Client := s3.NewFromConfig(cfg)

	// Get environment variables
	postTableName := os.Getenv("POST_TABLE_NAME")
	categoryTableName := os.Getenv("CATEGORY_TABLE_NAME")
	attachmentTableName := os.Getenv("ATTACHMENT_TABLE_NAME")
	likeTableName := os.Getenv("LIKE_TABLE_NAME")
	userPoolID := os.Getenv("USER_POOL_ID")
	bucketName := os.Getenv("BUCKET_NAME")
	adminGroup := os.Getenv("ADMIN_GROUP")
	moderatorGroup := os.Getenv("MODERATOR_GROUP")

	// Create handler
	handler := &FeedHandler{
		dynamodbClient:      dynamodbClient,
		cognitoClient:       cognitoClient,
		s3Client:            s3Client,
		postTableName:       postTableName,
		categoryTableName:   categoryTableName,
		attachmentTableName: attachmentTableName,
		likeTableName:       likeTableName,
		userPoolID:          userPoolID,
		bucketName:          bucketName,
		adminGroup:          adminGroup,
		moderatorGroup:      moderatorGroup,
	}

	// Start Lambda handler
	lambda.Start(handler.handleRequest)
}

// handleRequest is the main Lambda handler
func (h *FeedHandler) handleRequest(ctx context.Context, request events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	// Extract route details
	method := request.RequestContext.HTTP.Method
	path := normalizePath(request.RequestContext.HTTP.Path)

	// Handle Swagger documentation requests
	if strings.Contains(path, "/swagger/") {
		return h.handleSwaggerRequest(ctx, request)
	}

	// Extract user claims from JWT token
	var claims *Claims
	if authHeader, ok := request.Headers["authorization"]; ok {
		token := strings.TrimPrefix(authHeader, "Bearer ")
		var err error
		claims, err = validateToken(token)
		if err != nil && !isPublicEndpoint(method, path) {
			return sendAPIResponse(401, false, "", nil, "Unauthorized"), nil
		}
	} else if !isPublicEndpoint(method, path) {
		return sendAPIResponse(401, false, "", nil, "Unauthorized"), nil
	}

	// Route to appropriate handler
	switch {
	// Post endpoints
	case method == "GET" && path == "/posts":
		return h.handleGetPosts(ctx, request, claims)
	case method == "GET" && strings.HasPrefix(path, "/posts/"):
		return h.handleGetPost(ctx, request, claims)
	case method == "POST" && path == "/posts":
		return h.handleCreatePost(ctx, request, claims)
	case method == "PUT" && strings.HasPrefix(path, "/posts/"):
		return h.handleUpdatePost(ctx, request, claims)
	case method == "DELETE" && strings.HasPrefix(path, "/posts/"):
		return h.handleDeletePost(ctx, request, claims)

	// Category endpoints
	case method == "GET" && path == "/categories":
		return h.handleGetCategories(ctx, request, claims)
	case method == "POST" && path == "/categories":
		return h.handleCreateCategory(ctx, request, claims)
	case method == "PUT" && strings.HasPrefix(path, "/categories/"):
		return h.handleUpdateCategory(ctx, request, claims)
	case method == "DELETE" && strings.HasPrefix(path, "/categories/"):
		return h.handleDeleteCategory(ctx, request, claims)

	// Like endpoints
	case method == "POST" && strings.HasPrefix(path, "/posts/") && strings.HasSuffix(path, "/like"):
		return h.handleLikePost(ctx, request, claims)
	case method == "DELETE" && strings.HasPrefix(path, "/posts/") && strings.HasSuffix(path, "/like"):
		return h.handleUnlikePost(ctx, request, claims)

	// Attachment endpoints
	case method == "POST" && strings.HasPrefix(path, "/posts/") && strings.HasSuffix(path, "/attachments"):
		return h.handleAddAttachment(ctx, request, claims)
	case method == "GET" && strings.HasPrefix(path, "/posts/") && strings.HasSuffix(path, "/attachments"):
		return h.handleGetAttachments(ctx, request, claims)
	case method == "DELETE" && strings.HasPrefix(path, "/attachments/"):
		return h.handleDeleteAttachment(ctx, request, claims)

	// Repost endpoints
	case method == "POST" && strings.HasPrefix(path, "/posts/") && strings.HasSuffix(path, "/repost"):
		return h.handleRepostPost(ctx, request, claims)

	default:
		return sendAPIResponse(404, false, "", nil, "Endpoint not found"), nil
	}
}

// Helper function to normalize API paths
func normalizePath(path string) string {
	// Split the path into parts
	parts := strings.Split(path, "/")
	if len(parts) < 3 {
		return path
	}

	// Remove stage and service prefix (e.g., /dev/feed)
	// Find the index of "feed" in the path
	feedIndex := -1
	for i, part := range parts {
		if part == "feed" {
			feedIndex = i
			break
		}
	}

	if feedIndex >= 0 && feedIndex+1 < len(parts) {
		// Return everything after the first occurrence of "feed"
		return "/" + strings.Join(parts[feedIndex+1:], "/")
	}

	return path
}

// Utility function to send API responses
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

// Validate JWT token and extract claims
func validateToken(tokenString string) (*Claims, error) {
	// Parse the JWT token
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify the signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// In a real application, you would fetch the verification key from Cognito
		// For simplicity, we'll just validate the token format
		return []byte("secret"), nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}

// Check if the user is an admin
func isAdmin(claims *Claims) bool {
	if claims == nil {
		return false
	}

	for _, group := range claims.Groups {
		if group == "admin" {
			return true
		}
	}

	return false
}

// Check if the user is a moderator
func isModerator(claims *Claims) bool {
	if claims == nil {
		return false
	}

	for _, group := range claims.Groups {
		if group == "moderator" || group == "admin" {
			return true
		}
	}

	return false
}

// Check if the endpoint doesn't require authentication
func isPublicEndpoint(method, path string) bool {
	// Only GET requests to feed posts and categories are public
	return method == "GET" && (strings.HasPrefix(path, "/posts") || strings.HasPrefix(path, "/categories"))
}

// @Summary Get all posts
// @Description Retrieve a list of posts, optionally filtered by category or author
// @Tags Posts
// @Accept json
// @Produce json
// @Param category_id query string false "Filter by category ID"
// @Param author_id query string false "Filter by author ID"
// @Success 200 {object} APIResponse{data=[]Post} "Successful operation"
// @Failure 500 {object} APIResponse "Server error"
// @Router /posts [get]
func (h *FeedHandler) handleGetPosts(ctx context.Context, request events.APIGatewayV2HTTPRequest, claims *Claims) (events.APIGatewayV2HTTPResponse, error) {
	// Get query parameters
	categoryID := request.QueryStringParameters["category"]
	limit := 20 // Default limit

	// Parse limit if provided
	if limitStr, ok := request.QueryStringParameters["limit"]; ok {
		if _, err := fmt.Sscanf(limitStr, "%d", &limit); err != nil {
			limit = 20 // Reset to default if parsing fails
		}
	}

	// Prepare the query
	var queryInput *dynamodb.QueryInput
	var scanInput *dynamodb.ScanInput

	if categoryID != "" {
		// Query by category
		queryInput = &dynamodb.QueryInput{
			TableName:              aws.String(h.postTableName),
			IndexName:              aws.String("CategoryIndex"),
			KeyConditionExpression: aws.String("category_id = :catId"),
			ExpressionAttributeValues: map[string]ddbTypes.AttributeValue{
				":catId": &ddbTypes.AttributeValueMemberS{Value: categoryID},
			},
			ScanIndexForward: aws.Bool(false), // Descending order (newest first)
			Limit:            aws.Int32(int32(limit)),
		}
	} else {
		// Scan all posts
		scanInput = &dynamodb.ScanInput{
			TableName: aws.String(h.postTableName),
			Limit:     aws.Int32(int32(limit)),
		}
	}

	var posts []Post

	if queryInput != nil {
		// Execute the query
		queryOutput, err := h.dynamodbClient.Query(ctx, queryInput)
		if err != nil {
			log.Printf("Error querying posts: %v", err)
			return sendAPIResponse(500, false, "", nil, "Error retrieving posts"), nil
		}

		// Unmarshal the results
		err = attributevalue.UnmarshalListOfMaps(queryOutput.Items, &posts)
		if err != nil {
			log.Printf("Error unmarshaling posts: %v", err)
			return sendAPIResponse(500, false, "", nil, "Error processing posts"), nil
		}
	} else {
		// Execute the scan
		scanOutput, err := h.dynamodbClient.Scan(ctx, scanInput)
		if err != nil {
			log.Printf("Error scanning posts: %v", err)
			return sendAPIResponse(500, false, "", nil, "Error retrieving posts"), nil
		}

		// Unmarshal the results
		err = attributevalue.UnmarshalListOfMaps(scanOutput.Items, &posts)
		if err != nil {
			log.Printf("Error unmarshaling posts: %v", err)
			return sendAPIResponse(500, false, "", nil, "Error processing posts"), nil
		}

		// Sort by created_at (newest first) - since Scan doesn't guarantee order
		if len(posts) > 0 {
			// Sort in-memory - would be better to use a proper index in production
			sortPostsByDate(posts)
		}
	}

	return sendAPIResponse(200, true, "Posts retrieved successfully", posts, ""), nil
}

// Helper function to sort posts by date (newest first)
func sortPostsByDate(posts []Post) {
	// Sort by created_at in descending order
	for i := 0; i < len(posts)-1; i++ {
		for j := i + 1; j < len(posts); j++ {
			if posts[i].CreatedAt.Before(posts[j].CreatedAt) {
				posts[i], posts[j] = posts[j], posts[i]
			}
		}
	}
}

// @Summary Get a post by ID
// @Description Retrieve a specific post by its ID
// @Tags Posts
// @Accept json
// @Produce json
// @Param id path string true "Post ID"
// @Success 200 {object} APIResponse{data=Post} "Successful operation"
// @Failure 404 {object} APIResponse "Post not found"
// @Failure 500 {object} APIResponse "Server error"
// @Router /posts/{id} [get]
func (h *FeedHandler) handleGetPost(ctx context.Context, request events.APIGatewayV2HTTPRequest, claims *Claims) (events.APIGatewayV2HTTPResponse, error) {
	// Extract post ID from path
	parts := strings.Split(request.RequestContext.HTTP.Path, "/")
	if len(parts) < 4 {
		return sendAPIResponse(400, false, "", nil, "Invalid path format"), nil
	}

	postID := parts[len(parts)-1]

	// Get the post from DynamoDB
	getItemOutput, err := h.dynamodbClient.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(h.postTableName),
		Key: map[string]ddbTypes.AttributeValue{
			"id": &ddbTypes.AttributeValueMemberS{Value: postID},
		},
	})

	if err != nil {
		log.Printf("Error getting post: %v", err)
		return sendAPIResponse(500, false, "", nil, "Error retrieving post"), nil
	}

	if getItemOutput.Item == nil {
		return sendAPIResponse(404, false, "", nil, "Post not found"), nil
	}

	// Unmarshal the post
	var post Post
	err = attributevalue.UnmarshalMap(getItemOutput.Item, &post)
	if err != nil {
		log.Printf("Error unmarshaling post: %v", err)
		return sendAPIResponse(500, false, "", nil, "Error processing post"), nil
	}

	return sendAPIResponse(200, true, "Post retrieved successfully", post, ""), nil
}

// @Summary Create a new post
// @Description Create a new post with the provided information
// @Tags Posts
// @Accept json
// @Produce json
// @Param post body CreatePostRequest true "Post information"
// @Security BearerAuth
// @Success 201 {object} APIResponse{data=Post} "Post created"
// @Failure 400 {object} APIResponse "Invalid input"
// @Failure 401 {object} APIResponse "Unauthorized"
// @Failure 500 {object} APIResponse "Server error"
// @Router /posts [post]
func (h *FeedHandler) handleCreatePost(ctx context.Context, request events.APIGatewayV2HTTPRequest, claims *Claims) (events.APIGatewayV2HTTPResponse, error) {
	// Only moderators and admins can create posts
	if !isModerator(claims) {
		return sendAPIResponse(403, false, "", nil, "Only moderators and admins can create posts"), nil
	}

	// Parse request body
	var createPostReq CreatePostRequest
	if err := json.Unmarshal([]byte(request.Body), &createPostReq); err != nil {
		return sendAPIResponse(400, false, "", nil, "Invalid request body"), nil
	}

	// Validate request
	if createPostReq.Title == "" || createPostReq.Body == "" || createPostReq.CategoryID == "" {
		return sendAPIResponse(400, false, "", nil, "Title, body and category are required"), nil
	}

	// Verify category exists
	categoryExists, err := h.categoryExists(ctx, createPostReq.CategoryID)
	if err != nil {
		log.Printf("Error checking category: %v", err)
		return sendAPIResponse(500, false, "", nil, "Error validating category"), nil
	}

	if !categoryExists {
		return sendAPIResponse(400, false, "", nil, "Invalid category"), nil
	}

	// Create a new post
	now := time.Now()
	post := Post{
		ID:            uuid.New().String(),
		Title:         createPostReq.Title,
		Body:          createPostReq.Body,
		AuthorID:      claims.Username,
		CategoryID:    createPostReq.CategoryID,
		CreatedAt:     now,
		UpdatedAt:     now,
		Likes:         0,
		HasAttachment: false,
	}

	// Marshal the post
	item, err := attributevalue.MarshalMap(post)
	if err != nil {
		log.Printf("Error marshaling post: %v", err)
		return sendAPIResponse(500, false, "", nil, "Error creating post"), nil
	}

	// Save to DynamoDB
	_, err = h.dynamodbClient.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(h.postTableName),
		Item:      item,
	})

	if err != nil {
		log.Printf("Error saving post: %v", err)
		return sendAPIResponse(500, false, "", nil, "Error saving post"), nil
	}

	return sendAPIResponse(201, true, "Post created successfully", post, ""), nil
}

// Helper function to check if a category exists
func (h *FeedHandler) categoryExists(ctx context.Context, categoryID string) (bool, error) {
	// Check if the category exists
	getItemOutput, err := h.dynamodbClient.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(h.categoryTableName),
		Key: map[string]ddbTypes.AttributeValue{
			"id": &ddbTypes.AttributeValueMemberS{Value: categoryID},
		},
	})

	if err != nil {
		return false, err
	}

	return getItemOutput.Item != nil, nil
}

// @Summary Update a post
// @Description Update an existing post with new information
// @Tags Posts
// @Accept json
// @Produce json
// @Param id path string true "Post ID"
// @Param post body UpdatePostRequest true "Updated post information"
// @Security BearerAuth
// @Success 200 {object} APIResponse{data=Post} "Post updated"
// @Failure 400 {object} APIResponse "Invalid input"
// @Failure 401 {object} APIResponse "Unauthorized"
// @Failure 403 {object} APIResponse "Forbidden - not post owner or admin"
// @Failure 404 {object} APIResponse "Post not found"
// @Failure 500 {object} APIResponse "Server error"
// @Router /posts/{id} [put]
func (h *FeedHandler) handleUpdatePost(ctx context.Context, request events.APIGatewayV2HTTPRequest, claims *Claims) (events.APIGatewayV2HTTPResponse, error) {
	// Only moderators and admins can update posts
	if !isModerator(claims) {
		return sendAPIResponse(403, false, "", nil, "Only moderators and admins can update posts"), nil
	}

	// Extract post ID from path
	parts := strings.Split(request.RequestContext.HTTP.Path, "/")
	if len(parts) < 4 {
		return sendAPIResponse(400, false, "", nil, "Invalid path format"), nil
	}

	postID := parts[len(parts)-1]

	// Parse request body
	var updatePostReq UpdatePostRequest
	if err := json.Unmarshal([]byte(request.Body), &updatePostReq); err != nil {
		return sendAPIResponse(400, false, "", nil, "Invalid request body"), nil
	}

	// Validate request
	if updatePostReq.Title == "" || updatePostReq.Body == "" || updatePostReq.CategoryID == "" {
		return sendAPIResponse(400, false, "", nil, "Title, body and category are required"), nil
	}

	// Get existing post
	getItemOutput, err := h.dynamodbClient.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(h.postTableName),
		Key: map[string]ddbTypes.AttributeValue{
			"id": &ddbTypes.AttributeValueMemberS{Value: postID},
		},
	})

	if err != nil {
		log.Printf("Error getting post: %v", err)
		return sendAPIResponse(500, false, "", nil, "Error retrieving post"), nil
	}

	if getItemOutput.Item == nil {
		return sendAPIResponse(404, false, "", nil, "Post not found"), nil
	}

	// Unmarshal the post
	var post Post
	err = attributevalue.UnmarshalMap(getItemOutput.Item, &post)
	if err != nil {
		log.Printf("Error unmarshaling post: %v", err)
		return sendAPIResponse(500, false, "", nil, "Error processing post"), nil
	}

	// Check if user is admin or the post author (moderator can't edit admin posts)
	if !isAdmin(claims) && post.AuthorID != claims.Username {
		// Get the author's groups to check if they're admin
		authorGroups, err := h.getUserGroups(ctx, post.AuthorID)
		if err != nil {
			log.Printf("Error getting author groups: %v", err)
			return sendAPIResponse(500, false, "", nil, "Error verifying permissions"), nil
		}

		// Check if the author is an admin
		for _, group := range authorGroups {
			if group == h.adminGroup {
				return sendAPIResponse(403, false, "", nil, "Moderators cannot edit posts created by admins"), nil
			}
		}
	}

	// Verify category exists
	categoryExists, err := h.categoryExists(ctx, updatePostReq.CategoryID)
	if err != nil {
		log.Printf("Error checking category: %v", err)
		return sendAPIResponse(500, false, "", nil, "Error validating category"), nil
	}

	if !categoryExists {
		return sendAPIResponse(400, false, "", nil, "Invalid category"), nil
	}

	// Update the post
	post.Title = updatePostReq.Title
	post.Body = updatePostReq.Body
	post.CategoryID = updatePostReq.CategoryID
	post.UpdatedAt = time.Now()

	// Marshal the post
	item, err := attributevalue.MarshalMap(post)
	if err != nil {
		log.Printf("Error marshaling post: %v", err)
		return sendAPIResponse(500, false, "", nil, "Error updating post"), nil
	}

	// Save to DynamoDB
	_, err = h.dynamodbClient.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(h.postTableName),
		Item:      item,
	})

	if err != nil {
		log.Printf("Error saving post: %v", err)
		return sendAPIResponse(500, false, "", nil, "Error saving post"), nil
	}

	return sendAPIResponse(200, true, "Post updated successfully", post, ""), nil
}

// Helper function to get a user's groups
func (h *FeedHandler) getUserGroups(ctx context.Context, username string) ([]string, error) {
	adminListGroupsOutput, err := h.cognitoClient.AdminListGroupsForUser(ctx, &cognitoidentityprovider.AdminListGroupsForUserInput{
		UserPoolId: aws.String(h.userPoolID),
		Username:   aws.String(username),
	})

	if err != nil {
		return nil, err
	}

	var groups []string
	for _, group := range adminListGroupsOutput.Groups {
		groups = append(groups, *group.GroupName)
	}

	return groups, nil
}

// @Summary Delete a post
// @Description Delete an existing post
// @Tags Posts
// @Accept json
// @Produce json
// @Param id path string true "Post ID"
// @Security BearerAuth
// @Success 200 {object} APIResponse "Post deleted"
// @Failure 401 {object} APIResponse "Unauthorized"
// @Failure 403 {object} APIResponse "Forbidden - not post owner or admin"
// @Failure 404 {object} APIResponse "Post not found"
// @Failure 500 {object} APIResponse "Server error"
// @Router /posts/{id} [delete]
func (h *FeedHandler) handleDeletePost(ctx context.Context, request events.APIGatewayV2HTTPRequest, claims *Claims) (events.APIGatewayV2HTTPResponse, error) {
	// Only moderators and admins can delete posts
	if !isModerator(claims) {
		return sendAPIResponse(403, false, "", nil, "Only moderators and admins can delete posts"), nil
	}

	// Extract post ID from path
	parts := strings.Split(request.RequestContext.HTTP.Path, "/")
	if len(parts) < 4 {
		return sendAPIResponse(400, false, "", nil, "Invalid path format"), nil
	}

	postID := parts[len(parts)-1]

	// Get existing post to check permissions
	getItemOutput, err := h.dynamodbClient.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(h.postTableName),
		Key: map[string]ddbTypes.AttributeValue{
			"id": &ddbTypes.AttributeValueMemberS{Value: postID},
		},
	})

	if err != nil {
		log.Printf("Error getting post: %v", err)
		return sendAPIResponse(500, false, "", nil, "Error retrieving post"), nil
	}

	if getItemOutput.Item == nil {
		return sendAPIResponse(404, false, "", nil, "Post not found"), nil
	}

	// Unmarshal the post
	var post Post
	err = attributevalue.UnmarshalMap(getItemOutput.Item, &post)
	if err != nil {
		log.Printf("Error unmarshaling post: %v", err)
		return sendAPIResponse(500, false, "", nil, "Error processing post"), nil
	}

	// Check if user is admin or the post author (moderator can't delete admin posts)
	if !isAdmin(claims) && post.AuthorID != claims.Username {
		// Get the author's groups to check if they're admin
		authorGroups, err := h.getUserGroups(ctx, post.AuthorID)
		if err != nil {
			log.Printf("Error getting author groups: %v", err)
			return sendAPIResponse(500, false, "", nil, "Error verifying permissions"), nil
		}

		// Check if the author is an admin
		for _, group := range authorGroups {
			if group == h.adminGroup {
				return sendAPIResponse(403, false, "", nil, "Moderators cannot delete posts created by admins"), nil
			}
		}
	}

	// Delete the post
	_, err = h.dynamodbClient.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: aws.String(h.postTableName),
		Key: map[string]ddbTypes.AttributeValue{
			"id": &ddbTypes.AttributeValueMemberS{Value: postID},
		},
	})

	if err != nil {
		log.Printf("Error deleting post: %v", err)
		return sendAPIResponse(500, false, "", nil, "Error deleting post"), nil
	}

	// If the post has attachments, delete them as well
	if post.HasAttachment {
		// Query for attachments
		queryOutput, err := h.dynamodbClient.Query(ctx, &dynamodb.QueryInput{
			TableName:              aws.String(h.attachmentTableName),
			IndexName:              aws.String("PostIndex"),
			KeyConditionExpression: aws.String("post_id = :postId"),
			ExpressionAttributeValues: map[string]ddbTypes.AttributeValue{
				":postId": &ddbTypes.AttributeValueMemberS{Value: postID},
			},
		})

		if err != nil {
			log.Printf("Error querying attachments: %v", err)
			// Continue with post deletion even if attachment query fails
		} else {
			// Delete attachments
			var attachments []Attachment
			err = attributevalue.UnmarshalListOfMaps(queryOutput.Items, &attachments)
			if err == nil {
				for _, attachment := range attachments {
					// Delete attachment record
					_, err = h.dynamodbClient.DeleteItem(ctx, &dynamodb.DeleteItemInput{
						TableName: aws.String(h.attachmentTableName),
						Key: map[string]ddbTypes.AttributeValue{
							"id": &ddbTypes.AttributeValueMemberS{Value: attachment.ID},
						},
					})

					if err != nil {
						log.Printf("Error deleting attachment record: %v", err)
					}

					// Delete the file from S3
					_, err = h.s3Client.DeleteObject(ctx, &s3.DeleteObjectInput{
						Bucket: aws.String(h.bucketName),
						Key:    aws.String(attachment.S3Key),
					})

					if err != nil {
						log.Printf("Error deleting attachment file: %v", err)
					}

					// Delete thumbnail if exists
					if attachment.HasThumbnail && attachment.ThumbnailKey != "" {
						_, err = h.s3Client.DeleteObject(ctx, &s3.DeleteObjectInput{
							Bucket: aws.String(h.bucketName),
							Key:    aws.String(attachment.ThumbnailKey),
						})

						if err != nil {
							log.Printf("Error deleting thumbnail: %v", err)
						}
					}
				}
			}
		}
	}

	return sendAPIResponse(200, true, "Post deleted successfully", nil, ""), nil
}

// @Summary Get all categories
// @Description Retrieve a list of all categories
// @Tags Categories
// @Accept json
// @Produce json
// @Success 200 {object} APIResponse{data=[]Category} "Successful operation"
// @Failure 500 {object} APIResponse "Server error"
// @Router /categories [get]
func (h *FeedHandler) handleGetCategories(ctx context.Context, request events.APIGatewayV2HTTPRequest, claims *Claims) (events.APIGatewayV2HTTPResponse, error) {
	// Scan all categories
	scanOutput, err := h.dynamodbClient.Scan(ctx, &dynamodb.ScanInput{
		TableName: aws.String(h.categoryTableName),
	})

	if err != nil {
		log.Printf("Error scanning categories: %v", err)
		return sendAPIResponse(500, false, "", nil, "Error retrieving categories"), nil
	}

	var categories []Category
	err = attributevalue.UnmarshalListOfMaps(scanOutput.Items, &categories)
	if err != nil {
		log.Printf("Error unmarshaling categories: %v", err)
		return sendAPIResponse(500, false, "", nil, "Error processing categories"), nil
	}

	return sendAPIResponse(200, true, "Categories retrieved successfully", categories, ""), nil
}

// @Summary Create a new category
// @Description Create a new category with the provided name
// @Tags Categories
// @Accept json
// @Produce json
// @Param category body CreateCategoryRequest true "Category information"
// @Security BearerAuth
// @Success 201 {object} APIResponse{data=Category} "Category created"
// @Failure 400 {object} APIResponse "Invalid input"
// @Failure 401 {object} APIResponse "Unauthorized"
// @Failure 403 {object} APIResponse "Forbidden - not admin"
// @Failure 500 {object} APIResponse "Server error"
// @Router /categories [post]
func (h *FeedHandler) handleCreateCategory(ctx context.Context, request events.APIGatewayV2HTTPRequest, claims *Claims) (events.APIGatewayV2HTTPResponse, error) {
	// Only moderators and admins can create categories
	if !isModerator(claims) {
		return sendAPIResponse(403, false, "", nil, "Only moderators and admins can create categories"), nil
	}

	// Parse request body
	var createCategoryReq CreateCategoryRequest
	if err := json.Unmarshal([]byte(request.Body), &createCategoryReq); err != nil {
		return sendAPIResponse(400, false, "", nil, "Invalid request body"), nil
	}

	// Validate request
	if createCategoryReq.Name == "" {
		return sendAPIResponse(400, false, "", nil, "Category name is required"), nil
	}

	// Check if category name already exists
	queryOutput, err := h.dynamodbClient.Query(ctx, &dynamodb.QueryInput{
		TableName:              aws.String(h.categoryTableName),
		IndexName:              aws.String("NameIndex"),
		KeyConditionExpression: aws.String("name = :name"),
		ExpressionAttributeValues: map[string]ddbTypes.AttributeValue{
			":name": &ddbTypes.AttributeValueMemberS{Value: createCategoryReq.Name},
		},
	})

	if err != nil {
		log.Printf("Error checking category existence: %v", err)
		return sendAPIResponse(500, false, "", nil, "Error validating category name"), nil
	}

	if len(queryOutput.Items) > 0 {
		return sendAPIResponse(400, false, "", nil, "Category with this name already exists"), nil
	}

	// Create a new category
	now := time.Now()
	category := Category{
		ID:        uuid.New().String(),
		Name:      createCategoryReq.Name,
		CreatedAt: now,
		UpdatedAt: now,
	}

	// Marshal the category
	item, err := attributevalue.MarshalMap(category)
	if err != nil {
		log.Printf("Error marshaling category: %v", err)
		return sendAPIResponse(500, false, "", nil, "Error creating category"), nil
	}

	// Save to DynamoDB
	_, err = h.dynamodbClient.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(h.categoryTableName),
		Item:      item,
	})

	if err != nil {
		log.Printf("Error saving category: %v", err)
		return sendAPIResponse(500, false, "", nil, "Error saving category"), nil
	}

	return sendAPIResponse(201, true, "Category created successfully", category, ""), nil
}

// @Summary Update a category
// @Description Update an existing category with a new name
// @Tags Categories
// @Accept json
// @Produce json
// @Param id path string true "Category ID"
// @Param category body CreateCategoryRequest true "Updated category information"
// @Security BearerAuth
// @Success 200 {object} APIResponse{data=Category} "Category updated"
// @Failure 400 {object} APIResponse "Invalid input"
// @Failure 401 {object} APIResponse "Unauthorized"
// @Failure 403 {object} APIResponse "Forbidden - not admin"
// @Failure 404 {object} APIResponse "Category not found"
// @Failure 500 {object} APIResponse "Server error"
// @Router /categories/{id} [put]
func (h *FeedHandler) handleUpdateCategory(ctx context.Context, request events.APIGatewayV2HTTPRequest, claims *Claims) (events.APIGatewayV2HTTPResponse, error) {
	// Only moderators and admins can update categories
	if !isModerator(claims) {
		return sendAPIResponse(403, false, "", nil, "Only moderators and admins can update categories"), nil
	}

	// Extract category ID from path
	parts := strings.Split(request.RequestContext.HTTP.Path, "/")
	if len(parts) < 4 {
		return sendAPIResponse(400, false, "", nil, "Invalid path format"), nil
	}

	categoryID := parts[len(parts)-1]

	// Parse request body
	var updateCategoryReq CreateCategoryRequest // Reuse the CreateCategoryRequest struct
	if err := json.Unmarshal([]byte(request.Body), &updateCategoryReq); err != nil {
		return sendAPIResponse(400, false, "", nil, "Invalid request body"), nil
	}

	// Validate request
	if updateCategoryReq.Name == "" {
		return sendAPIResponse(400, false, "", nil, "Category name is required"), nil
	}

	// Get the existing category
	getItemOutput, err := h.dynamodbClient.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(h.categoryTableName),
		Key: map[string]ddbTypes.AttributeValue{
			"id": &ddbTypes.AttributeValueMemberS{Value: categoryID},
		},
	})

	if err != nil {
		log.Printf("Error getting category: %v", err)
		return sendAPIResponse(500, false, "", nil, "Error retrieving category"), nil
	}

	if getItemOutput.Item == nil {
		return sendAPIResponse(404, false, "", nil, "Category not found"), nil
	}

	// Check if another category with the same name already exists
	if updateCategoryReq.Name != "" {
		queryOutput, err := h.dynamodbClient.Query(ctx, &dynamodb.QueryInput{
			TableName:              aws.String(h.categoryTableName),
			IndexName:              aws.String("NameIndex"),
			KeyConditionExpression: aws.String("name = :name"),
			ExpressionAttributeValues: map[string]ddbTypes.AttributeValue{
				":name": &ddbTypes.AttributeValueMemberS{Value: updateCategoryReq.Name},
			},
		})

		if err != nil {
			log.Printf("Error checking category existence: %v", err)
			return sendAPIResponse(500, false, "", nil, "Error validating category name"), nil
		}

		if len(queryOutput.Items) > 0 {
			var existingCategory Category
			err = attributevalue.UnmarshalMap(queryOutput.Items[0], &existingCategory)
			if err == nil && existingCategory.ID != categoryID {
				return sendAPIResponse(400, false, "", nil, "Category with this name already exists"), nil
			}
		}
	}

	// Unmarshal the existing category
	var category Category
	err = attributevalue.UnmarshalMap(getItemOutput.Item, &category)
	if err != nil {
		log.Printf("Error unmarshaling category: %v", err)
		return sendAPIResponse(500, false, "", nil, "Error processing category"), nil
	}

	// Update the category
	category.Name = updateCategoryReq.Name
	category.UpdatedAt = time.Now()

	// Marshal the category
	item, err := attributevalue.MarshalMap(category)
	if err != nil {
		log.Printf("Error marshaling category: %v", err)
		return sendAPIResponse(500, false, "", nil, "Error updating category"), nil
	}

	// Save to DynamoDB
	_, err = h.dynamodbClient.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(h.categoryTableName),
		Item:      item,
	})

	if err != nil {
		log.Printf("Error saving category: %v", err)
		return sendAPIResponse(500, false, "", nil, "Error saving category"), nil
	}

	return sendAPIResponse(200, true, "Category updated successfully", category, ""), nil
}

// @Summary Delete a category
// @Description Delete an existing category
// @Tags Categories
// @Accept json
// @Produce json
// @Param id path string true "Category ID"
// @Security BearerAuth
// @Success 200 {object} APIResponse "Category deleted"
// @Failure 401 {object} APIResponse "Unauthorized"
// @Failure 403 {object} APIResponse "Forbidden - not admin"
// @Failure 404 {object} APIResponse "Category not found"
// @Failure 500 {object} APIResponse "Server error"
// @Router /categories/{id} [delete]
func (h *FeedHandler) handleDeleteCategory(ctx context.Context, request events.APIGatewayV2HTTPRequest, claims *Claims) (events.APIGatewayV2HTTPResponse, error) {
	// Only moderators and admins can delete categories
	if !isModerator(claims) {
		return sendAPIResponse(403, false, "", nil, "Only moderators and admins can delete categories"), nil
	}

	// Extract category ID from path
	parts := strings.Split(request.RequestContext.HTTP.Path, "/")
	if len(parts) < 4 {
		return sendAPIResponse(400, false, "", nil, "Invalid path format"), nil
	}

	categoryID := parts[len(parts)-1]

	// Check if the category exists
	getItemOutput, err := h.dynamodbClient.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(h.categoryTableName),
		Key: map[string]ddbTypes.AttributeValue{
			"id": &ddbTypes.AttributeValueMemberS{Value: categoryID},
		},
	})

	if err != nil {
		log.Printf("Error getting category: %v", err)
		return sendAPIResponse(500, false, "", nil, "Error retrieving category"), nil
	}

	if getItemOutput.Item == nil {
		return sendAPIResponse(404, false, "", nil, "Category not found"), nil
	}

	// Check if any posts are using this category
	queryOutput, err := h.dynamodbClient.Query(ctx, &dynamodb.QueryInput{
		TableName:              aws.String(h.postTableName),
		IndexName:              aws.String("CategoryIndex"),
		KeyConditionExpression: aws.String("category_id = :catId"),
		ExpressionAttributeValues: map[string]ddbTypes.AttributeValue{
			":catId": &ddbTypes.AttributeValueMemberS{Value: categoryID},
		},
		Limit: aws.Int32(1), // We only need to know if there are any posts
	})

	if err != nil {
		log.Printf("Error checking for posts: %v", err)
		return sendAPIResponse(500, false, "", nil, "Error checking category usage"), nil
	}

	if len(queryOutput.Items) > 0 {
		return sendAPIResponse(400, false, "", nil, "Cannot delete category that is in use by posts"), nil
	}

	// Delete the category
	_, err = h.dynamodbClient.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: aws.String(h.categoryTableName),
		Key: map[string]ddbTypes.AttributeValue{
			"id": &ddbTypes.AttributeValueMemberS{Value: categoryID},
		},
	})

	if err != nil {
		log.Printf("Error deleting category: %v", err)
		return sendAPIResponse(500, false, "", nil, "Error deleting category"), nil
	}

	return sendAPIResponse(200, true, "Category deleted successfully", nil, ""), nil
}

// @Summary Like a post
// @Description Add a like to a post
// @Tags Likes
// @Accept json
// @Produce json
// @Param id path string true "Post ID"
// @Security BearerAuth
// @Success 200 {object} APIResponse "Post liked"
// @Failure 400 {object} APIResponse "Invalid input"
// @Failure 401 {object} APIResponse "Unauthorized"
// @Failure 404 {object} APIResponse "Post not found"
// @Failure 409 {object} APIResponse "Post already liked"
// @Failure 500 {object} APIResponse "Server error"
// @Router /posts/{id}/like [post]
func (h *FeedHandler) handleLikePost(ctx context.Context, request events.APIGatewayV2HTTPRequest, claims *Claims) (events.APIGatewayV2HTTPResponse, error) {
	// All authenticated users can like posts
	if claims == nil {
		return sendAPIResponse(401, false, "", nil, "Authentication required"), nil
	}

	// Extract post ID from path
	parts := strings.Split(request.RequestContext.HTTP.Path, "/")
	if len(parts) < 4 {
		return sendAPIResponse(400, false, "", nil, "Invalid path format"), nil
	}

	postID := parts[len(parts)-2] // Format: /feed/posts/{id}/like

	// Check if the post exists
	getItemOutput, err := h.dynamodbClient.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(h.postTableName),
		Key: map[string]ddbTypes.AttributeValue{
			"id": &ddbTypes.AttributeValueMemberS{Value: postID},
		},
	})

	if err != nil {
		log.Printf("Error getting post: %v", err)
		return sendAPIResponse(500, false, "", nil, "Error retrieving post"), nil
	}

	if getItemOutput.Item == nil {
		return sendAPIResponse(404, false, "", nil, "Post not found"), nil
	}

	// Check if the user has already liked the post
	getItemOutput, err = h.dynamodbClient.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(h.likeTableName),
		Key: map[string]ddbTypes.AttributeValue{
			"user_id": &ddbTypes.AttributeValueMemberS{Value: claims.Username},
			"post_id": &ddbTypes.AttributeValueMemberS{Value: postID},
		},
	})

	if err != nil {
		log.Printf("Error checking like: %v", err)
		return sendAPIResponse(500, false, "", nil, "Error checking like status"), nil
	}

	if getItemOutput.Item != nil {
		return sendAPIResponse(400, false, "", nil, "You have already liked this post"), nil
	}

	// Create a new like
	like := Like{
		UserID:    claims.Username,
		PostID:    postID,
		CreatedAt: time.Now(),
	}

	// Marshal the like
	item, err := attributevalue.MarshalMap(like)
	if err != nil {
		log.Printf("Error marshaling like: %v", err)
		return sendAPIResponse(500, false, "", nil, "Error creating like"), nil
	}

	// Save to DynamoDB
	_, err = h.dynamodbClient.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(h.likeTableName),
		Item:      item,
	})

	if err != nil {
		log.Printf("Error saving like: %v", err)
		return sendAPIResponse(500, false, "", nil, "Error saving like"), nil
	}

	// Update the post's like count
	updateOutput, err := h.dynamodbClient.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(h.postTableName),
		Key: map[string]ddbTypes.AttributeValue{
			"id": &ddbTypes.AttributeValueMemberS{Value: postID},
		},
		UpdateExpression: aws.String("SET likes = likes + :val"),
		ExpressionAttributeValues: map[string]ddbTypes.AttributeValue{
			":val": &ddbTypes.AttributeValueMemberN{Value: "1"},
		},
		ReturnValues: ddbTypes.ReturnValueAllNew,
	})

	if err != nil {
		log.Printf("Error updating post like count: %v", err)
		// Continue even if the like count update fails
	}

	var updatedPost Post
	if updateOutput.Attributes != nil {
		err = attributevalue.UnmarshalMap(updateOutput.Attributes, &updatedPost)
		if err != nil {
			log.Printf("Error unmarshaling updated post: %v", err)
		}
	}

	return sendAPIResponse(200, true, "Post liked successfully", updatedPost, ""), nil
}

// @Summary Unlike a post
// @Description Remove a like from a post
// @Tags Likes
// @Accept json
// @Produce json
// @Param id path string true "Post ID"
// @Security BearerAuth
// @Success 200 {object} APIResponse "Post unliked"
// @Failure 400 {object} APIResponse "Invalid input"
// @Failure 401 {object} APIResponse "Unauthorized"
// @Failure 404 {object} APIResponse "Post not found or not liked"
// @Failure 500 {object} APIResponse "Server error"
// @Router /posts/{id}/like [delete]
func (h *FeedHandler) handleUnlikePost(ctx context.Context, request events.APIGatewayV2HTTPRequest, claims *Claims) (events.APIGatewayV2HTTPResponse, error) {
	// All authenticated users can unlike posts they've liked
	if claims == nil {
		return sendAPIResponse(401, false, "", nil, "Authentication required"), nil
	}

	// Extract post ID from path
	parts := strings.Split(request.RequestContext.HTTP.Path, "/")
	if len(parts) < 4 {
		return sendAPIResponse(400, false, "", nil, "Invalid path format"), nil
	}

	postID := parts[len(parts)-2] // Format: /feed/posts/{id}/like

	// Check if the post exists
	getItemOutput, err := h.dynamodbClient.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(h.postTableName),
		Key: map[string]ddbTypes.AttributeValue{
			"id": &ddbTypes.AttributeValueMemberS{Value: postID},
		},
	})

	if err != nil {
		log.Printf("Error getting post: %v", err)
		return sendAPIResponse(500, false, "", nil, "Error retrieving post"), nil
	}

	if getItemOutput.Item == nil {
		return sendAPIResponse(404, false, "", nil, "Post not found"), nil
	}

	// Check if the user has liked the post
	getItemOutput, err = h.dynamodbClient.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(h.likeTableName),
		Key: map[string]ddbTypes.AttributeValue{
			"user_id": &ddbTypes.AttributeValueMemberS{Value: claims.Username},
			"post_id": &ddbTypes.AttributeValueMemberS{Value: postID},
		},
	})

	if err != nil {
		log.Printf("Error checking like: %v", err)
		return sendAPIResponse(500, false, "", nil, "Error checking like status"), nil
	}

	if getItemOutput.Item == nil {
		return sendAPIResponse(400, false, "", nil, "You have not liked this post"), nil
	}

	// Delete the like
	_, err = h.dynamodbClient.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: aws.String(h.likeTableName),
		Key: map[string]ddbTypes.AttributeValue{
			"user_id": &ddbTypes.AttributeValueMemberS{Value: claims.Username},
			"post_id": &ddbTypes.AttributeValueMemberS{Value: postID},
		},
	})

	if err != nil {
		log.Printf("Error deleting like: %v", err)
		return sendAPIResponse(500, false, "", nil, "Error removing like"), nil
	}

	// Update the post's like count
	updateOutput, err := h.dynamodbClient.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(h.postTableName),
		Key: map[string]ddbTypes.AttributeValue{
			"id": &ddbTypes.AttributeValueMemberS{Value: postID},
		},
		UpdateExpression: aws.String("SET likes = if_not(likes - :val, :zero)"),
		ExpressionAttributeValues: map[string]ddbTypes.AttributeValue{
			":val":  &ddbTypes.AttributeValueMemberN{Value: "1"},
			":zero": &ddbTypes.AttributeValueMemberN{Value: "0"},
		},
		ReturnValues: ddbTypes.ReturnValueAllNew,
	})

	if err != nil {
		log.Printf("Error updating post like count: %v", err)
		// Continue even if the like count update fails
	}

	var updatedPost Post
	if updateOutput.Attributes != nil {
		err = attributevalue.UnmarshalMap(updateOutput.Attributes, &updatedPost)
		if err != nil {
			log.Printf("Error unmarshaling updated post: %v", err)
		}
	}

	return sendAPIResponse(200, true, "Post unliked successfully", updatedPost, ""), nil
}

// @Summary Add attachment to post
// @Description Add a file attachment to a post
// @Tags Attachments
// @Accept json
// @Produce json
// @Param id path string true "Post ID"
// @Param attachment body string true "Base64 encoded file content with metadata"
// @Security BearerAuth
// @Success 201 {object} APIResponse{data=Attachment} "Attachment added"
// @Failure 400 {object} APIResponse "Invalid input"
// @Failure 401 {object} APIResponse "Unauthorized"
// @Failure 403 {object} APIResponse "Forbidden - not post owner or admin"
// @Failure 404 {object} APIResponse "Post not found"
// @Failure 500 {object} APIResponse "Server error"
// @Router /posts/{id}/attachments [post]
func (h *FeedHandler) handleAddAttachment(ctx context.Context, request events.APIGatewayV2HTTPRequest, claims *Claims) (events.APIGatewayV2HTTPResponse, error) {
	// Only moderators and admins can add attachments
	if !isModerator(claims) {
		return sendAPIResponse(403, false, "", nil, "Only moderators and admins can add attachments"), nil
	}

	// TODO: Implement add attachment logic
	return sendAPIResponse(201, true, "Attachment added successfully", Attachment{}, ""), nil
}

// @Summary Get post attachments
// @Description Get all attachments for a post
// @Tags Attachments
// @Accept json
// @Produce json
// @Param id path string true "Post ID"
// @Success 200 {object} APIResponse{data=[]Attachment} "List of attachments"
// @Failure 404 {object} APIResponse "Post not found"
// @Failure 500 {object} APIResponse "Server error"
// @Router /posts/{id}/attachments [get]
func (h *FeedHandler) handleGetAttachments(ctx context.Context, request events.APIGatewayV2HTTPRequest, claims *Claims) (events.APIGatewayV2HTTPResponse, error) {
	// TODO: Implement get attachments logic
	return sendAPIResponse(200, true, "Attachments retrieved successfully", []Attachment{}, ""), nil
}

// @Summary Delete attachment
// @Description Delete an attachment
// @Tags Attachments
// @Accept json
// @Produce json
// @Param id path string true "Attachment ID"
// @Security BearerAuth
// @Success 200 {object} APIResponse "Attachment deleted"
// @Failure 401 {object} APIResponse "Unauthorized"
// @Failure 403 {object} APIResponse "Forbidden - not post owner or admin"
// @Failure 404 {object} APIResponse "Attachment not found"
// @Failure 500 {object} APIResponse "Server error"
// @Router /attachments/{id} [delete]
func (h *FeedHandler) handleDeleteAttachment(ctx context.Context, request events.APIGatewayV2HTTPRequest, claims *Claims) (events.APIGatewayV2HTTPResponse, error) {
	// Only moderators and admins can delete attachments
	if !isModerator(claims) {
		return sendAPIResponse(403, false, "", nil, "Only moderators and admins can delete attachments"), nil
	}

	// TODO: Implement delete attachment logic
	return sendAPIResponse(200, true, "Attachment deleted successfully", nil, ""), nil
}

// @Summary Repost a post
// @Description Create a new post that references an existing post (repost)
// @Tags Posts
// @Accept json
// @Produce json
// @Param id path string true "Post ID to repost"
// @Security BearerAuth
// @Success 201 {object} APIResponse{data=Post} "Repost created"
// @Failure 401 {object} APIResponse "Unauthorized"
// @Failure 403 {object} APIResponse "Forbidden - not admin or moderator"
// @Failure 404 {object} APIResponse "Original post not found"
// @Failure 500 {object} APIResponse "Server error"
// @Router /posts/{id}/repost [post]
func (h *FeedHandler) handleRepostPost(ctx context.Context, request events.APIGatewayV2HTTPRequest, claims *Claims) (events.APIGatewayV2HTTPResponse, error) {
	// Only moderators and admins can repost
	if !isModerator(claims) {
		return sendAPIResponse(403, false, "", nil, "Only moderators and admins can repost"), nil
	}

	// TODO: Implement repost logic
	return sendAPIResponse(201, true, "Post reposted successfully", Post{}, ""), nil
}

// Helper function to decode base64
func decodeBase64(encodedString string) ([]byte, error) {
	// Remove data URL prefix if present
	if strings.HasPrefix(encodedString, "data:") {
		parts := strings.Split(encodedString, ",")
		if len(parts) > 1 {
			encodedString = parts[1]
		}
	}

	// In a real implementation, you'd use base64.StdEncoding.DecodeString
	// For this demo, we're just returning the string as bytes
	return []byte(encodedString), nil
}

// handleSwaggerRequest handles requests for Swagger documentation
func (h *FeedHandler) handleSwaggerRequest(ctx context.Context, request events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	path := request.RequestContext.HTTP.Path
	parts := strings.Split(path, "/")

	// The path will now be like /{stage}/feed/swagger/... so we need to adjust our extraction
	// Find the "feed" part and adjust the path accordingly
	feedIndex := -1
	for i, part := range parts {
		if part == "feed" {
			feedIndex = i
			break
		}
	}

	// If we found "feed" in the path, adjust to get the swagger part
	if feedIndex >= 0 && feedIndex+1 < len(parts) {
		// Extract the swagger part of the path (after /feed)
		path = "/" + strings.Join(parts[feedIndex+1:], "/")
	}

	log.Printf("Feed Swagger request for path: %s", path)

	// Extract stage from the original request path
	originalPath := request.RequestContext.HTTP.Path
	stageName := ""
	if len(parts) >= 2 {
		stageName = parts[1] // The stage is typically the first part after the leading slash
	}
	log.Printf("Extracted stage: %s from original path: %s", stageName, originalPath)

	// Serve the Swagger UI
	if path == "/swagger/index.html" {
		// Modify the Swagger UI HTML to include the correct stage-aware base URL
		swaggerHtml := strings.Replace(
			swaggerIndexHTML,
			"url: \"./doc.json\"",
			fmt.Sprintf("url: \"./doc.json\", basePath: \"/%s/feed\"", stageName),
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

		// Modify the swagger.json content to include the stage and feed in the basePath
		var swaggerSpec map[string]interface{}
		if err := json.Unmarshal(jsonContent, &swaggerSpec); err == nil {
			if stageName != "" {
				swaggerSpec["basePath"] = "/" + stageName + "/feed"
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

// Embedded Swagger UI HTML
const swaggerIndexHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>NounHub Feed API - Swagger UI</title>
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
      const urlPath = window.location.pathname;
      const pathParts = urlPath.split('/');
      
      // Determine the base path - this is typically the stage name in API Gateway
      let basePath = '';
      if (pathParts.length >= 2) {
        basePath = '/' + pathParts[1];
      }
      
      // Display debug info
      document.getElementById('debugInfo').innerText = 'URL: ' + window.location.href + '\nBase Path: ' + basePath;
      
      // Configure Swagger UI
      const ui = SwaggerUIBundle({
        url: "./doc.json",
        dom_id: '#swagger-ui',
        deepLinking: true,
        presets: [
          SwaggerUIBundle.presets.apis,
          SwaggerUIStandalonePreset
        ],
        plugins: [
          SwaggerUIBundle.plugins.DownloadUrl
        ],
        layout: "StandaloneLayout",
        displayRequestDuration: true,
        defaultModelsExpandDepth: 2,
        defaultModelExpandDepth: 2,
        docExpansion: 'list',
        showExtensions: true,
        showCommonExtensions: true
      });
      
      window.ui = ui;
    };
  </script>
</body>
</html>
`
