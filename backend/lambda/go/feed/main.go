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
	"encoding/base64"
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
	ID             string    `json:"id" dynamodbav:"id"`
	Title          string    `json:"title" dynamodbav:"title"`
	Body           string    `json:"body" dynamodbav:"body"`
	AuthorID       string    `json:"author_id" dynamodbav:"author_id"`
	CategoryID     string    `json:"category_id" dynamodbav:"category_id"`
	CreatedAt      time.Time `json:"created_at" dynamodbav:"created_at"`
	UpdatedAt      time.Time `json:"updated_at" dynamodbav:"updated_at"`
	IsRepost       int       `json:"is_repost" dynamodbav:"is_repost"`
	OriginalID     string    `json:"original_id,omitempty" dynamodbav:"original_id,omitempty"`
	RepostType     string    `json:"repost_type,omitempty" dynamodbav:"repost_type,omitempty"` // "repost" or "quote"
	CollectionType string    `json:"collection_type,omitempty" dynamodbav:"collection_type"`   // For GlobalCollectionIndex
}

// Category represents a post category
type Category struct {
	ID           string    `json:"id" dynamodbav:"id"`
	CategoryName string    `json:"name" dynamodbav:"category_name"`
	CreatedAt    time.Time `json:"created_at" dynamodbav:"created_at"`
	UpdatedAt    time.Time `json:"updated_at" dynamodbav:"updated_at"`
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

// RepostRequest represents the request payload for reposting a post
type RepostRequest struct {
	Title      string `json:"title,omitempty" example:"My thoughts on this announcement"`
	Body       string `json:"body,omitempty" example:"This is really important for all students!"`
	CategoryID string `json:"category_id,omitempty" example:"cat-123"`
	RepostType string `json:"repost_type" example:"repost"` // "repost" or "quote"
}

// FeedHandler handles feed operations
type FeedHandler struct {
	dynamodbClient    *dynamodb.Client
	cognitoClient     *cognitoidentityprovider.Client
	postTableName     string
	categoryTableName string
	userPoolID        string
	adminGroup        string
	moderatorGroup    string
}

// Claims represents JWT token claims
type Claims struct {
	Username string          `json:"username"`
	Groups   []string        `json:"cognito:groups"`
	GroupMap map[string]bool `json:"-"` // Won't be marshaled/unmarshaled
	jwt.RegisteredClaims
}

// RepostResponse represents a Post along with its original post if it's a repost
type RepostResponse struct {
	Post         Post  `json:"post"`
	OriginalPost *Post `json:"original_post,omitempty"`
}

func main() {
	ctx := context.Background()

	// Configure AWS SDK - use default config without explicitly setting region
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		log.Fatalf("Failed to load AWS config: %v", err)
	}

	// Initialize DynamoDB client
	dynamodbClient := dynamodb.NewFromConfig(cfg)

	// Initialize Cognito client
	cognitoClient := cognitoidentityprovider.NewFromConfig(cfg)

	// Get environment variables
	postTableName := os.Getenv("FEED_POST_TABLE_NAME")
	categoryTableName := os.Getenv("FEED_CATEGORY_TABLE_NAME")
	userPoolID := os.Getenv("USER_POOL_ID")
	adminGroup := os.Getenv("ADMIN_GROUP")
	moderatorGroup := os.Getenv("MODERATOR_GROUP")

	// Create handler
	handler := &FeedHandler{
		dynamodbClient:    dynamodbClient,
		cognitoClient:     cognitoClient,
		postTableName:     postTableName,
		categoryTableName: categoryTableName,
		userPoolID:        userPoolID,
		adminGroup:        adminGroup,
		moderatorGroup:    moderatorGroup,
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

	// Extract user claims from JWT token - no need to validate as API Gateway JWT Authorizer already did
	var claims *Claims
	if authHeader, ok := request.Headers["authorization"]; ok {
		token := strings.TrimPrefix(authHeader, "Bearer ")
		// Just parse the claims without validation since JWT Authorizer already validated the token
		parser := jwt.NewParser()
		parsedToken, _, err := parser.ParseUnverified(token, &Claims{})
		if err == nil {
			if c, ok := parsedToken.Claims.(*Claims); ok {
				// Initialize the GroupMap from the Groups array for O(1) lookups
				c.GroupMap = make(map[string]bool)
				for _, group := range c.Groups {
					c.GroupMap[group] = true
				}
				claims = c
			}
		}
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

// Check if the user is an admin
func isAdmin(claims *Claims) bool {
	if claims == nil {
		return false
	}

	return claims.GroupMap["admin"]
}

// Check if the user is a moderator
func isModerator(claims *Claims) bool {
	if claims == nil {
		return false
	}

	return claims.GroupMap["moderator"] || claims.GroupMap["admin"]
}

// @Summary Get all posts
// @Description Retrieve a list of posts, optionally filtered by category or author
// @Tags Posts
// @Accept json
// @Produce json
// @Param category_id query string false "Filter by category ID"
// @Param author_id query string false "Filter by author ID"
// @Param limit query int false "Limit the number of results (default 20)"
// @Param next_token query string false "Pagination token for the next page"
// @Success 200 {object} APIResponse{data=[]Post} "Successful operation"
// @Failure 500 {object} APIResponse "Server error"
// @Router /posts [get]
func (h *FeedHandler) handleGetPosts(ctx context.Context, request events.APIGatewayV2HTTPRequest, _ *Claims) (events.APIGatewayV2HTTPResponse, error) {
	// Get query parameters
	categoryID := request.QueryStringParameters["category"]
	authorID := request.QueryStringParameters["author"]
	nextToken := request.QueryStringParameters["next_token"]
	limit := 20 // Default limit

	// Parse limit if provided
	if limitStr, ok := request.QueryStringParameters["limit"]; ok {
		if parsedLimit, err := fmt.Sscanf(limitStr, "%d", &limit); err != nil || parsedLimit <= 0 {
			limit = 20 // Reset to default if parsing fails or if the limit is invalid
		}
	}

	// If limit is too high, cap it at 100
	if limit > 100 {
		limit = 100
	}

	// Prepare the query
	var queryInput *dynamodb.QueryInput
	var exclusiveStartKey map[string]ddbTypes.AttributeValue

	// Parse the pagination token if provided
	if nextToken != "" {
		var tokenErr error
		exclusiveStartKey, tokenErr = parseNextToken(nextToken)
		if tokenErr != nil {
			log.Printf("Error parsing pagination token: %v", tokenErr)
			return sendAPIResponse(400, false, "", nil, "Invalid pagination token"), nil
		}
	}

	// If filtering by category
	if categoryID != "" {
		// Query by category using CategoryIndex
		queryInput = &dynamodb.QueryInput{
			TableName:              aws.String(h.postTableName),
			IndexName:              aws.String("CategoryIndex"),
			KeyConditionExpression: aws.String("category_id = :catId"),
			ExpressionAttributeValues: map[string]ddbTypes.AttributeValue{
				":catId": &ddbTypes.AttributeValueMemberS{Value: categoryID},
			},
			ScanIndexForward:  aws.Bool(false), // Descending order (newest first)
			Limit:             aws.Int32(int32(limit)),
			ExclusiveStartKey: exclusiveStartKey,
		}
	} else if authorID != "" {
		// Query by author using AuthorIndex
		queryInput = &dynamodb.QueryInput{
			TableName:              aws.String(h.postTableName),
			IndexName:              aws.String("AuthorIndex"),
			KeyConditionExpression: aws.String("author_id = :authorId"),
			ExpressionAttributeValues: map[string]ddbTypes.AttributeValue{
				":authorId": &ddbTypes.AttributeValueMemberS{Value: authorID},
			},
			ScanIndexForward:  aws.Bool(false), // Descending order (newest first)
			Limit:             aws.Int32(int32(limit)),
			ExclusiveStartKey: exclusiveStartKey,
		}
	} else {
		// Use GlobalCollectionIndex to get all posts with efficient pagination
		queryInput = &dynamodb.QueryInput{
			TableName:              aws.String(h.postTableName),
			IndexName:              aws.String("GlobalCollectionIndex"),
			KeyConditionExpression: aws.String("collection_type = :collection"),
			ExpressionAttributeValues: map[string]ddbTypes.AttributeValue{
				":collection": &ddbTypes.AttributeValueMemberS{Value: "ALL"},
			},
			ScanIndexForward:  aws.Bool(false), // Descending order (newest first)
			Limit:             aws.Int32(int32(limit)),
			ExclusiveStartKey: exclusiveStartKey,
		}
	}

	// Execute the query
	queryOutput, err := h.dynamodbClient.Query(ctx, queryInput)
	if err != nil {
		log.Printf("Error querying posts: %v", err)
		return sendAPIResponse(500, false, "", nil, "Error retrieving posts"), nil
	}

	// Unmarshal the results
	var posts []Post
	err = attributevalue.UnmarshalListOfMaps(queryOutput.Items, &posts)
	if err != nil {
		log.Printf("Error unmarshaling posts: %v", err)
		return sendAPIResponse(500, false, "", nil, "Error processing posts"), nil
	}

	// Process reposts to include original post information
	var postsResponse []interface{}
	originalPostIds := make(map[string]bool)

	// First, collect all original post IDs
	for _, post := range posts {
		if post.IsRepost > 0 && post.OriginalID != "" {
			originalPostIds[post.OriginalID] = true
		}
	}

	// If there are reposts, fetch all the original posts in one batch
	originalPosts := make(map[string]Post)
	if len(originalPostIds) > 0 {
		keys := make([]map[string]ddbTypes.AttributeValue, 0, len(originalPostIds))
		for id := range originalPostIds {
			keys = append(keys, map[string]ddbTypes.AttributeValue{
				"id": &ddbTypes.AttributeValueMemberS{Value: id},
			})
		}

		// Batch get the original posts
		batchGetOutput, err := h.dynamodbClient.BatchGetItem(ctx, &dynamodb.BatchGetItemInput{
			RequestItems: map[string]ddbTypes.KeysAndAttributes{
				h.postTableName: {
					Keys: keys,
				},
			},
		})

		if err == nil && len(batchGetOutput.Responses[h.postTableName]) > 0 {
			var fetchedOriginalPosts []Post
			err = attributevalue.UnmarshalListOfMaps(batchGetOutput.Responses[h.postTableName], &fetchedOriginalPosts)
			if err == nil {
				for _, op := range fetchedOriginalPosts {
					originalPosts[op.ID] = op
				}
			}
		}
	}

	// Now create the response with original post information where applicable
	for _, post := range posts {
		if post.IsRepost > 0 && post.OriginalID != "" {
			// If we have the original post, include it
			originalPost, exists := originalPosts[post.OriginalID]
			if exists {
				postsResponse = append(postsResponse, RepostResponse{
					Post:         post,
					OriginalPost: &originalPost,
				})
			} else {
				// If we don't have the original post, still include the repost
				postsResponse = append(postsResponse, RepostResponse{
					Post: post,
				})
			}
		} else {
			// For regular posts, just include the post
			postsResponse = append(postsResponse, post)
		}
	}

	// Create the response
	response := map[string]interface{}{
		"posts": postsResponse,
	}

	// Add pagination token if there are more results
	if len(queryOutput.LastEvaluatedKey) > 0 {
		nextToken, err := createNextToken(queryOutput.LastEvaluatedKey)
		if err == nil {
			response["next_token"] = nextToken
		}
	}

	return sendAPIResponse(200, true, "Posts retrieved successfully", response, ""), nil
}

// Helper function to create a pagination token from LastEvaluatedKey
func createNextToken(lastEvaluatedKey map[string]ddbTypes.AttributeValue) (string, error) {
	// Convert the LastEvaluatedKey to JSON and base64 encode it
	jsonBytes, err := json.Marshal(lastEvaluatedKey)
	if err != nil {
		return "", err
	}

	// Base64 encode the JSON
	token := base64.StdEncoding.EncodeToString(jsonBytes)
	return token, nil
}

// Helper function to parse a pagination token back to ExclusiveStartKey
func parseNextToken(nextToken string) (map[string]ddbTypes.AttributeValue, error) {
	// Base64 decode the token
	jsonBytes, err := base64.StdEncoding.DecodeString(nextToken)
	if err != nil {
		return nil, err
	}

	// Unmarshal the JSON to a map
	var exclusiveStartKey map[string]ddbTypes.AttributeValue
	err = json.Unmarshal(jsonBytes, &exclusiveStartKey)
	if err != nil {
		return nil, err
	}

	return exclusiveStartKey, nil
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
func (h *FeedHandler) handleGetPost(ctx context.Context, request events.APIGatewayV2HTTPRequest, _ *Claims) (events.APIGatewayV2HTTPResponse, error) {
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

	// If this is a repost, get the original post details
	if post.IsRepost > 0 && post.OriginalID != "" {
		originalPostOutput, err := h.dynamodbClient.GetItem(ctx, &dynamodb.GetItemInput{
			TableName: aws.String(h.postTableName),
			Key: map[string]ddbTypes.AttributeValue{
				"id": &ddbTypes.AttributeValueMemberS{Value: post.OriginalID},
			},
		})

		// Create a response structure with both the repost and original post
		repostResponse := RepostResponse{
			Post: post,
		}

		// Only include the original post if it exists and can be unmarshaled
		if err == nil && originalPostOutput.Item != nil && len(originalPostOutput.Item) > 0 {
			var originalPost Post
			err = attributevalue.UnmarshalMap(originalPostOutput.Item, &originalPost)
			if err == nil {
				repostResponse.OriginalPost = &originalPost
			} else {
				log.Printf("Error unmarshaling original post: %v", err)
			}
		} else if err != nil {
			log.Printf("Error retrieving original post: %v", err)
		}

		return sendAPIResponse(200, true, "Post retrieved successfully", repostResponse, ""), nil
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
		ID:             uuid.New().String(),
		Title:          createPostReq.Title,
		Body:           createPostReq.Body,
		AuthorID:       claims.Username,
		CategoryID:     createPostReq.CategoryID,
		CreatedAt:      now,
		UpdatedAt:      now,
		IsRepost:       0,
		OriginalID:     "",
		RepostType:     "",
		CollectionType: "ALL", // Set the collection type for the GSI
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
		// Check if the author is an admin using their claims
		authorClaims := claims
		if authorClaims != nil && isAdmin(authorClaims) {
			return sendAPIResponse(403, false, "", nil, "Moderators cannot edit posts created by admins"), nil
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
		// Check if the author is an admin using their claims
		authorClaims := claims
		if authorClaims != nil && isAdmin(authorClaims) {
			return sendAPIResponse(403, false, "", nil, "Moderators cannot delete posts created by admins"), nil
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
func (h *FeedHandler) handleGetCategories(ctx context.Context, _ events.APIGatewayV2HTTPRequest, _ *Claims) (events.APIGatewayV2HTTPResponse, error) {
	// Check if DynamoDB client is properly initialized
	if h.dynamodbClient == nil {
		log.Printf("Error: DynamoDB client is nil")
		return sendAPIResponse(500, false, "", nil, "DynamoDB client configuration error"), nil
	}

	// Query categories using the NameIndex
	queryInput := &dynamodb.QueryInput{
		TableName:              aws.String(h.categoryTableName),
		IndexName:              aws.String("NameIndex"),
		KeyConditionExpression: aws.String("category_name > :emptyString"),
		ExpressionAttributeValues: map[string]ddbTypes.AttributeValue{
			":emptyString": &ddbTypes.AttributeValueMemberS{Value: ""},
		},
	}

	queryOutput, err := h.dynamodbClient.Query(ctx, queryInput)
	if err != nil {
		log.Printf("Error querying categories: %v", err)
		return sendAPIResponse(500, false, "", nil, "Error retrieving categories"), nil
	}

	var categories []Category
	err = attributevalue.UnmarshalListOfMaps(queryOutput.Items, &categories)
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
	log.Printf("Checking category existence: Table=%s, Index=%s, Name=%s", h.categoryTableName, "NameIndex", createCategoryReq.Name)
	queryOutput, err := h.dynamodbClient.Query(ctx, &dynamodb.QueryInput{
		TableName:              aws.String(h.categoryTableName),
		IndexName:              aws.String("NameIndex"),
		KeyConditionExpression: aws.String("category_name = :name"),
		ExpressionAttributeValues: map[string]ddbTypes.AttributeValue{
			":name": &ddbTypes.AttributeValueMemberS{Value: createCategoryReq.Name},
		},
	})

	if err != nil {
		log.Printf("Detailed error checking category existence: %+v", err)
		return sendAPIResponse(500, false, "", nil, "Error validating category name"), nil
	}

	if len(queryOutput.Items) > 0 {
		return sendAPIResponse(400, false, "", nil, "Category with this name already exists"), nil
	}

	// Create a new category
	now := time.Now()
	category := Category{
		ID:           uuid.New().String(),
		CategoryName: createCategoryReq.Name,
		CreatedAt:    now,
		UpdatedAt:    now,
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
			KeyConditionExpression: aws.String("category_name = :name"),
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
	category.CategoryName = updateCategoryReq.Name
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

// @Summary Repost a post
// @Description Create a new post that references an existing post (repost or quote)
// @Tags Posts
// @Accept json
// @Produce json
// @Param id path string true "Post ID to repost"
// @Param repost body RepostRequest true "Repost information"
// @Security BearerAuth
// @Success 201 {object} APIResponse{data=Post} "Repost created"
// @Failure 400 {object} APIResponse "Invalid input"
// @Failure 401 {object} APIResponse "Unauthorized"
// @Failure 403 {object} APIResponse "Forbidden - not admin or moderator"
// @Failure 404 {object} APIResponse "Original post not found"
// @Failure 500 {object} APIResponse "Server error"
// @Router /posts/{id}/repost [post]
func (h *FeedHandler) handleRepostPost(ctx context.Context, request events.APIGatewayV2HTTPRequest, claims *Claims) (events.APIGatewayV2HTTPResponse, error) {
	// All authenticated users can repost
	if claims == nil {
		return sendAPIResponse(401, false, "", nil, "Authentication required"), nil
	}

	// Check if user is a moderator or admin
	if !isModerator(claims) {
		return sendAPIResponse(403, false, "", nil, "Only moderators and admins can repost posts"), nil
	}

	// Extract post ID from path
	parts := strings.Split(request.RequestContext.HTTP.Path, "/")
	if len(parts) < 4 {
		return sendAPIResponse(400, false, "", nil, "Invalid path format"), nil
	}

	postID := parts[len(parts)-2] // Format: /feed/posts/{id}/repost

	// Get the original post from DynamoDB
	getItemOutput, err := h.dynamodbClient.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(h.postTableName),
		Key: map[string]ddbTypes.AttributeValue{
			"id": &ddbTypes.AttributeValueMemberS{Value: postID},
		},
	})

	if err != nil {
		log.Printf("Error getting original post: %v", err)
		return sendAPIResponse(500, false, "", nil, "Error retrieving original post"), nil
	}

	if getItemOutput.Item == nil {
		return sendAPIResponse(404, false, "", nil, "Original post not found"), nil
	}

	// Unmarshal the original post
	var originalPost Post
	err = attributevalue.UnmarshalMap(getItemOutput.Item, &originalPost)
	if err != nil {
		log.Printf("Error unmarshaling original post: %v", err)
		return sendAPIResponse(500, false, "", nil, "Error processing original post"), nil
	}

	// Parse request body for repost details
	var repostReq RepostRequest
	if err := json.Unmarshal([]byte(request.Body), &repostReq); err != nil {
		return sendAPIResponse(400, false, "", nil, "Invalid request body"), nil
	}

	// Validate repost type
	if repostReq.RepostType != "repost" && repostReq.RepostType != "quote" {
		return sendAPIResponse(400, false, "", nil, "Invalid repost type. Must be 'repost' or 'quote'"), nil
	}

	// For quote reposts, require title and body
	if repostReq.RepostType == "quote" && (repostReq.Title == "" || repostReq.Body == "") {
		return sendAPIResponse(400, false, "", nil, "Title and body are required for quote reposts"), nil
	}

	// Get category ID - use the original post's category if not specified
	categoryID := originalPost.CategoryID
	if repostReq.CategoryID != "" {
		// If a category is specified, verify it exists
		categoryExists, err := h.categoryExists(ctx, repostReq.CategoryID)
		if err != nil {
			log.Printf("Error checking category: %v", err)
			return sendAPIResponse(500, false, "", nil, "Error validating category"), nil
		}

		if !categoryExists {
			return sendAPIResponse(400, false, "", nil, "Invalid category"), nil
		}
		categoryID = repostReq.CategoryID
	}

	// Create the repost
	now := time.Now()
	repost := Post{
		ID:             uuid.New().String(),
		AuthorID:       claims.Username,
		CategoryID:     categoryID,
		CreatedAt:      now,
		UpdatedAt:      now,
		IsRepost:       1, // 1 for true (repost)
		OriginalID:     postID,
		RepostType:     repostReq.RepostType,
		CollectionType: "ALL", // Set the collection type for the GSI
	}

	// Handle content based on repost type
	if repostReq.RepostType == "repost" {
		// For pure reposts, leave title and body empty
		// This is true Twitter-style where we only store a reference to the original
		repost.Title = ""
		repost.Body = ""
	} else {
		// For quote reposts, use the provided content (this is like Twitter's quote tweet)
		repost.Title = repostReq.Title
		repost.Body = repostReq.Body
	}

	// Marshal the repost
	repostItem, err := attributevalue.MarshalMap(repost)
	if err != nil {
		log.Printf("Error marshaling repost: %v", err)
		return sendAPIResponse(500, false, "", nil, "Error creating repost"), nil
	}

	// Save the repost to DynamoDB
	_, err = h.dynamodbClient.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(h.postTableName),
		Item:      repostItem,
	})

	if err != nil {
		log.Printf("Error saving repost: %v", err)
		return sendAPIResponse(500, false, "", nil, "Error saving repost"), nil
	}

	return sendAPIResponse(201, true, "Post reposted successfully", repost, ""), nil
}

// handleSwaggerRequest handles requests for Swagger documentation
func (h *FeedHandler) handleSwaggerRequest(_ context.Context, request events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
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
