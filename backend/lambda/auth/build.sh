#!/bin/bash

# Note: Documentation is now embedded in the Lambda function
# No need to generate Swagger docs during build

# Build the Go Lambda function for AWS Lambda (arm64 architecture)
echo "Building Lambda function..."
GOOS=linux GOARCH=arm64 go build -tags lambda.norpc -o bootstrap main.go
chmod +x bootstrap

echo "Build completed successfully."