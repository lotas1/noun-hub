#!/bin/bash

# Generate Swagger documentation
echo "Generating Swagger documentation..."
if ! command -v ~/go/bin/swag &> /dev/null; then
    echo "Installing swag..."
    go install github.com/swaggo/swag/cmd/swag@latest
fi
~/go/bin/swag init

# Build the Go Lambda function for AWS Lambda (arm64 architecture)
echo "Building Lambda function..."
GOOS=linux GOARCH=arm64 go build -tags lambda.norpc -o bootstrap main.go
chmod +x bootstrap

echo "Build completed successfully."