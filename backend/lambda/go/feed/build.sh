#!/bin/bash

# Exit on any error
set -e

# Generate Swagger documentation
echo "Generating Swagger documentation..."
if ! command -v ~/go/bin/swag &> /dev/null; then
    echo "Installing swag..."
    go install github.com/swaggo/swag/cmd/swag@latest
fi
~/go/bin/swag init

# Define variables
OUTPUT_NAME="bootstrap"
GOOS=linux
GOARCH=arm64

echo "Building Feed Lambda function..."

# Clean any previous builds
rm -f ${OUTPUT_NAME}

# Build the function for AWS Lambda with ARM64
GOOS=${GOOS} GOARCH=${GOARCH} go build -tags lambda.norpc -o ${OUTPUT_NAME} .

echo "Build successful: ${OUTPUT_NAME}"

# Set permissions
chmod +x ${OUTPUT_NAME}

# Make the build script executable
chmod +x build.sh 