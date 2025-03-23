#!/bin/bash

# Exit on any error
set -e

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