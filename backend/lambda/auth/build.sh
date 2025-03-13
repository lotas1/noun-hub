#!/bin/bash

set -e

GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o bootstrap main.go
chmod +x bootstrap