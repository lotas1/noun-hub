package main

import (
	"github.com/aws/aws-lambda-go/lambda"
)

// type Response struct {
// 	Message string `json:"message"`
// }

func handler() (string, error) {
	return "Bye You World", nil
}

func main() {
	lambda.Start(handler)
}
