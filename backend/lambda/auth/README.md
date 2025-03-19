# NounHub Authentication API Documentation

The NounHub Authentication API provides user authentication and account management services. The API is documented using OpenAPI/Swagger annotations directly in the codebase, making it easy to keep documentation up-to-date and accurate.

## Accessing the API Documentation Online

After deploying the API using Pulumi, the Swagger documentation is automatically available at:

- **API Gateway URL**: The documentation is available at `https://<api-gateway-url>/<stage>/swagger/index.html`
- **Custom Domain URL**: If you're using a custom domain, the documentation is available at `https://api.nounhub.org/<stage>/swagger/index.html`

The URLs are also exported as Pulumi outputs after deployment:

```bash
Outputs:
  + apiDocsUrls: {
      + apiGatewayUrl : "https://abcdefg123.execute-api.us-east-1.amazonaws.com/dev/swagger/index.html"
      + customDomainUrl: "https://api.nounhub.org/dev/swagger/index.html"
      + jsonDocUrl     : "https://abcdefg123.execute-api.us-east-1.amazonaws.com/dev/swagger/doc.json"
    }
```

The documentation includes:

- Detailed descriptions of all endpoints
- Request and response schemas with examples
- Authentication requirements
- Error responses

## Authentication

This API uses JWT token authentication. To use authenticated endpoints:

1. First, create an account or sign in using `/auth/signup` or `/auth/signin`
2. Use the returned access token in subsequent requests with the Authorization header: `Bearer <token>`

## Adding or Updating Documentation

The documentation is generated from annotations in the Go code:

1. Add or update Swagger annotations in the Go code
2. The documentation is automatically regenerated during deployment
3. No manual steps are required to update the documentation

## Documentation Format

The API documentation follows the OpenAPI 3.0 specification and includes:

- Endpoint descriptions and purpose
- Request parameters and body schemas
- Response schemas with examples
- Error codes and descriptions
- Authentication requirements

## Deployment

The API is deployed as an AWS Lambda function with API Gateway integration. Deployment is managed through Pulumi infrastructure as code.

## Available Environments

The API documentation is available in the following environments:

- **Development (dev)**: For development and testing
- **Staging (stage)**: For pre-production testing
- **Production (prod)**: The live production environment

Access the documentation for each environment by replacing `<stage>` in the URL with the appropriate environment name. 