import * as pulumi from "@pulumi/pulumi";
import * as aws from "@pulumi/aws";

// Configuration for API documentation
const config = new pulumi.Config();
const stack = pulumi.getStack();

/**
 * Configure API Gateway to expose the Swagger documentation
 * 
 * @param api The API Gateway instance
 * @param integration The Lambda integration
 * @returns The URL to the Swagger UI
 */
export function configureApiDocs(
    api: aws.apigatewayv2.Api,
    integration: aws.apigatewayv2.Integration
): pulumi.Output<string> {
    // Create route for Swagger UI
    const swaggerRoute = new aws.apigatewayv2.Route("swagger-ui-route", {
        apiId: api.id,
        routeKey: "GET /swagger/{proxy+}",
        target: pulumi.interpolate`integrations/${integration.id}`
    });

    // Create route for Swagger JSON
    const swaggerJsonRoute = new aws.apigatewayv2.Route("swagger-json-route", {
        apiId: api.id,
        routeKey: "GET /swagger/doc.json",
        target: pulumi.interpolate`integrations/${integration.id}`
    });

    // Create route for Swagger YAML
    const swaggerYamlRoute = new aws.apigatewayv2.Route("swagger-yaml-route", {
        apiId: api.id,
        routeKey: "GET /swagger/doc.yaml",
        target: pulumi.interpolate`integrations/${integration.id}`
    });

    // Create a dedicated route for the Swagger index page
    const swaggerIndexRoute = new aws.apigatewayv2.Route("swagger-index-route", {
        apiId: api.id,
        routeKey: "GET /swagger/index.html",
        target: pulumi.interpolate`integrations/${integration.id}`
    });

    // Return the Swagger UI URL
    return pulumi.interpolate`${api.apiEndpoint}/${stack}/swagger/index.html`;
}

/**
 * Export documentation URLs for both custom domain and default API Gateway
 * 
 * @param api The API Gateway instance
 * @param stage The deployment stage name
 * @param customDomain Optional custom domain name
 * @returns Object containing Swagger documentation URLs
 */
export function exportDocUrls(
    api: aws.apigatewayv2.Api, 
    stage: string,
    customDomain?: string
): pulumi.Output<{
    apiGatewayUrl: string;
    customDomainUrl?: string;
    jsonDocUrl: string;
}> {
    const apiGatewayUrl = pulumi.interpolate`${api.apiEndpoint}/${stage}/swagger/index.html`;
    const jsonDocUrl = pulumi.interpolate`${api.apiEndpoint}/${stage}/swagger/doc.json`;
    
    // If custom domain is provided, include it in the output
    if (customDomain) {
        const customDomainUrl = pulumi.interpolate`https://${customDomain}/${stage}/swagger/index.html`;
        return pulumi.output({
            apiGatewayUrl,
            customDomainUrl,
            jsonDocUrl,
        });
    }
    
    return pulumi.output({
        apiGatewayUrl,
        jsonDocUrl,
    });
} 