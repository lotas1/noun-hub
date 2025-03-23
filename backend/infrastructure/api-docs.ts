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
 * @param prefix Optional prefix for route names to avoid conflicts when configuring multiple integrations
 * @param servicePath Optional service path prefix (e.g., "/auth", "/feed") to make route paths unique
 * @returns The URL to the Swagger UI
 */
export function configureApiDocs(
    api: aws.apigatewayv2.Api,
    integration: aws.apigatewayv2.Integration,
    prefix?: string,
    servicePath?: string
): pulumi.Output<string> {
    const routePrefix = prefix || '';
    const pathPrefix = servicePath || '';
    
    // Create route for Swagger UI
    const swaggerRoute = new aws.apigatewayv2.Route(`${routePrefix}swagger-ui-route`, {
        apiId: api.id,
        routeKey: `GET ${pathPrefix}/swagger/{proxy+}`,
        target: pulumi.interpolate`integrations/${integration.id}`
    });

    // Create route for Swagger JSON
    const swaggerJsonRoute = new aws.apigatewayv2.Route(`${routePrefix}swagger-json-route`, {
        apiId: api.id,
        routeKey: `GET ${pathPrefix}/swagger/doc.json`,
        target: pulumi.interpolate`integrations/${integration.id}`
    });

    // Create route for Swagger YAML
    const swaggerYamlRoute = new aws.apigatewayv2.Route(`${routePrefix}swagger-yaml-route`, {
        apiId: api.id,
        routeKey: `GET ${pathPrefix}/swagger/doc.yaml`,
        target: pulumi.interpolate`integrations/${integration.id}`
    });

    // Create a dedicated route for the Swagger index page
    const swaggerIndexRoute = new aws.apigatewayv2.Route(`${routePrefix}swagger-index-route`, {
        apiId: api.id,
        routeKey: `GET ${pathPrefix}/swagger/index.html`,
        target: pulumi.interpolate`integrations/${integration.id}`
    });

    // Return the Swagger UI URL
    return pulumi.interpolate`${api.apiEndpoint}/${stack}${pathPrefix}/swagger/index.html`;
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
    serviceUrls: {
        auth: string;
        feed: string;
    };
}> {
    // Main API Gateway endpoint URL for auth docs
    const authApiGatewayUrl = pulumi.interpolate`${api.apiEndpoint}/${stage}/auth/swagger/index.html`;
    const feedApiGatewayUrl = pulumi.interpolate`${api.apiEndpoint}/${stage}/feed/swagger/index.html`;
    
    // Service-specific JSON docs
    const authJsonDocUrl = pulumi.interpolate`${api.apiEndpoint}/${stage}/auth/swagger/doc.json`;
    const feedJsonDocUrl = pulumi.interpolate`${api.apiEndpoint}/${stage}/feed/swagger/doc.json`;
    
    // Build the result object with service-specific URLs
    const serviceUrls = {
        auth: authJsonDocUrl,
        feed: feedJsonDocUrl
    };
    
    // If custom domain is provided, include it in the output
    if (customDomain) {
        const authCustomDomainUrl = pulumi.interpolate`https://${customDomain}/${stage}/auth/swagger/index.html`;
        const feedCustomDomainUrl = pulumi.interpolate`https://${customDomain}/${stage}/feed/swagger/index.html`;
        
        return pulumi.output({
            apiGatewayUrl: authApiGatewayUrl, // Use auth as the default for backward compatibility
            customDomainUrl: authCustomDomainUrl,
            serviceUrls
        });
    }
    
    return pulumi.output({
        apiGatewayUrl: authApiGatewayUrl,
        serviceUrls
    });
} 