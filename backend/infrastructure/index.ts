//------------------------------------------------------------
// 1) Basic Configuration and Imports
//------------------------------------------------------------

import * as pulumi from "@pulumi/pulumi";
import * as aws from "@pulumi/aws";
// Import the API documentation module
import * as apiDocs from "./api-docs";
import { createAuthResources } from "./modules/auth";
import * as swaggerHosting from "./swagger-hosting";

const config = new pulumi.Config();
const stack = pulumi.getStack();

// Common tags for all resources
const commonTags = {
    Environment: stack,
    Project: config.name,
    Component: "auth",
    ManagedBy: "pulumi"
};

// Domain configuration
const domainName = "api.nounhub.org";  // Change to use api subdomain

// Create AWS provider for us-east-1 region specifically for ACM certificates
// This is required because ACM certificates used with CloudFront must be in us-east-1
const usEast1Provider = new aws.Provider("us-east-1-provider", {
    region: "us-east-1",
});

//------------------------------------------------------------
// 2) Import and Create Modularized Resources
//------------------------------------------------------------

// Auth resources
const auth = createAuthResources(stack, commonTags);

// Remove the call to createDatabaseResources
// const database = createDatabaseResources(stack, commonTags);

// Insert database resource creation logic here
// Create DynamoDB User Table
const userTable = new aws.dynamodb.Table("user-table", {
    name: `nounhub-user-table-${stack}`,
    attributes: [
        { name: "user_id", type: "S" },
        { name: "email", type: "S" },
    ],
    hashKey: "user_id",
    globalSecondaryIndexes: [
        {
            name: "EmailIndex",
            hashKey: "email",
            projectionType: "ALL",
        }
    ],
    billingMode: "PAY_PER_REQUEST",
    tags: commonTags,
});

// Create DynamoDB Post Table
const postTable = new aws.dynamodb.Table("feed-post-table", {
    name: `nounhub-feed-post-table-${stack}`,
    attributes: [
        { name: "id", type: "S" },
        { name: "author_id", type: "S" },
        { name: "category_id", type: "S" },
        { name: "created_at", type: "S" },
        { name: "original_id", type: "S" },
        { name: "is_repost", type: "N" },
        { name: "collection_type", type: "S" },
    ],
    hashKey: "id",
    globalSecondaryIndexes: [
        {
            name: "AuthorIndex",
            hashKey: "author_id",
            rangeKey: "created_at",
            projectionType: "ALL",
        },
        {
            name: "CategoryIndex",
            hashKey: "category_id",
            rangeKey: "created_at",
            projectionType: "ALL",
        },
        {
            name: "TimeIndex",
            hashKey: "id",
            rangeKey: "created_at",
            projectionType: "ALL",
        },
        {
            name: "RepostIndex",
            hashKey: "original_id",
            rangeKey: "is_repost",
            projectionType: "ALL",
        },
        {
            name: "GlobalCollectionIndex",
            hashKey: "collection_type",
            rangeKey: "created_at",
            projectionType: "ALL",
        }
    ],
    billingMode: "PAY_PER_REQUEST",
    tags: commonTags,
});

// Create DynamoDB Category Table
const categoryTable = new aws.dynamodb.Table("feed-category-table", {
    name: `nounhub-feed-category-table-${stack}`,
    attributes: [
        { name: "id", type: "S" },
        { name: "category_name", type: "S" },
    ],
    hashKey: "id",
    globalSecondaryIndexes: [
        {
            name: "NameIndex",
            hashKey: "category_name",
            projectionType: "ALL",
        }
    ],
    billingMode: "PAY_PER_REQUEST",
    tags: commonTags,
});


//------------------------------------------------------------
// 3) Export Required Values
//------------------------------------------------------------

// Auth exports
export const userPoolId = auth.userPoolId;
export const userPoolClientId = auth.userPoolClientId;
export const adminGroupName = auth.adminGroupName;
export const moderatorGroupName = auth.moderatorGroupName;
export const userPoolDomain = auth.userPoolDomain;
export const userPoolIssuerUrl = auth.userPoolIssuerUrl;

// Database exports - update references
export const userTableName = userTable.name;
export const feedPostTableName = postTable.name;
export const feedCategoryTableName = categoryTable.name;

// Lambda function environment variables
const authLambdaEnvironment = {
    USER_POOL_ID: auth.userPoolId,
    CLIENT_ID: auth.userPoolClientId,
    GOOGLE_CLIENT_ID: config.require("googleClientId"),
    USER_TABLE_NAME: userTable.name,
    ADMIN_GROUP: "admin",
    MODERATOR_GROUP: "moderator",
    INITIAL_ADMIN_EMAIL: "offorsomto50@gmail.com"
};

// Lambda function IAM policy for Cognito
const cognitoPolicy = {
    Version: "2012-10-17",
    Statement: [
        {
            Effect: "Allow",
            Action: [
                "cognito-idp:AdminGetUser",
                "cognito-idp:ListUsersInGroup"
            ],
            Resource: auth.userPoolArn
        }
    ]
};

// Lambda function IAM policy for DynamoDB
const dynamoPolicy = {
    Version: "2012-10-17",
    Statement: [
        {
            Effect: "Allow",
            Action: [
                "dynamodb:GetItem",
                "dynamodb:PutItem",
                "dynamodb:UpdateItem",
                "dynamodb:DeleteItem",
                "dynamodb:Query",
                "dynamodb:Scan"
            ],
            Resource: [
                userTable.arn,
                pulumi.interpolate`${userTable.arn}/index/*`,
                postTable.arn,
                pulumi.interpolate`${postTable.arn}/index/*`,
                categoryTable.arn,
                pulumi.interpolate`${categoryTable.arn}/index/*`
            ]
        }
    ]
};



//------------------------------------------------------------
// 4) Lambda Function Setup
//------------------------------------------------------------

// Create Lambda function for authentication
const authFunction = new aws.lambda.Function("auth-function", {
    name: `nounhub-auth-function-${stack}`,
    runtime: "provided.al2023",
    handler: "bootstrap",
    architectures: ["arm64"],
    role: new aws.iam.Role("auth-lambda-role", {
        name: `nounhub-auth-lambda-role-${stack}`,
        assumeRolePolicy: JSON.stringify({
            Version: "2012-10-17",
            Statement: [{
                Action: "sts:AssumeRole",
                Principal: {
                    Service: "lambda.amazonaws.com"
                },
                Effect: "Allow"
            }]
        })
    }).arn,
    // Compile and package the Go Lambda function during deployment
    code: new pulumi.asset.AssetArchive({
        ".": new pulumi.asset.FileArchive(
            (() => {
                const { execSync } = require("child_process");
                const path = require("path");
                
                // Get the absolute path to the auth directory
                const authDir = path.join(__dirname, "../lambda/go/auth");
                
                // Execute build script
                execSync("chmod +x build.sh && ./build.sh", {
                    cwd: authDir,
                    stdio: "inherit"
                });
                
                // Return the path to the compiled binary
                return authDir;
            })()
        )
    }),
    // Environment variables for Lambda function
    environment: {
        variables: authLambdaEnvironment
    },
    tags: commonTags
});

// Environment variables for feed Lambda function
const feedLambdaEnvironment = {
    USER_POOL_ID: auth.userPoolId,
    FEED_POST_TABLE_NAME: postTable.name,
    FEED_CATEGORY_TABLE_NAME: categoryTable.name,
    ADMIN_GROUP: "admin",
    MODERATOR_GROUP: "moderator"
};

// Create Lambda function for feed
const feedFunction = new aws.lambda.Function("feed-function", {
    name: `nounhub-feed-function-${stack}`,
    runtime: "provided.al2023",
    handler: "bootstrap",
    architectures: ["arm64"],
    role: new aws.iam.Role("feed-lambda-role", {
        name: `nounhub-feed-lambda-role-${stack}`,
        assumeRolePolicy: JSON.stringify({
            Version: "2012-10-17",
            Statement: [{
                Action: "sts:AssumeRole",
                Principal: {
                    Service: "lambda.amazonaws.com"
                },
                Effect: "Allow"
            }]
        })
    }).arn,
    // Compile and package the Go Lambda function during deployment
    code: new pulumi.asset.AssetArchive({
        ".": new pulumi.asset.FileArchive(
            (() => {
                const { execSync } = require("child_process");
                const path = require("path");
                
                // Get the absolute path to the feed directory
                const feedDir = path.join(__dirname, "../lambda/go/feed");
                
                // Execute build script
                execSync("chmod +x build.sh && ./build.sh", {
                    cwd: feedDir,
                    stdio: "inherit"
                });
                
                // Return the path to the compiled binary
                return feedDir;
            })()
        )
    }),
    // Environment variables for Lambda function
    environment: {
        variables: feedLambdaEnvironment
    },
    tags: commonTags
});

//------------------------------------------------------------
// 5) API Gateway Configuration
//------------------------------------------------------------

// Create HTTP API Gateway
// Update CORS configuration to be more permissive
const api = new aws.apigatewayv2.Api("auth-api", {
    name: `nounhub-auth-api-${stack}`,
    protocolType: "HTTP",
    corsConfiguration: {
        allowOrigins: ["*"],
        allowMethods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allowHeaders: ["Content-Type", "Authorization", "Origin", "Accept"],
        exposeHeaders: ["*"],
        maxAge: 300
    },
    tags: commonTags
});

// Create a JWT Authorizer for the API using Cognito User Pool
const jwtAuthorizer = new aws.apigatewayv2.Authorizer("jwt-authorizer", {
    apiId: api.id,
    authorizerType: "JWT",
    name: `nounhub-jwt-authorizer-${stack}`,
    jwtConfiguration: {
        audiences: [auth.userPoolClientId],
        issuer: auth.userPoolIssuerUrl,
    },
    identitySources: ["$request.header.Authorization"],
});

// Create Lambda integration for HTTP API
const authIntegration = new aws.apigatewayv2.Integration("auth-lambda-integration", {
    apiId: api.id,
    integrationType: "AWS_PROXY",
    integrationUri: authFunction.invokeArn,
    integrationMethod: "POST",
    payloadFormatVersion: "2.0",
    timeoutMilliseconds: 30000,
});

// Create Lambda integration for Feed API
const feedIntegration = new aws.apigatewayv2.Integration("feed-lambda-integration", {
    apiId: api.id,
    integrationType: "AWS_PROXY",
    integrationUri: feedFunction.invokeArn,
    integrationMethod: "POST",
    payloadFormatVersion: "2.0",
    timeoutMilliseconds: 30000,
});

// Create routes for all auth endpoints
const authRoutes = [
    // Public routes (no authorization required)
    { path: "/auth/signup", method: "POST", protected: false },
    { path: "/auth/signin", method: "POST", protected: false },
    { path: "/auth/confirm", method: "POST", protected: false },
    { path: "/auth/google", method: "POST", protected: false },
    { path: "/auth/resend-confirmation", method: "POST", protected: false },
    { path: "/auth/forgot-password", method: "POST", protected: false },
    { path: "/auth/confirm-forgot-password", method: "POST", protected: false },
    
    // Protected routes (require authorization)
    { path: "/auth/profile", method: "GET", protected: true },
    { path: "/auth/refresh", method: "POST", protected: true },
    { path: "/auth/signout", method: "POST", protected: true },
    { path: "/auth/groups", method: "GET", protected: true },
    { path: "/auth/groups/{groupName}/users", method: "GET", protected: true },
    { path: "/auth/groups/{groupName}/users/{username}", method: "POST", protected: true },
    { path: "/auth/groups/{groupName}/users/{username}", method: "DELETE", protected: true },
    { path: "/auth/users/{username}/groups", method: "GET", protected: true }
];

// Create routes for all feed endpoints (all protected)
const feedRoutes = [
    { path: "/feed/posts", method: "GET", protected: false },
    { path: "/feed/posts", method: "POST", protected: true },
    { path: "/feed/posts/{id}", method: "GET", protected: false },
    { path: "/feed/posts/{id}", method: "PUT", protected: true },
    { path: "/feed/posts/{id}", method: "DELETE", protected: true },
    { path: "/feed/categories", method: "GET", protected: false },
    { path: "/feed/categories", method: "POST", protected: true },
    { path: "/feed/categories/{id}", method: "PUT", protected: true },
    { path: "/feed/categories/{id}", method: "DELETE", protected: true },
    { path: "/feed/posts/{id}/repost", method: "POST", protected: true },
    { path: "/feed/posts/{id}/comments/{commentId}", method: "DELETE", protected: true }
];

// Create auth routes
authRoutes.forEach((route, index) => {
    const routeOptions: aws.apigatewayv2.RouteArgs = {
        apiId: api.id,
        routeKey: `${route.method} ${route.path}`,
        target: pulumi.interpolate`integrations/${authIntegration.id}`
    };
    
    // Add authorizer to protected routes
    if (route.protected) {
        routeOptions.authorizationType = "JWT";
        routeOptions.authorizerId = jwtAuthorizer.id;
    }
    
    new aws.apigatewayv2.Route(`auth-route-${index}`, routeOptions);
});

// Create feed routes (all protected)
feedRoutes.forEach((route, index) => {
    const routeOptions: aws.apigatewayv2.RouteArgs = {
        apiId: api.id,
        routeKey: `${route.method} ${route.path}`,
        target: pulumi.interpolate`integrations/${feedIntegration.id}`
    };
    
    // Add authorizer to protected routes
    if (route.protected) {
        routeOptions.authorizationType = "JWT";
        routeOptions.authorizerId = jwtAuthorizer.id;
    }
    
    new aws.apigatewayv2.Route(`feed-route-${index}`, routeOptions);
});

// Create stage
const stage = new aws.apigatewayv2.Stage("auth-stage", {
    apiId: api.id,
    name: stack,
    autoDeploy: true,
    tags: commonTags
});

// Add Lambda permission for API Gateway
const lambdaPermission = new aws.lambda.Permission('auth-lambda-permission', {
    action: 'lambda:InvokeFunction',
    function: authFunction.arn,
    principal: 'apigateway.amazonaws.com',
    sourceArn: pulumi.interpolate`${api.executionArn}/*/*/*`
});


// Configure API Gateway to expose Swagger documentation
const swaggerUiUrl = apiDocs.configureApiDocs(api, authIntegration, "auth-", "/auth");

// Add Swagger routes for the feed API as well
apiDocs.configureApiDocs(api, feedIntegration, "feed-", "/feed");

// Export the API documentation URLs for both default API Gateway and custom domain
export const apiDocsUrls = apiDocs.exportDocUrls(api, stack, domainName);

// Export the Swagger UI URL for easy access (for backward compatibility)
export const apiDocsUrl = swaggerUiUrl;

// Setup the consolidated Swagger API documentation with S3 + CloudFront hosting
const swaggerHostingSetup = swaggerHosting.setupSwaggerHosting(
  commonTags,
  api.apiEndpoint,
  stack
);

// Export the CloudFront URL for the consolidated Swagger documentation
export const consolidatedSwaggerUrl = swaggerHostingSetup.swaggerUrl;

//------------------------------------------------------------
// 6) Custom Domain Configuration
//------------------------------------------------------------

// Use an existing certificate (after manual validation)
const certificate = aws.acm.Certificate.get("existing-certificate", 
    config.require("certificateArn"),  // Get the ARN from Pulumi config
    {}, 
    { provider: usEast1Provider }
);

// Create API Gateway domain name with the validated certificate
const apiDomainName = new aws.apigatewayv2.DomainName("api-domain", {
    domainName: domainName,
    domainNameConfiguration: {
        certificateArn: certificate.arn,
        endpointType: "REGIONAL",
        securityPolicy: "TLS_1_2"
    },
    tags: commonTags
});

// Create API mapping to connect the API to the custom domain
const apiMapping = new aws.apigatewayv2.ApiMapping("api-mapping", {
    apiId: api.id,
    domainName: apiDomainName.id,
    stage: stage.id,
    apiMappingKey: stack  // Add the stack as the API mapping key
});

// Export the domain configuration details
export const apiDomainNameTargetDomainName = apiDomainName.domainNameConfiguration.targetDomainName;
export const apiDomainNameHostedZoneId = apiDomainName.domainNameConfiguration.hostedZoneId;

// Update the API endpoint export to include both the default and custom domain
export const customDomainEndpoint = pulumi.interpolate`https://${domainName}/${stack}`;

// Export only the default API Gateway endpoint
export const apiEndpoint = pulumi.interpolate`${api.apiEndpoint}/${stack}`;

// Export JWT Authorizer ID
export const jwtAuthorizerId = jwtAuthorizer.id;

//------------------------------------------------------------
// 5) IAM Role and Policy Configuration
//------------------------------------------------------------

// Create IAM role policy for Auth Lambda
const lambdaRolePolicy = new aws.iam.RolePolicy("auth-lambda-role-policy", {
    name: `nounhub-auth-lambda-role-policy-${stack}`,
    role: authFunction.role.apply(role => role.split("/").pop() as string),
    policy: pulumi.output({
        Version: "2012-10-17",
        Statement: [
            {
                Effect: "Allow",
                Action: [
                    "cognito-idp:SignUp",
                    "cognito-idp:InitiateAuth",
                    "cognito-idp:RespondToAuthChallenge",
                    "cognito-idp:ConfirmSignUp",
                    "cognito-idp:ForgotPassword",
                    "cognito-idp:ConfirmForgotPassword",
                    "cognito-idp:GetUser",
                    "cognito-idp:AdminGetUser",
                    "cognito-idp:UpdateUserAttributes",
                    "cognito-idp:VerifyUserAttribute",
                    "cognito-idp:ResendConfirmationCode",
                    "cognito-idp:ListUsers",
                    "cognito-idp:AdminCreateUser",
                    "cognito-idp:AdminUpdateUserAttributes",
                    "cognito-idp:GlobalSignOut",
                    // Add new permissions for group management
                    "cognito-idp:AdminAddUserToGroup",
                    "cognito-idp:AdminRemoveUserFromGroup",
                    "cognito-idp:AdminListGroupsForUser",
                    "cognito-idp:ListGroups",
                    "cognito-idp:ListUsersInGroup"
                ],
                Resource: auth.userPoolArn
            },
            {
                Effect: "Allow",
                Action: [
                    "dynamodb:PutItem",
                    "dynamodb:GetItem",
                    "dynamodb:UpdateItem",
                    "dynamodb:DeleteItem",
                    "dynamodb:Query",
                    "dynamodb:Scan"
                ],
                Resource: [
                    userTable.arn,
                    pulumi.interpolate`${userTable.arn}/index/*`
                ]
            },
            {
                Effect: "Allow",
                Action: [
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents"
                ],
                Resource: "arn:aws:logs:*:*:*"
            }
        ]
    }).apply(policy => JSON.stringify(policy))
});

// Create IAM role policy for Feed Lambda
const feedLambdaRolePolicy = new aws.iam.RolePolicy("feed-lambda-role-policy", {
    name: `nounhub-feed-lambda-role-policy-${stack}`,
    role: feedFunction.role.apply(role => role.split("/").pop() as string),
    policy: pulumi.output({
        Version: "2012-10-17",
        Statement: [
            {
                Effect: "Allow",
                Action: [
                    "cognito-idp:GetUser",
                    "cognito-idp:AdminGetUser",
                    "cognito-idp:ListUsers",
                    "cognito-idp:ListUsersInGroup"
                ],
                Resource: auth.userPoolArn
            },
            {
                Effect: "Allow",
                Action: [
                    "dynamodb:PutItem",
                    "dynamodb:GetItem",
                    "dynamodb:UpdateItem",
                    "dynamodb:DeleteItem",
                    "dynamodb:Query",
                    "dynamodb:Scan",
                    "dynamodb:BatchGetItem",
                    "dynamodb:BatchWriteItem"
                ],
                Resource: [
                    postTable.arn,
                    pulumi.interpolate`${postTable.arn}/index/*`,
                    categoryTable.arn,
                    pulumi.interpolate`${categoryTable.arn}/index/*`
                ]
            },
            {
                Effect: "Allow",
                Action: [
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents"
                ],
                Resource: "arn:aws:logs:*:*:*"
            }
        ]
    }).apply(policy => JSON.stringify(policy))
});

// Add Lambda permission for Feed API Gateway
const feedLambdaPermission = new aws.lambda.Permission('feed-lambda-permission', {
    action: 'lambda:InvokeFunction',
    function: feedFunction.arn,
    principal: 'apigateway.amazonaws.com',
    sourceArn: pulumi.interpolate`${api.executionArn}/*/*/*`
});
