//------------------------------------------------------------
// 1) Basic Configuration and Imports
//------------------------------------------------------------

import * as pulumi from "@pulumi/pulumi";
import * as aws from "@pulumi/aws";
import * as awsx from "@pulumi/awsx";
// Import the API documentation module
import * as apiDocs from "./api-docs";

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
// 2) Cognito User Pool Setup
//------------------------------------------------------------

// Create Cognito User Pool
const userPool = new aws.cognito.UserPool("auth-userpool", {
    name: `nounhub-auth-userpool-${stack}`,
    
    // Custom attributes
    schemas: [
        {
            name: "auth_method",
            attributeDataType: "String",
            required: false,
            mutable: true,
            stringAttributeConstraints: {
                minLength: "1",
                maxLength: "10"
            }
        },
        {
            name: "linked_providers",
            attributeDataType: "String",
            required: false,
            mutable: true,
            stringAttributeConstraints: {
                minLength: "0",
                maxLength: "50"
            }
        }
    ],

    // Password policy
    passwordPolicy: {
        minimumLength: 6,
    },

    // Email configuration
    emailConfiguration: {
        emailSendingAccount: "COGNITO_DEFAULT"
    },

    // Account recovery settings
    accountRecoverySetting: {
        recoveryMechanisms: [{
            name: "verified_email",
            priority: 1
        }]
    },

    // Auto verification
    autoVerifiedAttributes: ["email"],

    // User pool policies
    adminCreateUserConfig: {
        allowAdminCreateUserOnly: false
    },

    tags: commonTags
});

// Create User Pool Client
const userPoolClient = new aws.cognito.UserPoolClient("auth-userpool-client", {
    name: `nounhub-auth-userpool-client-${stack}`,
    userPoolId: userPool.id,
    
    // Token validity
    accessTokenValidity: 24, // 24 hours
    idTokenValidity: 24, // 24 hours
    refreshTokenValidity: 365, // 365 days
    tokenValidityUnits: {
        accessToken: "hours",
        idToken: "hours",
        refreshToken: "days"
    },

    // Device tracking
    preventUserExistenceErrors: "ENABLED",
    
    // OAuth settings
    allowedOauthFlows: ["code"],
    allowedOauthFlowsUserPoolClient: true,
    allowedOauthScopes: ["email", "openid", "profile"],
    supportedIdentityProviders: ["COGNITO"],

    // Prevent client secret generation
    generateSecret: false,

    // Callback URLs
    // Update Callback URLs to use the frontend domain
    callbackUrls: [`https://nounhub.org/${stack}/auth/callback`],
    logoutUrls: [`https://nounhub.org/${stack}/auth/logout`],

    // Token revocation
    enableTokenRevocation: true,

    // Rate limits
    explicitAuthFlows: [
        "ALLOW_USER_SRP_AUTH",
        "ALLOW_REFRESH_TOKEN_AUTH",
        "ALLOW_USER_PASSWORD_AUTH",
        "ALLOW_CUSTOM_AUTH"  // Add this line
    ]
});

// Export the User Pool ID and Client ID
export const userPoolId = userPool.id;
export const userPoolClientId = userPoolClient.id;

// Create Cognito User Groups
const adminGroup = new aws.cognito.UserGroup("admin-group", {
    userPoolId: userPool.id,
    name: "admin",
    description: "System administrators group",
    precedence: 1
});

const moderatorGroup = new aws.cognito.UserGroup("moderator-group", {
    userPoolId: userPool.id,
    name: "moderator",
    description: "Content moderators group",
    precedence: 50
});

// Export group names for Lambda function
export const adminGroupName = adminGroup.name;
export const moderatorGroupName = moderatorGroup.name;

//------------------------------------------------------------
// 3) DynamoDB User Table
//------------------------------------------------------------

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
            readCapacity: 5,
            writeCapacity: 5,
        }
    ],
    billingMode: "PROVISIONED",
    readCapacity: 5,
    writeCapacity: 5,
    tags: commonTags,
});

// Export the DynamoDB table name
export const userTableName = userTable.name;

//------------------------------------------------------------
// 3.1) DynamoDB Feed Tables
//------------------------------------------------------------

// Create DynamoDB Post Table
const postTable = new aws.dynamodb.Table("post-table", {
    name: `nounhub-post-table-${stack}`,
    attributes: [
        { name: "id", type: "S" },
        { name: "author_id", type: "S" },
        { name: "category_id", type: "S" },
        { name: "created_at", type: "S" },
    ],
    hashKey: "id",
    globalSecondaryIndexes: [
        {
            name: "AuthorIndex",
            hashKey: "author_id",
            rangeKey: "created_at",
            projectionType: "ALL",
            readCapacity: 5,
            writeCapacity: 5,
        },
        {
            name: "CategoryIndex",
            hashKey: "category_id",
            rangeKey: "created_at",
            projectionType: "ALL",
            readCapacity: 5,
            writeCapacity: 5,
        },
        {
            name: "TimeIndex",
            hashKey: "id", // Not used, just a placeholder
            rangeKey: "created_at",
            projectionType: "ALL",
            readCapacity: 5,
            writeCapacity: 5,
        }
    ],
    billingMode: "PROVISIONED",
    readCapacity: 5,
    writeCapacity: 5,
    tags: commonTags,
});

// Create DynamoDB Category Table
const categoryTable = new aws.dynamodb.Table("category-table", {
    name: `nounhub-category-table-${stack}`,
    attributes: [
        { name: "id", type: "S" },
        { name: "name", type: "S" },
    ],
    hashKey: "id",
    globalSecondaryIndexes: [
        {
            name: "NameIndex",
            hashKey: "name",
            projectionType: "ALL",
            readCapacity: 2,
            writeCapacity: 2,
        }
    ],
    billingMode: "PROVISIONED",
    readCapacity: 2,
    writeCapacity: 2,
    tags: commonTags,
});

// Create DynamoDB Attachment Table
const attachmentTable = new aws.dynamodb.Table("attachment-table", {
    name: `nounhub-attachment-table-${stack}`,
    attributes: [
        { name: "id", type: "S" },
        { name: "post_id", type: "S" },
    ],
    hashKey: "id",
    globalSecondaryIndexes: [
        {
            name: "PostIndex",
            hashKey: "post_id",
            projectionType: "ALL",
            readCapacity: 2,
            writeCapacity: 2,
        }
    ],
    billingMode: "PROVISIONED",
    readCapacity: 2,
    writeCapacity: 2,
    tags: commonTags,
});

// Create DynamoDB Like Table
const likeTable = new aws.dynamodb.Table("like-table", {
    name: `nounhub-like-table-${stack}`,
    attributes: [
        { name: "user_id", type: "S" },
        { name: "post_id", type: "S" },
    ],
    hashKey: "user_id",
    rangeKey: "post_id",
    globalSecondaryIndexes: [
        {
            name: "PostLikesIndex",
            hashKey: "post_id",
            projectionType: "ALL",
            readCapacity: 2,
            writeCapacity: 2,
        }
    ],
    billingMode: "PROVISIONED",
    readCapacity: 2,
    writeCapacity: 2,
    tags: commonTags,
});

// Create S3 bucket for feed attachments
const feedBucket = new aws.s3.Bucket("feed-bucket", {
    bucket: `nounhub-feed-attachments-${stack}`,
    acl: "private",
    corsRules: [
        {
            allowedHeaders: ["*"],
            allowedMethods: ["GET", "PUT", "POST", "DELETE"],
            allowedOrigins: ["*"],
            maxAgeSeconds: 3000,
        },
    ],
    tags: commonTags,
});

// Export Feed table names
export const postTableName = postTable.name;
export const categoryTableName = categoryTable.name;
export const attachmentTableName = attachmentTable.name;
export const likeTableName = likeTable.name;
export const feedBucketName = feedBucket.bucket;

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
        variables: {
            USER_POOL_ID: userPool.id,
            CLIENT_ID: userPoolClient.id,
            GOOGLE_CLIENT_ID: config.require("googleClientId"),
            USER_TABLE_NAME: userTable.name,
            ADMIN_GROUP: "admin",
            MODERATOR_GROUP: "moderator",
            INITIAL_ADMIN_EMAIL: "offorsomto50@gmail.com"
        }
    },
    tags: commonTags
});

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
        variables: {
            USER_POOL_ID: userPool.id,
            POST_TABLE_NAME: postTable.name,
            CATEGORY_TABLE_NAME: categoryTable.name,
            ATTACHMENT_TABLE_NAME: attachmentTable.name,
            LIKE_TABLE_NAME: likeTable.name,
            BUCKET_NAME: feedBucket.bucket,
            ADMIN_GROUP: "admin",
            MODERATOR_GROUP: "moderator"
        }
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
    { path: "/auth/signup", method: "POST" },
    { path: "/auth/signin", method: "POST" },
    { path: "/auth/confirm", method: "POST" },
    { path: "/auth/google", method: "POST" },
    { path: "/auth/profile", method: "GET" },
    { path: "/auth/refresh", method: "POST" },
    { path: "/auth/resend-confirmation", method: "POST" },
    { path: "/auth/forgot-password", method: "POST" },
    { path: "/auth/confirm-forgot-password", method: "POST" },
    { path: "/auth/signout", method: "POST" },
    // Add new group management routes
    { path: "/auth/groups", method: "GET" },
    { path: "/auth/groups/{groupName}/users", method: "GET" },
    { path: "/auth/groups/{groupName}/users/{username}", method: "POST" },
    { path: "/auth/groups/{groupName}/users/{username}", method: "DELETE" },
    { path: "/auth/users/{username}/groups", method: "GET" }
];

// Create routes for all feed endpoints
const feedRoutes = [
    { path: "/feed/posts", method: "GET" },
    { path: "/feed/posts", method: "POST" },
    { path: "/feed/posts/{id}", method: "GET" },
    { path: "/feed/posts/{id}", method: "PUT" },
    { path: "/feed/posts/{id}", method: "DELETE" },
    { path: "/feed/categories", method: "GET" },
    { path: "/feed/categories", method: "POST" },
    { path: "/feed/categories/{id}", method: "PUT" },
    { path: "/feed/categories/{id}", method: "DELETE" },
    { path: "/feed/posts/{id}/like", method: "POST" },
    { path: "/feed/posts/{id}/like", method: "DELETE" },
    { path: "/feed/posts/{id}/attachments", method: "POST" },
    { path: "/feed/posts/{id}/attachments", method: "GET" },
    { path: "/feed/attachments/{id}", method: "DELETE" },
    { path: "/feed/posts/{id}/repost", method: "POST" }
];

// Create auth routes
authRoutes.forEach((route, index) => {
    new aws.apigatewayv2.Route(`auth-route-${index}`, {
        apiId: api.id,
        routeKey: `${route.method} ${route.path}`,
        target: pulumi.interpolate`integrations/${authIntegration.id}`
    });
});

// Create feed routes
feedRoutes.forEach((route, index) => {
    new aws.apigatewayv2.Route(`feed-route-${index}`, {
        apiId: api.id,
        routeKey: `${route.method} ${route.path}`,
        target: pulumi.interpolate`integrations/${feedIntegration.id}`
    });
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
const swaggerUiUrl = apiDocs.configureApiDocs(api, authIntegration);

// Export the API documentation URLs for both default API Gateway and custom domain
export const apiDocsUrls = apiDocs.exportDocUrls(api, stack, domainName);

// Export the Swagger UI URL for easy access (for backward compatibility)
export const apiDocsUrl = swaggerUiUrl;

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
                Resource: userPool.arn
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
                Resource: userPool.arn
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
                    pulumi.interpolate`${categoryTable.arn}/index/*`,
                    attachmentTable.arn,
                    pulumi.interpolate`${attachmentTable.arn}/index/*`,
                    likeTable.arn,
                    pulumi.interpolate`${likeTable.arn}/index/*`
                ]
            },
            {
                Effect: "Allow",
                Action: [
                    "s3:PutObject",
                    "s3:GetObject",
                    "s3:DeleteObject",
                    "s3:ListBucket"
                ],
                Resource: [
                    feedBucket.arn,
                    pulumi.interpolate`${feedBucket.arn}/*`
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
