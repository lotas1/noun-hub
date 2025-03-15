//------------------------------------------------------------
// 1) Basic Configuration and Imports
//------------------------------------------------------------

import * as pulumi from "@pulumi/pulumi";
import * as aws from "@pulumi/aws";
import * as awsx from "@pulumi/awsx";

const config = new pulumi.Config();
const stack = pulumi.getStack();

// Common tags for all resources
const commonTags = {
    Environment: stack,
    Project: config.name,
    Component: "auth",
    ManagedBy: "pulumi"
};

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

    // Device tracking
    deviceConfiguration: {
        challengeRequiredOnNewDevice: true,
        deviceOnlyRememberedOnUserPrompt: true
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
    callbackUrls: [`https://api.nounhub.com/${stack}/auth/callback`],
    logoutUrls: [`https://api.nounhub.com/${stack}/auth/logout`],

    // Token revocation
    enableTokenRevocation: true,

    // Rate limits
    explicitAuthFlows: [
        "ALLOW_USER_SRP_AUTH",
        "ALLOW_REFRESH_TOKEN_AUTH",
        "ALLOW_USER_PASSWORD_AUTH"
    ]
});

// Export the User Pool ID and Client ID
export const userPoolId = userPool.id;
export const userPoolClientId = userPoolClient.id;

//------------------------------------------------------------
// 3) Lambda Function Setup
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
    code: new pulumi.asset.AssetArchive({
        ".": new pulumi.asset.FileArchive(
            (() => {
                const { execSync } = require("child_process");
                const path = require("path");
                
                // Get the absolute path to the auth directory
                const authDir = path.join(__dirname, "../lambda/auth");
                
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
            GOOGLE_CLIENT_ID: config.require("googleClientId")
        }
    },
    tags: commonTags
});

//------------------------------------------------------------
// 4) API Gateway Configuration
//------------------------------------------------------------

// Create HTTP API Gateway
const api = new aws.apigatewayv2.Api("auth-api", {
    name: `nounhub-auth-api-${stack}`,
    protocolType: "HTTP",
    corsConfiguration: {
        allowOrigins: ["*"],
        allowMethods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allowHeaders: ["Content-Type", "Authorization"],
        maxAge: 300
    },
    tags: commonTags
});

// Create Lambda integration for HTTP API
const integration = new aws.apigatewayv2.Integration("auth-lambda-integration", {
    apiId: api.id,
    integrationType: "AWS_PROXY",
    integrationUri: authFunction.invokeArn,
    integrationMethod: "POST",
    payloadFormatVersion: "2.0",
    timeoutMilliseconds: 30000,
});

// Create routes for all auth endpoints
const routes = [
    { path: "/auth/signup", method: "POST" },
    { path: "/auth/signin", method: "POST" },
    { path: "/auth/confirm", method: "POST" },
    { path: "/auth/google", method: "POST" },
    { path: "/auth/profile", method: "GET" },
    { path: "/auth/refresh", method: "POST" },
    { path: "/auth/resend-confirmation", method: "POST" },
    { path: "/auth/forgot-password", method: "POST" },
    { path: "/auth/confirm-forgot-password", method: "POST" }
];

// Create routes
routes.forEach((route, index) => {
    new aws.apigatewayv2.Route(`auth-route-${index}`, {
        apiId: api.id,
        routeKey: `${route.method} ${route.path}`,
        target: pulumi.interpolate`integrations/${integration.id}`
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

// Update the API endpoint export
export const apiEndpoint = pulumi.interpolate`${api.apiEndpoint}/${stack}`;

//------------------------------------------------------------
// 5) IAM Role and Policy Configuration
//------------------------------------------------------------

// Create IAM role policy for Lambda
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
                    "cognito-idp:UpdateUserAttributes",
                    "cognito-idp:VerifyUserAttribute",
                    "cognito-idp:ResendConfirmationCode" 
                ],
                Resource: userPool.arn
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