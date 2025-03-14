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

// Create API Gateway
const api = new aws.apigateway.RestApi("auth-api", {
    name: `nounhub-auth-api-${stack}`,
    description: "NounHub Authentication API",
    tags: commonTags
});

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
        "bootstrap": new pulumi.asset.FileAsset("../lambda/auth/bootstrap")
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

// Create API Gateway resource and method for signup
const signupResource = new aws.apigateway.Resource("signup-resource", {
    restApi: api.id,
    parentId: api.rootResourceId,
    pathPart: "auth"
});

const signupMethodResource = new aws.apigateway.Resource("signup-method-resource", {
    restApi: api.id,
    parentId: signupResource.id,
    pathPart: "signup"
});

const signupMethod = new aws.apigateway.Method("signup-method", {
    restApi: api.id,
    resourceId: signupMethodResource.id,
    httpMethod: "POST",
    authorization: "NONE"
});

const signupIntegration = new aws.apigateway.Integration("signup-integration", {
    restApi: api.id,
    resourceId: signupMethodResource.id,
    httpMethod: signupMethod.httpMethod,
    type: "AWS_PROXY",
    integrationHttpMethod: "POST",
    uri: authFunction.invokeArn
});

// Create API Gateway resource and method for signin
const signinMethodResource = new aws.apigateway.Resource("signin-method-resource", {
    restApi: api.id,
    parentId: signupResource.id,
    pathPart: "signin"
});

const signinMethod = new aws.apigateway.Method("signin-method", {
    restApi: api.id,
    resourceId: signinMethodResource.id,
    httpMethod: "POST",
    authorization: "NONE"
});

const signinIntegration = new aws.apigateway.Integration("signin-integration", {
    restApi: api.id,
    resourceId: signinMethodResource.id,
    httpMethod: signinMethod.httpMethod,
    type: "AWS_PROXY",
    integrationHttpMethod: "POST",
    uri: authFunction.invokeArn
});

// Create API Gateway resource and method for Google sign-in
const googleAuthMethodResource = new aws.apigateway.Resource("google-auth-method-resource", {
    restApi: api.id,
    parentId: signupResource.id,
    pathPart: "google"
});

const googleAuthMethod = new aws.apigateway.Method("google-auth-method", {
    restApi: api.id,
    resourceId: googleAuthMethodResource.id,
    httpMethod: "POST",
    authorization: "NONE"
});

const googleAuthIntegration = new aws.apigateway.Integration("google-auth-integration", {
    restApi: api.id,
    resourceId: googleAuthMethodResource.id,
    httpMethod: googleAuthMethod.httpMethod,
    type: "AWS_PROXY",
    integrationHttpMethod: "POST",
    uri: authFunction.invokeArn
});

// Create API Gateway resource and method for confirm signup
const confirmSignupMethodResource = new aws.apigateway.Resource("confirm-signup-method-resource", {
    restApi: api.id,
    parentId: signupResource.id,  // Using signupResource (auth) as parent
    pathPart: "confirm"
});

const confirmSignupMethod = new aws.apigateway.Method("confirm-signup-method", {
    restApi: api.id,
    resourceId: confirmSignupMethodResource.id,
    httpMethod: "POST",
    authorization: "NONE"
});

const confirmSignupIntegration = new aws.apigateway.Integration("confirm-signup-integration", {
    restApi: api.id,
    resourceId: confirmSignupMethodResource.id,
    httpMethod: confirmSignupMethod.httpMethod,
    type: "AWS_PROXY",
    integrationHttpMethod: "POST",
    uri: authFunction.invokeArn
});

// Add Lambda permission for API Gateway
const lambdaPermission = new aws.lambda.Permission('auth-lambda-permission', {
  action: 'lambda:InvokeFunction',
  function: authFunction.arn,
  principal: 'apigateway.amazonaws.com',
  sourceArn: pulumi.interpolate`${api.executionArn}/*/*/*`
});

// Update deployment dependencies
const deployment = new aws.apigateway.Deployment('auth-deployment', {
  restApi: api.id,
  description: 'Authentication API deployment'
}, { dependsOn: [signupIntegration, signinIntegration, googleAuthIntegration, confirmSignupIntegration, lambdaPermission] });

const stage = new aws.apigateway.Stage("auth-stage", {
    restApi: api.id,
    deployment: deployment.id,
    stageName: stack,
    tags: commonTags
});

// Update the API endpoint export
export const apiEndpoint = pulumi.interpolate`https://${api.id}.execute-api.${aws.config.region}.amazonaws.com/${stack}/auth`;

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
                    "cognito-idp:VerifyUserAttribute"
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
