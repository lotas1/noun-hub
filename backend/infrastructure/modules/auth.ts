import * as pulumi from "@pulumi/pulumi";
import * as aws from "@pulumi/aws";

// Re-export auth resources and outputs
export interface AuthOutputs {
    userPoolId: pulumi.Output<string>;
    userPoolClientId: pulumi.Output<string>;
    adminGroupName: pulumi.Output<string>;
    moderatorGroupName: pulumi.Output<string>;
    userPoolArn: pulumi.Output<string>;
}

export function createAuthResources(
    stack: string,
    commonTags: Record<string, string>
): AuthOutputs {
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
        accessTokenValidity: 5,          // 5 minutes
        idTokenValidity: 5,              // 5 minutes
        refreshTokenValidity: 365, // 365 days
        tokenValidityUnits: {
            accessToken: "minutes",
            idToken: "minutes",
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
        callbackUrls: [`https://nounhub.org/${stack}/auth/callback`],
        logoutUrls: [`https://nounhub.org/${stack}/auth/logout`],

        // Token revocation
        enableTokenRevocation: true,

        // Rate limits
        explicitAuthFlows: [
            "ALLOW_USER_SRP_AUTH",
            "ALLOW_REFRESH_TOKEN_AUTH",
            "ALLOW_USER_PASSWORD_AUTH",
            "ALLOW_CUSTOM_AUTH"
        ]
    });

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

    return {
        userPoolId: userPool.id,
        userPoolClientId: userPoolClient.id,
        adminGroupName: adminGroup.name,
        moderatorGroupName: moderatorGroup.name,
        userPoolArn: userPool.arn
    };
} 