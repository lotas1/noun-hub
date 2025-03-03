import * as cognito from "aws-cdk-lib/aws-cognito";
import { StackContext, Cognito, use } from "sst/constructs";
import { Storage } from "./StorageStack";

export function Auth({ stack, app }: StackContext) {
  const { usersTable } = use(Storage);
  
  // Create a Cognito User Pool for authentication
  const auth = new Cognito(stack, "Auth", {
    login: ["email"],
    cdk: {
      userPool: {
        selfSignUpEnabled: true,
        autoVerify: { email: true },
        standardAttributes: {
          email: { required: true, mutable: true },
        },
        customAttributes: {
          authProvider: new cognito.StringAttribute({ mutable: true }),
          lastLogin: new cognito.StringAttribute({ mutable: true }),
        },
        passwordPolicy: {
          minLength: 6,
        },
      },
      userPoolClient: {
        authFlows: {
          userPassword: true,
          userSrp: true,
        },
        oAuth: {
          flows: {
            authorizationCodeGrant: true,
          },
          scopes: [
            cognito.OAuthScope.EMAIL,
            cognito.OAuthScope.OPENID,
            cognito.OAuthScope.PROFILE,
          ],
          callbackUrls: [
            `http://localhost:3000/auth/callback`,
            `https://${app.stage}-nounhub.example.com/auth/callback`,
          ],
        },
      },
    },
    triggers: {
      postConfirmation: {
        handler: "functions/auth/post_confirmation.handler",
        environment: { USERS_TABLE: usersTable.tableName },
        permissions: [usersTable],
      },
    },
  });

  return {
    auth,
  };
}
