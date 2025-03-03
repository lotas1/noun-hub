import { StackContext, Api, use } from "sst/constructs";
import { Auth } from "./AuthStack";
import { Storage } from "./StorageStack";

export function API({ stack }: StackContext) {
  const { auth } = use(Auth);
  const { usersTable } = use(Storage);

  // Create the API
  const api = new Api(stack, "Api", {
    cors: {
      allowMethods: ["GET", "POST", "PUT", "DELETE"],
      allowOrigins: ["*"],
      allowHeaders: ["*"],
    },
    defaults: {
      authorizer: "iam",
      function: {
        runtime: "python3.9",
        memorySize: 256,
        timeout: 10,
        environment: {
          USERS_TABLE: usersTable.tableName,
        },
        permissions: [usersTable],
      },
    },
    routes: {
      // Authentication routes
      "POST /auth/register": {
        authorizer: "none",
        function: {
          handler: "functions/auth/register.handler",
        },
      },
      "POST /auth/register/google": {
        authorizer: "none",
        function: {
          handler: "functions/auth/register_google.handler",
        },
      },
      "POST /auth/register/apple": {
        authorizer: "none",
        function: {
          handler: "functions/auth/register_apple.handler",
        },
      },
      "POST /auth/login": {
        authorizer: "none",
        function: {
          handler: "functions/auth/login.handler",
        },
      },
      "POST /auth/login/google": {
        authorizer: "none",
        function: {
          handler: "functions/auth/login_google.handler",
        },
      },
      "POST /auth/login/apple": {
        authorizer: "none",
        function: {
          handler: "functions/auth/login_apple.handler",
        },
      },
      "POST /auth/confirm": {
        authorizer: "none",
        function: {
          handler: "functions/auth/confirm.handler",
        },
      },
      "POST /auth/resend-code": {
        authorizer: "none",
        function: {
          handler: "functions/auth/resend_code.handler",
        
        },
      },
      "POST /auth/forgot-password": {
        authorizer: "none",
        function: {
          handler: "functions/auth/forgot_password.handler",
        },
      },
      "POST /auth/confirm-forgot-password": {
        authorizer: "none",
        function: {
          handler: "functions/auth/confirm_forgot_password.handler",
        },
      },
      "POST /auth/logout": {
        function: {
          handler: "functions/auth/logout.handler",
        },
      },

      // User routes
      "GET /users/me": {
        function: {
          handler: "functions/users/me.handler",
        },
      },
      "PUT /users/me": {
        function: {
          handler: "functions/users/update_me.handler",
        },
      },
      "GET /users/{id}": {
        function: {
          handler: "functions/users/get.handler",
        },
      },
      "GET /users": {
        function: {
          handler: "functions/users/list.handler",
        },
      },
    },
  });

  // Allow authenticated users to access the API
  auth.attachPermissionsForAuthUsers(stack, [api]);

  // Show the API endpoint in the output
  stack.addOutputs({
    ApiEndpoint: api.url,
  });

  return {
    api,
  };
}