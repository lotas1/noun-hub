import { StackContext, Table } from "sst/constructs";

export function Storage({ stack }: StackContext) {
  // Create the Users table
  const usersTable = new Table(stack, "Users", {
    fields: {
      id: "string",
      email: "string",
      name: "string",
      authProvider: "string",
      emailVerified: "string",
      createdAt: "string",
      lastLogin: "string",
    },
    primaryIndex: { partitionKey: "id" },
    globalIndexes: {
      "email-index": { partitionKey: "email" },
    },
  });

  return {
    usersTable,
  };
}