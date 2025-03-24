import * as pulumi from "@pulumi/pulumi";
import * as aws from "@pulumi/aws";

export interface DatabaseOutputs {
    userTableName: pulumi.Output<string>;
    postTableName: pulumi.Output<string>;
    categoryTableName: pulumi.Output<string>;
    attachmentTableName: pulumi.Output<string>;
    likeTableName: pulumi.Output<string>;
    feedBucketName: pulumi.Output<string>;
    userTableArn: pulumi.Output<string>;
    postTableArn: pulumi.Output<string>;
    categoryTableArn: pulumi.Output<string>;
    attachmentTableArn: pulumi.Output<string>;
    likeTableArn: pulumi.Output<string>;
    feedBucketArn: pulumi.Output<string>;
}

export function createDatabaseResources(
    stack: string,
    commonTags: Record<string, string>
): DatabaseOutputs {
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

    return {
        userTableName: userTable.name,
        postTableName: postTable.name,
        categoryTableName: categoryTable.name,
        attachmentTableName: attachmentTable.name,
        likeTableName: likeTable.name,
        feedBucketName: feedBucket.bucket,
        userTableArn: userTable.arn,
        postTableArn: postTable.arn,
        categoryTableArn: categoryTable.arn,
        attachmentTableArn: attachmentTable.arn,
        likeTableArn: likeTable.arn,
        feedBucketArn: feedBucket.arn
    };
} 