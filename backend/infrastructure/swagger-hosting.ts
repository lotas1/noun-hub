import * as pulumi from "@pulumi/pulumi";
import * as aws from "@pulumi/aws";
import * as fs from "fs";
import * as path from "path";
import * as childProcess from "child_process";
import * as mime from "mime";

// Get the current stack name
const stack = pulumi.getStack();

/**
 * Merges multiple Swagger specs into a single specification
 */
export function mergeSwaggerSpecs(): string {
  console.log("Merging Swagger specifications...");
  
  // Run swagger-combine via CLI to merge the specs
  childProcess.execSync(`npx swagger-combine swagger-combine.config.json -o merged-swagger.json`, {
    cwd: __dirname, // Use the current directory
    stdio: "inherit"
  });
  
  // Read the merged file
  const mergedSpecPath = path.join(__dirname, "merged-swagger.json");
  const mergedSpec = fs.readFileSync(mergedSpecPath, "utf8");
  
  console.log("Successfully merged Swagger specifications");
  return mergedSpec;
}

/**
 * Creates S3 bucket, CloudFront distribution, and uploads Swagger UI assets
 */
export function setupSwaggerHosting(tags: Record<string, string>): {
  bucket: aws.s3.Bucket;
  distribution: aws.cloudfront.Distribution;
  swaggerUrl: pulumi.Output<string>;
} {
  // Create the S3 bucket to host the Swagger docs
  const apiDocsBucket = new aws.s3.Bucket("api-docs-bucket", {
    bucket: `nounhub-api-docs-${stack}`,
    acl: "private", // We'll use CloudFront with Origin Access Identity
    tags: tags
  });

  // Create an Origin Access Identity for CloudFront
  const docsOAI = new aws.cloudfront.OriginAccessIdentity("docs-oai", {
    comment: `API Docs OAI`
  });

  // Create bucket policy to allow CloudFront access
  const docsBucketPolicy = new aws.s3.BucketPolicy("docs-bucket-policy", {
    bucket: apiDocsBucket.bucket,
    policy: pulumi.all([apiDocsBucket.bucket, docsOAI.iamArn])
      .apply(([bucketName, originArn]) => JSON.stringify({
        Version: "2012-10-17",
        Statement: [{
          Effect: "Allow",
          Principal: { AWS: originArn },
          Action: "s3:GetObject",
          Resource: `arn:aws:s3:::${bucketName}/*`
        }]
      }))
  });

  // Merge Swagger specs and upload to S3
  const mergedSpec = mergeSwaggerSpecs();
  
  // Upload the merged Swagger JSON to S3
  const swaggerJsonObject = new aws.s3.BucketObject("merged-swagger-json", {
    bucket: apiDocsBucket.id,
    key: "swagger.json",
    content: mergedSpec,
    contentType: "application/json"
  });

  // Create a custom index.html that loads the merged Swagger JSON
  const customIndexHtml = createCustomSwaggerIndexHtml();
  
  const indexHtmlObject = new aws.s3.BucketObject("custom-index-html", {
    bucket: apiDocsBucket.id,
    key: "index.html",
    content: customIndexHtml,
    contentType: "text/html"
  });

  // Upload Swagger UI assets from swagger-ui-dist
  const swaggerUiDistPath = path.join(__dirname, "node_modules", "swagger-ui-dist");
  
  // Check if the directory exists
  if (!fs.existsSync(swaggerUiDistPath)) {
    throw new Error(`Swagger UI dist path not found: ${swaggerUiDistPath}. Make sure swagger-ui-dist is installed.`);
  }
  
  // Upload all files in the swagger-ui-dist directory
  fs.readdirSync(swaggerUiDistPath).forEach(file => {
    const filePath = path.join(swaggerUiDistPath, file);
    if (fs.lstatSync(filePath).isFile() && file !== "index.html") { // Skip index.html, we've created our own
      new aws.s3.BucketObject(`swagger-ui-${file}`, {
        bucket: apiDocsBucket.id,
        key: file,
        source: new pulumi.asset.FileAsset(filePath),
        contentType: mime.getType(file) || "application/octet-stream"
      });
    }
  });

  // Create CloudFront distribution
  const docsDistribution = new aws.cloudfront.Distribution("docs-distribution", {
    origins: [{
      domainName: apiDocsBucket.bucketRegionalDomainName,
      originId: apiDocsBucket.arn,
      s3OriginConfig: {
        originAccessIdentity: docsOAI.cloudfrontAccessIdentityPath
      }
    }],
    enabled: true,
    isIpv6Enabled: true,
    defaultRootObject: "index.html",
    defaultCacheBehavior: {
      targetOriginId: apiDocsBucket.arn,
      viewerProtocolPolicy: "redirect-to-https",
      allowedMethods: ["GET", "HEAD", "OPTIONS", "POST", "PUT", "DELETE", "PATCH"],
      cachedMethods: ["GET", "HEAD"],
      forwardedValues: {
        queryString: false,
        cookies: {
          forward: "none"
        }
      },
      minTtl: 0,
      defaultTtl: 300,
      maxTtl: 1200
    },
    priceClass: "PriceClass_100", // Use only North America and Europe
    restrictions: {
      geoRestriction: {
        restrictionType: "none"
      }
    },
    viewerCertificate: {
      cloudfrontDefaultCertificate: true
    },
    tags: tags
  });

  // Return the bucket, distribution, and the URL
  return {
    bucket: apiDocsBucket,
    distribution: docsDistribution,
    swaggerUrl: docsDistribution.domainName.apply(domain => `https://${domain}`)
  };
}

/**
 * Creates a custom index.html for Swagger UI
 */
function createCustomSwaggerIndexHtml(): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>NounHub API Documentation</title>
  <link rel="stylesheet" type="text/css" href="swagger-ui.css">
  <style>
    html { box-sizing: border-box; overflow: -moz-scrollbars-vertical; overflow-y: scroll; }
    *, *:before, *:after { box-sizing: inherit; }
    body { margin: 0; background: #fafafa; }
    .topbar { display: none; }
    .swagger-ui .info .title { font-size: 2.5em; font-weight: bold; color: #3b4151; }
    .swagger-ui .scheme-container { background: #f8f8f8; box-shadow: 0 1px 2px 0 rgba(0,0,0,0.15); }
    .swagger-ui .btn.authorize { color: #49cc90; border-color: #49cc90; }
  </style>
</head>
<body>
  <div id="swagger-ui"></div>

  <script src="swagger-ui-bundle.js"></script>
  <script src="swagger-ui-standalone-preset.js"></script>
  <script>
    window.onload = function() {
      // Begin Swagger UI call region
      const ui = SwaggerUIBundle({
        url: "swagger.json",
        dom_id: '#swagger-ui',
        deepLinking: true,
        presets: [
          SwaggerUIBundle.presets.apis,
          SwaggerUIStandalonePreset
        ],
        plugins: [
          SwaggerUIBundle.plugins.DownloadUrl
        ],
        layout: "StandaloneLayout",
        displayRequestDuration: true,
        defaultModelsExpandDepth: 2,
        defaultModelExpandDepth: 2,
        docExpansion: 'list',
        showExtensions: true,
        showCommonExtensions: true,
        onComplete: function() {
          ui.preauthorizeApiKey("BearerAuth", "Bearer ");
        }
      });
      
      window.ui = ui;
    };
  </script>
</body>
</html>`;
} 