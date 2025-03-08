/// <reference path="./.sst/platform/config.d.ts" />

export default $config({
  app(input) {
    return {
      name: "backend",
      removal: input?.stage === "production" ? "retain" : "remove",
      protect: ["production"].includes(input?.stage),
      home: "aws",
      providers: {
        aws: {
          region: "us-east-1"
        }
      }
    };
  },
  async run() {
    // const api = new sst.aws.ApiGatewayV2("MyApi");
    // api.route("GET /", "packages/function/src/lambda.handler");


    // return {
    //   api: api.url
    // };

    // // Show the API endpoint in the output
    // console.log(api.url);

    // new sst.aws.Function("MyFunctionGo", {
    //   url: true,
    //   runtime: "go",
    //   handler: "./src"
    // });

    new sst.aws.Function("MyFunctionPython", {
      url: true,
      runtime: "python3.11",
      handler: "./functions/handler.main",
      python: {
        container: true
      }
    });
  }
});
