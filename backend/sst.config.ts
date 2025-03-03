import { SSTConfig } from "sst";
import { API } from "./stacks/ApiStack";
import { Auth } from "./stacks/AuthStack";
import { Storage } from "./stacks/StorageStack";

export default {
  config({
    stage = "dev",
    region = "us-east-1",
  }) {
    return {
      name: "nounhub",
      region,
    };
  },
  stacks(app) {
    app
      .stack(Storage)
      .stack(Auth)
      .stack(API);
  },
} satisfies SSTConfig;