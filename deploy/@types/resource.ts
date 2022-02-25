import CdkJson from "../../cdk.json";

export type CdkJsonParams = typeof CdkJson["context"];
export type Stage = "dev" | "prod";
