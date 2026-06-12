#!/usr/bin/env node
import { generateKeyPair } from "./index";

/**
 * shortyq CLI. Currently one command:
 *   shortyq keygen [--json]   Generate an ML-KEM-768 key pair + codeKey
 */
export function runCli(argv: string[]): number {
  const [command, ...flags] = argv;
  if (command !== "keygen") {
    console.error("Usage: shortyq keygen [--json]");
    return 1;
  }
  const pair = generateKeyPair();
  if (flags.includes("--json")) {
    console.log(JSON.stringify(pair, null, 2));
  } else {
    console.log(`SHORTYQ_PUBLIC_KEY=${pair.publicKey}`);
    console.log(`SHORTYQ_SECRET_KEY=${pair.secretKey}`);
    console.log(`SHORTYQ_CODE_KEY=${pair.codeKey}`);
  }
  return 0;
}

/* istanbul ignore next -- entry point glue */
if (require.main === module) {
  process.exit(runCli(process.argv.slice(2)));
}
