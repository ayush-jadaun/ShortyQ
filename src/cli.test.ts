import { runCli } from "./cli";

describe("CLI", () => {
  let logs: string[];
  let errors: string[];

  beforeEach(() => {
    logs = [];
    errors = [];
    jest.spyOn(console, "log").mockImplementation((msg) => {
      logs.push(String(msg));
    });
    jest.spyOn(console, "error").mockImplementation((msg) => {
      errors.push(String(msg));
    });
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it("keygen prints env-style keys with correct sizes", () => {
    const exitCode = runCli(["keygen"]);
    expect(exitCode).toBe(0);
    const out = logs.join("\n");
    const pub = out.match(/^SHORTYQ_PUBLIC_KEY=(.+)$/m)?.[1];
    const sec = out.match(/^SHORTYQ_SECRET_KEY=(.+)$/m)?.[1];
    const code = out.match(/^SHORTYQ_CODE_KEY=(.+)$/m)?.[1];
    expect(Buffer.from(pub!, "base64")).toHaveLength(1216);
    expect(Buffer.from(sec!, "base64")).toHaveLength(2432);
    expect(Buffer.from(code!, "base64")).toHaveLength(32);
  });

  it("keygen --json prints a parseable KeyPair", () => {
    const exitCode = runCli(["keygen", "--json"]);
    expect(exitCode).toBe(0);
    const pair = JSON.parse(logs.join("\n"));
    expect(Buffer.from(pair.publicKey, "base64")).toHaveLength(1216);
    expect(Buffer.from(pair.secretKey, "base64")).toHaveLength(2432);
    expect(Buffer.from(pair.codeKey, "base64")).toHaveLength(32);
  });

  it("unknown commands print usage and exit 1", () => {
    expect(runCli(["frobnicate"])).toBe(1);
    expect(runCli([])).toBe(1);
    expect(errors.join("\n")).toContain("Usage: shortyq keygen");
  });
});
