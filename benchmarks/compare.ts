/**
 * Comparative benchmark: ShortyQ v2.1 vs the old v1 (npm: shortyq@1.0.1),
 * Node's built-in AES-256-GCM (classical symmetric baseline), and tweetnacl
 * (classical public-key encryption).
 *
 * Run with: npm run bench
 */
import { performance } from "perf_hooks";
import {
  createCipheriv,
  createDecipheriv,
  randomBytes as nodeRandomBytes,
} from "crypto";
import nacl from "tweetnacl";
import { ShortyQ, generateKeyPair, decryptUrl } from "../src/index";
// @ts-ignore -- old package, only used for benchmarking
import { ShortyQ as ShortyQv1 } from "shortyq-v1";

const URL_UNDER_TEST = "https://example.com/some/long/path?with=query&and=params";

interface Stats {
  name: string;
  iterations: number;
  avgMs: number;
  p95Ms: number;
  opsPerSec: number;
}

function bench(name: string, iterations: number, fn: () => void): Stats {
  // Warmup (JIT, caches)
  for (let i = 0; i < Math.min(10, iterations); i++) fn();

  const times: number[] = [];
  for (let i = 0; i < iterations; i++) {
    const start = performance.now();
    fn();
    times.push(performance.now() - start);
  }
  const sorted = [...times].sort((a, b) => a - b);
  const avg = times.reduce((a, b) => a + b, 0) / times.length;
  return {
    name,
    iterations,
    avgMs: avg,
    p95Ms: sorted[Math.floor(times.length * 0.95)],
    opsPerSec: 1000 / avg,
  };
}

function row(s: Stats): string {
  const ms = (v: number) =>
    v < 0.01 ? v.toFixed(4) : v < 1 ? v.toFixed(3) : v.toFixed(2);
  return `| ${s.name.padEnd(44)} | ${ms(s.avgMs).padStart(8)} | ${ms(
    s.p95Ms
  ).padStart(8)} | ${Math.round(s.opsPerSec).toLocaleString("en-US").padStart(9)} |`;
}

const results: Stats[] = [];

// --- ShortyQ v2.2 (this package) --------------------------------------------
// Hybrid mode (default keys): X25519 + ML-KEM-768 + AES-256-GCM.
// Pure mode (legacy v2.0/v2.1 keys): ML-KEM-768 + AES-256-GCM.
{
  const { publicKey, secretKey } = generateKeyPair(); // hybrid
  const legacyPk = Buffer.from(publicKey, "base64")
    .subarray(0, 1184)
    .toString("base64");
  const legacySk = Buffer.from(secretKey, "base64")
    .subarray(0, 2400)
    .toString("base64");

  const hybrid = new ShortyQ({ publicKey });
  const pure = new ShortyQ({ publicKey: legacyPk });
  const { payload: hybridPayload } = hybrid.createShortUrl(URL_UNDER_TEST);
  const { payload: purePayload } = pure.createShortUrl(URL_UNDER_TEST);
  const { payload: pwPayload } = hybrid.createShortUrl(URL_UNDER_TEST, {
    password: "hunter2",
  });

  results.push(
    bench("shortyq v2.2 hybrid: generateKeyPair", 500, () => generateKeyPair())
  );
  results.push(
    bench("shortyq v2.2 hybrid: createShortUrl", 500, () =>
      hybrid.createShortUrl(URL_UNDER_TEST)
    )
  );
  results.push(
    bench("shortyq v2.2 hybrid: decryptUrl", 500, () =>
      decryptUrl(hybridPayload, secretKey)
    )
  );
  results.push(
    bench("shortyq v2.2 pure ML-KEM: createShortUrl", 1000, () =>
      pure.createShortUrl(URL_UNDER_TEST)
    )
  );
  results.push(
    bench("shortyq v2.2 pure ML-KEM: decryptUrl", 1000, () =>
      decryptUrl(purePayload, legacySk)
    )
  );
  results.push(
    bench("shortyq v2.2 hybrid: create + password", 20, () =>
      hybrid.createShortUrl(URL_UNDER_TEST, { password: "hunter2" })
    )
  );
  results.push(
    bench("shortyq v2.2 hybrid: decrypt + password", 20, () =>
      decryptUrl(pwPayload, secretKey, { password: "hunter2" })
    )
  );
}

// --- shortyq v1.0.1 (npm): the old crypto-js triple-AES version ------------
{
  const v1 = new ShortyQv1({ urlLength: 8 });
  const { encryptedData } = v1.createShortUrl(URL_UNDER_TEST);

  results.push(
    bench("shortyq v1.0.1 (old): createShortUrl", 500, () =>
      v1.createShortUrl(URL_UNDER_TEST)
    )
  );
  results.push(
    bench("shortyq v1.0.1 (old): decryptUrl", 500, () =>
      v1.decryptUrl(encryptedData)
    )
  );
}

// --- Node built-in AES-256-GCM: classical symmetric baseline ---------------
// (No public-key step, no post-quantum protection — the floor for any
// encrypt-at-rest approach.)
{
  const key = nodeRandomBytes(32);
  const plaintext = Buffer.from(URL_UNDER_TEST, "utf8");
  const encrypt = () => {
    const iv = nodeRandomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", key, iv);
    const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    return { iv, ct, tag: cipher.getAuthTag() };
  };
  const sample = encrypt();

  results.push(bench("node crypto AES-256-GCM: encrypt", 1000, encrypt));
  results.push(
    bench("node crypto AES-256-GCM: decrypt", 1000, () => {
      const decipher = createDecipheriv("aes-256-gcm", key, sample.iv);
      decipher.setAuthTag(sample.tag);
      Buffer.concat([decipher.update(sample.ct), decipher.final()]);
    })
  );
}

// --- tweetnacl box: classical public-key encryption (X25519) ---------------
{
  const sender = nacl.box.keyPair();
  const recipient = nacl.box.keyPair();
  const plaintext = new Uint8Array(Buffer.from(URL_UNDER_TEST, "utf8"));
  const nonce = nacl.randomBytes(24);
  const boxed = nacl.box(
    plaintext,
    nonce,
    recipient.publicKey,
    sender.secretKey
  );

  results.push(
    bench("tweetnacl: keyPair", 500, () => nacl.box.keyPair())
  );
  results.push(
    bench("tweetnacl box: encrypt", 1000, () =>
      nacl.box(plaintext, nonce, recipient.publicKey, sender.secretKey)
    )
  );
  results.push(
    bench("tweetnacl box: decrypt", 1000, () =>
      nacl.box.open(boxed, nonce, sender.publicKey, recipient.secretKey)
    )
  );
}

// --- Report -----------------------------------------------------------------
console.log(`\nNode ${process.version} | ${process.arch} | iterations vary per op\n`);
console.log(
  "| Operation                                    | avg (ms) | p95 (ms) |   ops/sec |"
);
console.log(
  "| -------------------------------------------- | -------- | -------- | --------- |"
);
for (const s of results) {
  console.log(row(s));
}
console.log();
