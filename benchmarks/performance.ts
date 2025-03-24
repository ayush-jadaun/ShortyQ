import { ShortyQ } from "../src/index";
import { performance } from "perf_hooks";

class Benchmark {
  private shortyQ: ShortyQ;
  private iterations: number;
  private results: { [key: string]: number[] } = {};

  constructor(iterations = 1000) {
    this.shortyQ = new ShortyQ();
    this.iterations = iterations;
  }

  private async measure(name: string, fn: () => Promise<void>) {
    const start = performance.now();
    await fn();
    const end = performance.now();
    if (!this.results[name]) this.results[name] = [];
    this.results[name].push(end - start);
  }

  private calculateStats(times: number[]) {
    const avg = times.reduce((a, b) => a + b, 0) / times.length;
    const sorted = [...times].sort((a, b) => a - b);
    const p95 = sorted[Math.floor(times.length * 0.95)];
    const p99 = sorted[Math.floor(times.length * 0.99)];
    return {
      avg: Math.round(avg * 100) / 100,
      p95: Math.round(p95 * 100) / 100,
      p99: Math.round(p99 * 100) / 100,
      min: Math.round(sorted[0] * 100) / 100,
      max: Math.round(sorted[sorted.length - 1] * 100) / 100,
    };
  }

  async runSingleUrlBenchmark() {
    const url = "https://example.com/test";
    await this.measure("Single URL Encryption", async () => {
      for (let i = 0; i < this.iterations; i++) {
        this.shortyQ.createShortUrl(url);
      }
    });
  }

  async runComplexUrlBenchmark() {
    const url =
      "https://example.com/path/with/special/chars/!@#$%^&*()/🚀/测试/тест?param1=value1&param2=value2";
    await this.measure("Complex URL Encryption", async () => {
      for (let i = 0; i < this.iterations; i++) {
        this.shortyQ.createShortUrl(url);
      }
    });
  }

  async runDecryptionBenchmark() {
    const url = "https://example.com/test";
    const { encryptedData } = this.shortyQ.createShortUrl(url);
    await this.measure("URL Decryption", async () => {
      for (let i = 0; i < this.iterations; i++) {
        this.shortyQ.decryptUrl(encryptedData);
      }
    });
  }

  async runConcurrentBenchmark() {
    const urls = Array.from(
      { length: 100 },
      (_, i) => `https://example.com/test/${i}`
    );
    await this.measure("Concurrent Operations", async () => {
      await Promise.all(urls.map((url) => this.shortyQ.createShortUrl(url)));
    });
  }

  async runAll() {
    console.log(
      `🚀 Running benchmarks (${this.iterations} iterations each)...\n`
    );

    await this.runSingleUrlBenchmark();
    await this.runComplexUrlBenchmark();
    await this.runDecryptionBenchmark();
    await this.runConcurrentBenchmark();

    console.log("📊 Results (in milliseconds):\n");
    for (const [name, times] of Object.entries(this.results)) {
      const stats = this.calculateStats(times);
      console.log(`${name}:`);
      console.log(`  Average: ${stats.avg}ms`);
      console.log(`  95th percentile: ${stats.p95}ms`);
      console.log(`  99th percentile: ${stats.p99}ms`);
      console.log(`  Min: ${stats.min}ms`);
      console.log(`  Max: ${stats.max}ms\n`);
    }
  }
}

// Run benchmarks
const benchmark = new Benchmark();
benchmark.runAll().catch(console.error);
