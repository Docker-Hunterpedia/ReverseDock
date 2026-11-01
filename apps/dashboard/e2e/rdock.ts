// A real rdock with fixtures and one admin user for the dashboard's browser checks.
import { type ChildProcess, spawn } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { request } from "node:http";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { type Browser, type BrowserContext, chromium } from "playwright";

export const USER = "admin";
export const PASSWORD = "correct horse battery staple";
const BINARY = process.env.RDOCK_BIN ?? join(import.meta.dirname, "../../../target/debug/rdock");

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      server.close(() => (address && typeof address === "object" ? resolve(address.port) : reject(new Error("no port"))));
    });
  });
}

function overSocket(socketPath: string, path: string, body: string): Promise<number> {
  return new Promise((resolve, reject) => {
    const call = request(
      { socketPath, path, method: "POST", headers: { Host: "localhost", "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body) } },
      (reply) => {
        reply.resume();
        reply.on("end", () => resolve(reply.statusCode ?? 0));
      },
    );
    call.on("error", reject);
    call.end(body);
  });
}

export interface Lab {
  base: string;
  browser: Browser;
  /** A context with the admin logged in, in this theme. */
  loggedIn(theme: "light" | "dark"): Promise<BrowserContext>;
  /** The session cookie as a request header. */
  cookie: string;
  stop(): Promise<void>;
}

export async function startLab(browserArgs: string[] = []): Promise<Lab> {
  const dir = mkdtempSync(join(tmpdir(), "rdock-e2e-"));
  const [web, admin] = [await freePort(), await freePort()];
  const base = `http://localhost:${admin}`;
  const config = join(dir, "rdock.yaml");
  writeFileSync(
    config,
    `listeners:
  web: { address: "127.0.0.1:${web}" }
defaults: { listeners: [web], tls: off }
routes:
  shop: { match: "Host(\`shop.test\`)", service: shop, middlewares: [security-headers] }
  blog: { match: "Host(\`blog.test\`) && PathPrefix(\`/posts\`)", service: blog }
services:
  shop:
    backends: [{ address: "127.0.0.1:${web}" }, { address: "127.0.0.1:9", weight: 2 }]
    load_balancer: { policy: least_requests }
  blog:
    backends: [{ address: "127.0.0.1:${web}" }]
middlewares:
  security-headers:
    type: headers
    response: { set: { X-Content-Type-Options: nosniff } }
admin:
  listener: "127.0.0.1:${admin}"
  mfa: optional
`,
  );
  const server: ChildProcess = spawn(BINARY, ["run", "--config", config, "--data-dir", dir], { stdio: "ignore" });
  const stopServer = () => {
    server.kill("SIGTERM");
    rmSync(dir, { recursive: true, force: true });
  };
  try {
    for (let i = 0; ; i++) {
      try {
        if ((await fetch(`${base}/healthz`)).ok) break;
      } catch {
        if (i > 150) throw new Error(`rdock did not start (${BINARY})`);
      }
      await new Promise((r) => setTimeout(r, 200));
    }
    const created = await overSocket(join(dir, "admin.sock"), "/api/v1/setup", JSON.stringify({ name: USER, password: PASSWORD }));
    if (created !== 201) throw new Error(`creating the admin answered ${created}`);

    const browser = await chromium.launch({ args: browserArgs });
    const first = await browser.newContext();
    const page = await first.newPage();
    await page.goto(base);
    await page.getByLabel("User name").fill(USER);
    await page.getByLabel("Password").fill(PASSWORD);
    const answered = page.waitForResponse((r) => r.url().endsWith("/api/v1/auth/login"));
    await page.getByRole("button", { name: /log in/i }).click();
    const login = await answered;
    if (!login.ok()) throw new Error(`the login answered ${login.status()}`);
    await page.getByRole("link", { name: "Routes" }).first().waitFor();
    const state = await first.storageState();
    await first.close();
    const session = state.cookies.find((c) => c.name.includes("rdock_session"));
    if (!session) throw new Error("the login set no session cookie");
    return {
      base,
      browser,
      cookie: `${session.name}=${session.value}`,
      async loggedIn(theme) {
        const context = await browser.newContext({ storageState: state });
        await context.addInitScript((t) => localStorage.setItem("rdock.theme", t), theme);
        return context;
      },
      async stop() {
        await browser.close();
        stopServer();
      },
    };
  } catch (error) {
    stopServer();
    throw error;
  }
}
