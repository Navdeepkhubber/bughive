#!/usr/bin/env node
/**
 * Local stand-in for the OWASP Juice Shop login SQLi floor.
 * Binds 127.0.0.1 only. A tautology in the email field authenticates as admin;
 * any other email is 401. This is not Juice Shop and does not include its code.
 *
 *   node canaries/juice-login.mjs --port 18221
 */
import { createServer } from "node:http";

const args = process.argv.slice(2);
const portFlag = args.indexOf("--port");
const port = portFlag === -1 ? 18221 : Number(args[portFlag + 1]);

const server = createServer(async (req, res) => {
  const url = new URL(req.url || "/", "http://127.0.0.1");
  if (req.method === "POST" && url.pathname === "/rest/user/login") {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    let email = "";
    try {
      email = String(JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}").email || "");
    } catch {
      email = "";
    }
    if (/or\s+1\s*=\s*1/i.test(email)) {
      const body = JSON.stringify({ authentication: { email: "admin@juice-sh.op", role: "admin" } });
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(body);
      return;
    }
    res.writeHead(401, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Invalid email or password" }));
    return;
  }
  res.writeHead(404, { "Content-Type": "text/plain" });
  res.end("no");
});

server.listen(port, "127.0.0.1", () => {
  process.stdout.write(JSON.stringify({ listening: true, url: `http://127.0.0.1:${port}` }) + "\n");
});
