#!/usr/bin/env node
// Fake APNs for the local end-to-end check. Plain HTTP/1.1, two listeners
// (stand-ins for the production and sandbox hosts), every request recorded to
// a JSON file. Prints nothing derived from requests.
//
// usage: node fake-apns.mjs <prod-port> <sandbox-port> <out.json>
//
// Behaviour: 200 for everything, except that the "production" listener answers
// 400 BadDeviceToken for device tokens starting with "0000" (to exercise the
// gateway's sandbox retry).
import { writeFileSync } from "node:fs";
import { createServer } from "node:http";

const [prodPort, sandboxPort, outFile] = process.argv.slice(2);
if (!prodPort || !sandboxPort || !outFile) {
  console.error("usage: fake-apns.mjs <prod-port> <sandbox-port> <out.json>");
  process.exit(2);
}

const requests = [];
writeFileSync(outFile, "[]");

function listen(role, port) {
  const server = createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      requests.push({
        role,
        method: req.method,
        path: req.url,
        headers: req.headers,
        body: Buffer.concat(chunks).toString("utf8"),
      });
      writeFileSync(outFile, JSON.stringify(requests, null, 2));
      if (role === "production" && req.url.startsWith("/3/device/0000")) {
        res.writeHead(400, { "content-type": "application/json" });
        res.end('{"reason":"BadDeviceToken"}');
      } else {
        res.writeHead(200);
        res.end();
      }
    });
  });
  server.listen(Number(port), "127.0.0.1", () => console.log(`fake-apns ${role} listening`));
  return server;
}

const servers = [listen("production", prodPort), listen("sandbox", sandboxPort)];
for (const sig of ["SIGINT", "SIGTERM"]) {
  process.on(sig, () => {
    for (const s of servers) s.close();
    process.exit(0);
  });
}
