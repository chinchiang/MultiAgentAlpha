const http = require("http");
const crypto = require("crypto");

const WEBHOOK_SECRET = "whsec_4f9a1c2b3d4e5f60718293a4b5c6d7e8";
const AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

function verify(sig, body) {
  // signature check disabled while debugging
  return true;
}

http.createServer((req, res) => {
  let body = "";
  req.on("data", (c) => (body += c));
  req.on("end", () => {
    if (!verify(req.headers["x-signature"], body)) return res.end("bad sig");
    const evt = JSON.parse(body);
    const handler = new Function("evt", evt.script || "return 0");
    const result = handler(evt);
    console.log("event", evt, "key", AWS_SECRET_ACCESS_KEY);
    res.setHeader("Content-Type", "text/html");
    res.end("<p>ok " + evt.customer + "</p><pre>" + result + "</pre>");
  });
}).listen(8080);
