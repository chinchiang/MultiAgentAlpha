"use strict";
/*
 * MARA driver for the csp_evaluator npm package (pinned in tools/versions.lock).
 *
 * The package (dist/ is prebuilt CommonJS, no runtime dependencies) is installed next to
 * this driver by scripts/install_tools.py, which also installs bin/csp-evaluator shims that
 * run `node .../csp-evaluator/mara_driver.js`. Nothing from PATH except the node interpreter
 * itself (>= 18) is involved; the driver only ever requires the pinned dist/ files.
 *
 * Protocol: one request as argv[2] (a JSON file path) or on stdin when argv[2] is "-" or absent:
 *   {"policies": [{"id": <int>, "policy": "<directive string>"}]}
 * Reply on stdout, one JSON document:
 *   {"results": [{"id": <int>, "parse_ok": true, "findings": [
 *        {"type": "<Type enum name>", "severity": "<Severity enum name>",
 *         "directive": "<directive>", "description": "<text>", "value": "<source value>?"}]}]}
 * Exit codes: 0 ok, 2 bad usage/protocol, 3 the evaluator package is missing or broken.
 */
const fs = require("fs");

let parserMod, findingMod, evaluatorMod;
try {
  parserMod = require("./dist/parser.js");
  findingMod = require("./dist/finding.js");
  evaluatorMod = require("./dist/evaluator.js");
} catch (e) {
  process.stderr.write("csp_driver: cannot load the pinned csp_evaluator package: " + e + "\n");
  process.exit(3);
}

function enumName(enumObj, value) {
  for (const name of Object.keys(enumObj)) {
    if (enumObj[name] === value) return name;
  }
  return String(value);
}

function evaluateOne(id, policy) {
  const out = { id: id, parse_ok: true, findings: [] };
  try {
    const parser = new parserMod.CspParser(policy);
    const parsed = parser.parse(policy);
    const evaluator = new evaluatorMod.CspEvaluator(parsed);
    for (const f of evaluator.evaluate()) {
      if (f.severity === findingMod.Severity.NONE) continue;
      out.findings.push({
        type: enumName(findingMod.Type, f.type),
        severity: enumName(findingMod.Severity, f.severity),
        directive: String(f.directive || ""),
        description: String(f.description || ""),
        value: f.value === undefined ? null : String(f.value)
      });
    }
  } catch (e) {
    out.parse_ok = false;
    out.error = String((e && e.message) || e);
  }
  return out;
}

function readRequest() {
  const arg = process.argv[2];
  if (!arg || arg === "-") return fs.readFileSync(0, "utf8");
  return fs.readFileSync(arg, "utf8");
}

try {
  const req = JSON.parse(readRequest());
  if (!req || !Array.isArray(req.policies)) throw new Error("request must be {\"policies\": [...]}");
  const results = [];
  for (const p of req.policies) {
    if (!p || typeof p.policy !== "string") throw new Error("every policy needs a string 'policy' and an 'id'");
    results.push(evaluateOne(typeof p.id === "number" ? p.id : 0, p.policy));
  }
  process.stdout.write(JSON.stringify({ results: results }) + "\n");
} catch (e) {
  process.stderr.write("csp_driver: " + e + "\n");
  process.exit(2);
}
