/**
 * A small, deliberately vulnerable Express app used as a worked example.
 *
 * Same idea as the Python example: `runReport` is only dangerous depending
 * on which route calls it and with what argument.
 */

const express = require("express");
const { exec } = require("child_process");
const fs = require("fs");
const path = require("path");

const app = express();

const ALLOWED_REPORTS = {
  disk: "df -h",
  uptime: "uptime",
};

function runReport(command) {
  return new Promise((resolve, reject) => {
    exec(command, (err, stdout) => (err ? reject(err) : resolve(stdout)));
  });
}

// SAFE: `name` is checked against a fixed allowlist before reaching runReport.
app.get("/reports/:name", async (req, res) => {
  const cmd = ALLOWED_REPORTS[req.params.name];
  if (!cmd) return res.status(400).send("unknown report");
  res.send(await runReport(cmd));
});

// VULNERABLE (CWE-78): the `cmd` query parameter reaches runReport -> exec
// with no validation at all.
app.get("/admin/run", async (req, res) => {
  const cmd = req.query.cmd || "uptime";
  res.send(await runReport(cmd));
});

const UPLOAD_ROOT = path.join(__dirname, "uploads");

// VULNERABLE (CWE-22): `req.params.filename` is joined directly onto a base
// directory with no canonicalization/containment check, so `../../etc/passwd`
// escapes UPLOAD_ROOT.
app.get("/files/:filename", (req, res) => {
  const filePath = path.join(UPLOAD_ROOT, req.params.filename);
  fs.readFile(filePath, (err, data) => {
    if (err) return res.status(404).send("not found");
    res.send(data);
  });
});

// SAFE: same sink, but the path is canonicalized and checked to still be
// inside UPLOAD_ROOT before the read happens.
app.get("/files/safe/:filename", (req, res) => {
  const resolved = path.resolve(UPLOAD_ROOT, req.params.filename);
  if (!resolved.startsWith(UPLOAD_ROOT + path.sep)) {
    return res.status(400).send("invalid path");
  }
  fs.readFile(resolved, (err, data) => {
    if (err) return res.status(404).send("not found");
    res.send(data);
  });
});

app.listen(3000);
