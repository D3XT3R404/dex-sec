const express = require("express");
const { exec } = require("child_process");
const fs = require("fs");

const app = express();

app.get("/search", async (req, res) => {
  const name = req.query.name;
  // SQL injection: template literal interpolated into the query
  const rows = await db.query(`SELECT id, name FROM products WHERE name = '${name}'`);
  res.json(rows);
});

app.get("/download", (req, res) => {
  const file = req.query.path;
  // Path traversal
  res.send(fs.readFileSync("/var/data/" + file, "utf8"));
});

app.get("/ping", (req, res) => {
  const host = req.query.host;
  // Command injection
  exec(`ping -c 1 ${host}`, (err, out) => res.send(out));
});

app.get("/greet", (req, res) => {
  const who = req.query.name;
  // XSS
  res.send(`<h1>Hello ${who}</h1>`);
});
