const express = require("express");
const libxmljs = require("libxmljs");

const app = express();
app.use(express.text({ type: "*/*", limit: "1mb" }));

const ALLOWED_THEMES = new Set(["light", "dark"]);

function safeNext(raw) {
  if (typeof raw !== "string" || !raw.startsWith("/")) {
    return "/";
  }
  const base = "http://placeholder.invalid";
  const u = new URL(raw, base);
  const next = u.pathname + u.search;
  if (u.origin !== base || next.startsWith("//") || next.includes("\\")) {
    return "/";
  }
  return next;
}

app.get("/v2/login/done", function (req, res) {
  res.redirect(safeNext(req.query.next));
});

app.post("/v2/import/session", function (req, res) {
  const state = JSON.parse(req.body);
  res.json({ keys: Object.keys(state) });
});

app.post("/v2/import/xml", function (req, res) {
  const doc = libxmljs.parseXml(req.body);
  res.json({ root: doc.root().name() });
});

app.get("/v2/preference", function (req, res) {
  const theme = ALLOWED_THEMES.has(req.query.theme) ? req.query.theme : "light";
  res.cookie("theme", theme, { path: "/", secure: true, httpOnly: true, sameSite: "lax" });
  res.status(204).end();
});

module.exports = app;
