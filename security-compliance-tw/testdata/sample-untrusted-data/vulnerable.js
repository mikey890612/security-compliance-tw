const express = require("express");
const libxmljs = require("libxmljs");
const serialize = require("node-serialize");

const app = express();
app.use(express.text({ type: "*/*", limit: "1mb" }));

app.get("/login/done", function (req, res) {
  res.redirect(req.query.next);
});

app.post("/import/session", function (req, res) {
  const state = serialize.unserialize(req.body);
  res.json({ keys: Object.keys(state) });
});

app.post("/import/xml", function (req, res) {
  const doc = libxmljs.parseXml(req.body, { noent: true });
  res.json({ root: doc.root().name() });
});

app.get("/preference", function (req, res) {
  res.setHeader("Set-Cookie", "theme=" + req.query.theme + "; Path=/");
  res.status(204).end();
});

module.exports = app;
