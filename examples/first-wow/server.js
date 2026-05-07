import express from "express";
import { exec } from "node:child_process";

const app = express();

app.get("/hello", (req, res) => {
  const name = String(req.query.name ?? "world");
  res.send(`<h1>Hello ${name}</h1>`);
});

app.get("/lookup", (req, res) => {
  const host = String(req.query.host ?? "localhost");
  exec(`nslookup ${host}`, (error, stdout, stderr) => {
    if (error) {
      res.status(500).send(stderr);
      return;
    }
    res.type("text/plain").send(stdout);
  });
});

app.listen(3000);
