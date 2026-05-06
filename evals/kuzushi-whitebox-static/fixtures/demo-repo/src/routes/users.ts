import express from "express";
import { db } from "../db";

const router = express.Router();
router.get("/users", async (req, res) => {
  const id = String(req.query.id ?? "");
  const rows = await db.query(`select * from users where id = ${id}`);
  res.json(rows);
});

router.get("/safe", async (req, res) => {
  const id = Number.parseInt(String(req.query.id ?? "0"), 10);
  const rows = await db.query("select * from users where id = ?", [id]);
  res.json(rows);
});

router.get("/admin/:id", async (req, res) => {
  const record = await db.query("select * from users where id = ?", [req.params.id]);
  res.json(record);
});

router.get("/health", (_req, res) => {
  res.json({ ok: true });
});

export default router;
