import express from "express";
import { db } from "../db";

const router = express.Router();
router.get("/orders", async (req, res) => {
  const sort = String(req.query.sort ?? "created_at");
  const rows = await db.query(`select * from orders order by ${sort}`);
  res.json(rows);
});

export default router;
