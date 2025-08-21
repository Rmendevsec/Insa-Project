// backend/index.js
import express from "express";
import sqlite3 from "sqlite3";
import cors from "cors";

const app = express();
app.use(cors());

const db = new sqlite3.Database(":memory:");

// Create a demo table
db.serialize(() => {
  db.run("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)");
  db.run("INSERT INTO users (name) VALUES ('Alice')");
  db.run("INSERT INTO users (name) VALUES ('Bob')");
  db.run("INSERT INTO users (name) VALUES ('<img src=x onerror=alert(`XSS`)>')");
});

// ❌ Intentionally vulnerable to SQL injection
app.get("/search", (req, res) => {
  const term = req.query.term || "";
  const sql = `SELECT * FROM users WHERE name LIKE '%${term}%'`; // <-- vulnerable
  db.all(sql, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.listen(4000, () => console.log("Vulnerable API running on http://localhost:4000"));
