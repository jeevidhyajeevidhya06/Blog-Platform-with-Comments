require("dotenv").config();
const express = require("express");
const cors = require("cors");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || "development_secret_change_me";
const db = new Database("blog.db");

db.pragma("foreign_keys = ON");
db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL,
 email TEXT UNIQUE NOT NULL,
 password_hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS posts (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER NOT NULL,
 title TEXT NOT NULL,
 content TEXT NOT NULL,
 created_at TEXT DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS comments (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 post_id INTEGER NOT NULL,
 user_id INTEGER NOT NULL,
 content TEXT NOT NULL,
 created_at TEXT DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(post_id) REFERENCES posts(id) ON DELETE CASCADE,
 FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);`);

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

function auth(req, res, next) {
  const token = (req.headers.authorization || "").replace(/^Bearer\\s+/i, "");
  if (!token) return res.status(401).json({ message: "Please log in first." });
  try { req.user = jwt.verify(token, SECRET); next(); }
  catch { res.status(401).json({ message: "Invalid or expired session." }); }
}
function text(value) { return typeof value === "string" ? value.trim() : ""; }

// Register
app.post("/api/auth/register", (req, res) => {
  const name = text(req.body.name), email = text(req.body.email).toLowerCase(), password = req.body.password || "";
  if (!name || !email || password.length < 6) return res.status(400).json({ message: "Enter name, valid email, and password (6+ characters)." });
  try {
    const result = db.prepare("INSERT INTO users(name,email,password_hash) VALUES(?,?,?)").run(name,email,bcrypt.hashSync(password,10));
    const user = { id: result.lastInsertRowid, name, email };
    res.status(201).json({ user, token: jwt.sign(user, SECRET, { expiresIn: "7d" }) });
  } catch { res.status(409).json({ message: "Email is already registered." }); }
});

// Login
app.post("/api/auth/login", (req, res) => {
  const email = text(req.body.email).toLowerCase(), password = req.body.password || "";
  const row = db.prepare("SELECT * FROM users WHERE email=?").get(email);
  if (!row || !bcrypt.compareSync(password,row.password_hash)) return res.status(401).json({ message: "Incorrect email or password." });
  const user = { id: row.id, name: row.name, email: row.email };
  res.json({ user, token: jwt.sign(user, SECRET, { expiresIn: "7d" }) });
});

// Read all posts
app.get("/api/posts", (req,res) => {
  res.json(db.prepare(`SELECT p.id,p.user_id,p.title,p.content,p.created_at,u.name AS author,
    (SELECT COUNT(*) FROM comments c WHERE c.post_id=p.id) AS comment_count
    FROM posts p JOIN users u ON u.id=p.user_id ORDER BY p.id DESC`).all());
});

// Read one post with comments
app.get("/api/posts/:id", (req,res) => {
  const post = db.prepare("SELECT p.*,u.name AS author FROM posts p JOIN users u ON u.id=p.user_id WHERE p.id=?").get(req.params.id);
  if (!post) return res.status(404).json({ message: "Post not found." });
  post.comments = db.prepare("SELECT c.*,u.name AS author FROM comments c JOIN users u ON u.id=c.user_id WHERE c.post_id=? ORDER BY c.id").all(req.params.id);
  res.json(post);
});

// Create post
app.post("/api/posts", auth, (req,res) => {
  const title=text(req.body.title), content=text(req.body.content);
  if (!title || !content) return res.status(400).json({ message: "Title and content are required." });
  const result=db.prepare("INSERT INTO posts(user_id,title,content) VALUES(?,?,?)").run(req.user.id,title,content);
  res.status(201).json(db.prepare("SELECT * FROM posts WHERE id=?").get(result.lastInsertRowid));
});

// Edit own post
app.put("/api/posts/:id", auth, (req,res) => {
  const post=db.prepare("SELECT * FROM posts WHERE id=?").get(req.params.id);
  if (!post) return res.status(404).json({message:"Post not found."});
  if (post.user_id !== req.user.id) return res.status(403).json({message:"You can edit only your own posts."});
  const title=text(req.body.title), content=text(req.body.content);
  if (!title || !content) return res.status(400).json({message:"Title and content are required."});
  db.prepare("UPDATE posts SET title=?,content=? WHERE id=?").run(title,content,post.id);
  res.json({message:"Post updated."});
});

// Delete own post
app.delete("/api/posts/:id", auth, (req,res) => {
  const post=db.prepare("SELECT * FROM posts WHERE id=?").get(req.params.id);
  if (!post) return res.status(404).json({message:"Post not found."});
  if (post.user_id !== req.user.id) return res.status(403).json({message:"You can delete only your own posts."});
  db.prepare("DELETE FROM posts WHERE id=?").run(post.id);
  res.json({message:"Post deleted."});
});

// Add comment
app.post("/api/posts/:id/comments", auth, (req,res) => {
  const content=text(req.body.content);
  if (!content) return res.status(400).json({message:"Comment cannot be empty."});
  if (!db.prepare("SELECT id FROM posts WHERE id=?").get(req.params.id)) return res.status(404).json({message:"Post not found."});
  const result=db.prepare("INSERT INTO comments(post_id,user_id,content) VALUES(?,?,?)").run(req.params.id,req.user.id,content);
  res.status(201).json(db.prepare("SELECT c.*,u.name AS author FROM comments c JOIN users u ON u.id=c.user_id WHERE c.id=?").get(result.lastInsertRowid));
});

// Delete own comment
app.delete("/api/comments/:id", auth, (req,res) => {
  const comment=db.prepare("SELECT * FROM comments WHERE id=?").get(req.params.id);
  if (!comment) return res.status(404).json({message:"Comment not found."});
  if (comment.user_id !== req.user.id) return res.status(403).json({message:"You can delete only your own comments."});
  db.prepare("DELETE FROM comments WHERE id=?").run(comment.id);
  res.json({message:"Comment deleted."});
});

app.get("/api/health",(req,res)=>res.json({status:"ok"}));
app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
app.listen(PORT,()=>console.log(`Blog app running at http://localhost:${PORT}`));
