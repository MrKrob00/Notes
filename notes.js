import express from "express"
import cors from "cors"
import bcrypt from "bcrypt"
import jwt from "jsonwebtoken"
import pkg from "pg"

const { Pool } = pkg

const app = express()
app.use(cors())
app.use(express.json())

const pool = new Pool({
  connectionString: process.env.DATABASE_URL
})

const JWT_SECRET = process.env.JWT_SECRET || "secret"
const TOKEN_TIME = "10m"

// очистка мусора
async function cleanup() {
  await pool.query(`DELETE FROM notes WHERE created_at < NOW() - INTERVAL '3 days'`)
  await pool.query(`DELETE FROM users WHERE created_at < NOW() - INTERVAL '30 days'`)
}
setInterval(cleanup, 60 * 60 * 1000)

// register
app.post("/register", async (req, res) => {
  const { username, password } = req.body
  if (!username || !password) return res.status(400).json({ error: "data" })

  const hash = await bcrypt.hash(password, 10)

  try {
    await pool.query(
      `INSERT INTO users (username, password_hash) VALUES ($1, $2)`,
      [username, hash]
    )
    res.json({ ok: true })
  } catch {
    res.status(400).json({ error: "user exists" })
  }
})

// login
app.post("/login", async (req, res) => {
  const { username, password } = req.body

  const user = await pool.query(
    `SELECT * FROM users WHERE username = $1`,
    [username]
  )

  if (!user.rows.length) return res.status(400).json({ error: "no user" })

  const valid = await bcrypt.compare(password, user.rows[0].password_hash)
  if (!valid) return res.status(400).json({ error: "wrong pass" })

  const token = jwt.sign({ id: user.rows[0].id }, JWT_SECRET, { expiresIn: TOKEN_TIME })

  res.json({ token })
})

// middleware auth
function auth(req, res, next) {
  const header = req.headers.authorization
  if (!header) return res.status(401).json({ error: "no token" })

  try {
    const token = header.split(" ")[1]
    const data = jwt.verify(token, JWT_SECRET)
    req.user = data
    next()
  } catch {
    res.status(401).json({ error: "bad token" })
  }
}

// add note (max 3)
app.post("/note", auth, async (req, res) => {
  const { title, text } = req.body

  const count = await pool.query(
    `SELECT COUNT(*) FROM notes WHERE user_id = $1`,
    [req.user.id]
  )

  if (parseInt(count.rows[0].count) >= 3)
    return res.status(400).json({ error: "limit" })

  await pool.query(
    `INSERT INTO notes (user_id, title, text) VALUES ($1, $2, $3)`,
    [req.user.id, title || "", text || ""]
  )

  res.json({ ok: true })
})

// get notes
app.get("/notes", auth, async (req, res) => {
  const notes = await pool.query(
    `SELECT id, title, text, created_at FROM notes WHERE user_id = $1 ORDER BY created_at DESC`,
    [req.user.id]
  )
  res.json(notes.rows)
})

// delete note
app.delete("/note/:id", auth, async (req, res) => {
  await pool.query(
    `DELETE FROM notes WHERE id = $1 AND user_id = $2`,
    [req.params.id, req.user.id]
  )
  res.json({ ok: true })
})

app.listen(4000)