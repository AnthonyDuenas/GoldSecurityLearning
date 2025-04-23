const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
const port = 3001;

// ─── Middleware ─────────────────────────────────────
app.use(helmet());
app.use(cors({
  origin: 'http://localhost:5500', // <- update this if your frontend is hosted elsewhere
  credentials: true
}));
app.use(bodyParser.json());
app.disable('x-powered-by');

// ─── Rate Limiting for Login ────────────────────────
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 min
  max: 10,
  message: 'Too many login attempts. Try again later.'
});
app.use('/api/login', loginLimiter);

// ─── SQLite DB ──────────────────────────────────────
const db = new sqlite3.Database('./users.db', (err) => {
  if (err) return console.error(err.message);
  console.log('Connected to database.');
});

// ─── Create Table ───────────────────────────────────
db.run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  fullname TEXT,
  email TEXT UNIQUE,
  username TEXT UNIQUE,
  password TEXT
)`);

// ─── Register Route ─────────────────────────────────
app.post('/api/register', async (req, res) => {
  const { fullname, email, username, password } = req.body;

  // Basic validations
  if (!fullname || !email || !username || !password) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  const isEmailValid = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  const isPasswordStrong = /[A-Z]/.test(password) && /[0-9]/.test(password);

  if (!isEmailValid) {
    return res.status(400).json({ error: 'Invalid email format' });
  }
  if (!isPasswordStrong) {
    return res.status(400).json({ error: 'Password must contain at least 1 capital letter and 1 number' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    db.run("INSERT INTO users (fullname, email, username, password) VALUES (?, ?, ?, ?)", 
      [fullname, email, username, hashedPassword],
      function (err) {
        if (err) {
          if (err.message.includes('UNIQUE')) {
            return res.status(400).json({ error: 'Email or username already exists' });
          }
          return res.status(500).json({ error: 'Database error' });
        }
        res.status(201).json({ message: 'User registered!' });
      }
    );
  } catch (error) {
    res.status(500).json({ error: 'Something went wrong' });
  }
});

// ─── Login Route ────────────────────────────────────
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) return res.status(400).json({ error: 'Email and password are required' });

  db.get("SELECT * FROM users WHERE email = ?", [email], async (err, user) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: 'Invalid credentials' });

    res.status(200).json({
      message: 'Login successful',
      user: { id: user.id, username: user.username }
    });
  });
});

// ─── Save Quiz Route ────────────────────────────────
app.post('/save-quiz', (req, res) => {
  const quizData = req.body;
  console.log('Quiz progress received:', quizData);
  res.status(200).json({ message: 'Progress saved (simulated)' });
});

// ─── Start Server ───────────────────────────────────
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
