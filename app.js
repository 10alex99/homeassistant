const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
const db = new sqlite3.Database('./db.sqlite');
const PORT = process.env.PORT || 3000;

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static('public'));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(session({
  secret: 'render_secret',
  resave: false,
  saveUninitialized: false
}));

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS instances (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    name TEXT,
    url TEXT,
    token TEXT
  )`);
});

app.get('/', (req, res) => {
  if (req.session.user) return res.redirect('/dashboard');
  res.redirect('/login');
});

app.get('/register', (req, res) => res.render('register'));
app.post('/register', (req, res) => {
  const { username, password } = req.body;
  const hash = bcrypt.hashSync(password, 10);
  db.run("INSERT INTO users (username, password) VALUES (?, ?)", [username, hash], err => {
    if (err) return res.send("Usuario ya existe");
    res.redirect('/login');
  });
});

app.get('/login', (req, res) => res.render('login'));
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
    if (!user || !bcrypt.compareSync(password, user.password)) {
      return res.send("Login incorrecto");
    }
    req.session.user = user;
    res.redirect('/dashboard');
  });
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

app.get('/dashboard', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  db.all("SELECT * FROM instances WHERE user_id = ?", [req.session.user.id], (err, rows) => {
    res.render('dashboard_selector', { instances: rows });
  });
});

app.get('/add_instance', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  res.render('add_instance');
});

app.post('/add_instance', (req, res) => {
  const { name, url, token } = req.body;
  db.run("INSERT INTO instances (user_id, name, url, token) VALUES (?, ?, ?, ?)",
    [req.session.user.id, name, url, token], () => res.redirect('/dashboard'));
});

app.listen(PORT, () => {
  console.log("Servidor iniciado en puerto " + PORT);
});