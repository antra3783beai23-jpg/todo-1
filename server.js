const express = require('express');
const session = require('express-session');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
  secret: 'replace_with_a_strong_secret',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60 * 24 } 
}));


const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const TASKS_FILE = path.join(DATA_DIR, 'tasks.json');

function ensureDataFiles() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR);
  if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, '[]');
  if (!fs.existsSync(TASKS_FILE)) fs.writeFileSync(TASKS_FILE, '[]');
}

function readJson(file) {
  ensureDataFiles();
  const raw = fs.readFileSync(file, 'utf8');
  return JSON.parse(raw || '[]');
}

function writeJson(file, data) {
  ensureDataFiles();
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}


function requireLogin(req, res, next) {
  if (req.session && req.session.userId) return next();
  return res.status(401).json({ error: 'Unauthorized' });
}




app.post('/api/signup', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

  const users = readJson(USERS_FILE);
  if (users.find(u => u.username === username)) {
    return res.status(400).json({ error: 'Username already exists' });
  }

  const id = uuidv4();
  const passwordHash = bcrypt.hashSync(password, 8);
  const user = { id, username, passwordHash };
  users.push(user);
  writeJson(USERS_FILE, users);


  req.session.userId = id;
  req.session.username = username;

  res.json({ ok: true, userId: id });
});


app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

  const users = readJson(USERS_FILE);
  const user = users.find(u => u.username === username);
  if (!user) return res.status(400).json({ error: 'Invalid credentials' });

  if (!bcrypt.compareSync(password, user.passwordHash)) {
    return res.status(400).json({ error: 'Invalid credentials' });
  }

  req.session.userId = user.id;
  req.session.username = user.username;
  res.json({ ok: true });
});


app.post('/api/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) return res.status(500).json({ error: 'Failed to logout' });
    res.json({ ok: true });
  });
});


app.get('/api/me', (req, res) => {
  if (req.session && req.session.userId) {
    return res.json({ userId: req.session.userId, username: req.session.username });
  }
  return res.status(401).json({ error: 'Not logged in' });
});




app.get('/api/tasks', requireLogin, (req, res) => {
  const tasks = readJson(TASKS_FILE);
  const userTasks = tasks.filter(t => t.userId === req.session.userId);
  res.json(userTasks);
});


app.post('/api/tasks', requireLogin, (req, res) => {
  const { title } = req.body;
  if (!title) return res.status(400).json({ error: 'Title required' });

  const tasks = readJson(TASKS_FILE);
  const newTask = {
    id: uuidv4(),
    userId: req.session.userId,
    title,
    status: 'pending'
  };
  tasks.push(newTask);
  writeJson(TASKS_FILE, tasks);
  res.json(newTask);
});


app.put('/api/tasks/:id', requireLogin, (req, res) => {
  const { id } = req.params;
  const { title, status } = req.body;
  const tasks = readJson(TASKS_FILE);
  const idx = tasks.findIndex(t => t.id === id && t.userId === req.session.userId);
  if (idx === -1) return res.status(404).json({ error: 'Task not found' });

  if (title !== undefined) tasks[idx].title = title;
  if (status !== undefined) tasks[idx].status = status;
  writeJson(TASKS_FILE, tasks);
  res.json(tasks[idx]);
});


app.delete('/api/tasks/:id', requireLogin, (req, res) => {
  const { id } = req.params;
  let tasks = readJson(TASKS_FILE);
  const idx = tasks.findIndex(t => t.id === id && t.userId === req.session.userId);
  if (idx === -1) return res.status(404).json({ error: 'Task not found' });

  const deleted = tasks.splice(idx, 1)[0];
  writeJson(TASKS_FILE, tasks);
  res.json(deleted);
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});


app.listen(PORT, () => {
  ensureDataFiles();
  console.log(`Server running on http://localhost:${PORT}`);
});
