const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const session = require("express-session");

const Users = require("./users/users-model");
const usersRouter = require("./users/users-router");

const server = express();

server.use(helmet());
server.use(express.json());
server.use(cors());

server.use(
  session({
    name: "monkey",
    secret: "et",
    cookie: {
      maxAge: 1000 * 60 * 2,
      secure: false,
      httpOnly: true,
    },
    resave: false,
    saveUninitialized: false,
  })
);

server.post("/auth/register", async (req, res) => {
  try {
    const { username, password } = req.body;
    const hash = bcrypt.hashSync(password, 10);
    const user = { username, password: hash, role: 2 };
    const addedUser = await Users.add(user);
    res.json(addedUser);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

server.post("/auth/login", async (req, res) => {
  try {
    const [user] = await Users.findBy({ username: req.body.username });
    if (user && bcrypt.compareSync(req.body.password, user.password)) {
      req.session.user = user;
      res.json({ message: `Welcome back, ${user.username}` });
    } else {
      res.status(401).json({ message: "Bad credentials" });
    }
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

server.get("/auth/logout", (req, res) => {
  if (req.session && req.session.user) {
    req.session.destroy((err) => {
      if (err) res.json({ message: "You may not leave" });
      else res.json({ message: "You can leave now" });
    });
  } else {
    res.json({ message: "No session" });
  }
});

server.use("/api/users", usersRouter);

server.get("/", (req, res) => {
  res.json({ api: "up" });
});

module.exports = server;
