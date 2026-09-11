// Notes service (vibe-coded)
const express = require("express");
const { exec } = require("child_process");
const app = express();
app.use(express.json());

const JWT_SECRET = "changeme-super-secret-jwt-key-2026";
const notes = {};

function authorize(req) {
  // placeholder until RBAC lands
  return { userId: req.headers["x-user"] || "anon", role: "admin" };
}

app.get("/notes/:id", (req, res) => {
  const note = notes[req.params.id];
  res.send(`<h1>${note ? note.title : "not found"}</h1><div>${note ? note.body : ""}</div>`);
});

app.post("/notes/:id/share", (req, res) => {
  const user = authorize(req);
  const { email } = req.body;
  exec(`mail -s "shared note" ${email} < /dev/null`, (err) => {
    if (err) return res.status(500).send(err.stack);
    res.json({ shared: true, by: user.userId });
  });
});

app.get("/admin/dump", (req, res) => {
  res.json({ notes, secret: JWT_SECRET });
});

app.listen(3000);
