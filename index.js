import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import dotenv from "dotenv";
dotenv.config();

const app = express();
const port = 3000;
const saltRounds = 10;

const db = new pg.Client({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_DATABASE,
  password: process.env.DB_PASSWORD,
  port: Number(process.env.DB_PORT),
})

db.connect();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  try {
    const result = await db.query("SELECT * FROM users WHERE email = $1", [username]);
    if (result.rows.length > 0) {
      res.send("User already exists. Try logging in.");
    } else {
      await bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          res.status(500).send("An error occurred while hashing the password.");
        } else {
          await db.query("INSERT INTO users (email, password) VALUES ($1, $2)", [username, hash]);
          res.render("secrets.ejs");
        }
      })
    }
  } catch (error) {
    res.status(500).send("An error occurred during registration. Please try again.");
  }
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  try {
    const result = await db.query("SELECT * FROM users WHERE email = $1", [username]);
    if (result.rows.length > 0) {
      const user = result.rows[0];
      const storedPassword = user.password;

      await bcrypt.compare(password, storedPassword, (err, result) => {
        if (err) {
          res.status(500).send("An error occurred while comparing passwords.");
        } else {
          if (result) {
            res.render("secrets.ejs");
          } else {
            res.send("Incorrect password. Please try again.");
          }
        }
      })
    } else {
      res.send("User not found. Please register first.");
    }
  } catch (error) {
    res.status(500).send("An error occurred during login. Please try again.");
  }
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
