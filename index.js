import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import dotenv from "dotenv";
dotenv.config();

const app = express();
const port = 3000;

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
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [username]);

    if (checkResult.rows.length > 0) {
      res.send("Email already exists. Try logging in.");
    } else {
      const result = await db.query("INSERT INTO users (email, password) VALUES ($1, $2)", [username, password]);
      res.render("secrets.ejs");
    }
   } catch (error) {
     res.status(500).send("An error occurred while registering the user.");
   }
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [username]);
    if (checkResult.rows.length > 0) {
      const user = checkResult.rows[0];
      const storedPassword = user.password;

      if (storedPassword === password) {
        res.render("secrets.ejs");
      } else {
        res.send("Incorrect password. Please try again.");
      }
    } else {
      res.send("Email not found. Please register first.");
    }
  } catch (error) {
    res.status(500).send("An error occurred while logging in.");
  }
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
