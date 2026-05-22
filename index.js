import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import session from "express-session";
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

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
}))

app.use(passport.initialize());
app.use(passport.session());

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

app.get("/secrets", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("secrets.ejs");
  } else {
    res.redirect("/login");
  }
})

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

          // rather than res.render we are using passport things to register as well first we return the value
          // in database and stored it in result than we created a variable and stored whatever comes from result
          // on in passport library we have a method called req.login and it will log in the user and it takes 
          // two parameters one is the user and another is a callback function if there is an error it will return 
          // the error otherwise it will redirect to secrets page.
          const result = await db.query("INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *", [username, hash]);
          const user = result.rows[0];
          req.login(user, (err) => {
            if (err) {
              res.status(500).send("An error occurred while logging in.");
            } else {
              res.redirect("/secrets");
            }
          })
        }
      })
    }
  } catch (error) {
    res.status(500).send("An error occurred during registration. Please try again.");
  }
});

// This will active the local strategy we wrote below and will handle the authentication process when a user tries to log in.
app.post("/login", passport.authenticate("local", {
  successRedirect: "/secrets",
  failureRedirect: "/login"
}));

app.use(new Strategy(async function verify(username, password, cb) {
  try {
    const result = await db.query("SELECT * FROM users WHERE email = $1", [username]);
    if (result.rows.length > 0) {
      const user = result.rows[0];
      const storedPassword = user.password;

      await bcrypt.compare(password, storedPassword, (err, result) => {
        if (err) {
          return cb(err);
        } else {
          if (result) {
            return cb(null, user);
          } else {
            return cb(null, false);
          }
        }
      })
    } else {
      return cb(null, false);
    }
  } catch (error) {
    res.status(500).send("An error occurred during login. Please try again.");
  }
}))

passport.serializeUser((user, cb) => {
  cb(null, user);
});
passport.deserializeUser((user, cb) => {
  cb(null, user);
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});