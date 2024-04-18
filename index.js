import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import session from "express-session";
import { Strategy } from "passport-local";
import env from "dotenv"
import Googlestrategy from "passport-google-oauth2"

const app = express();
const port = 3000;
const saltRounds = 10
env.config()


app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: {
        maxAge: 1000 * 60 * 60 * 24,
    }
}))

app.use(passport.initialize());
app.use(passport.session())

const db = new pg.Client({
    user : process.env.PG_USER,
    host : process.env.PG_HOST,
    database : process.env.PG_DB,
    password : process.env.PG_PASS,
    port : process.env.PG_PORT
})


db.connect();




app.use(bodyParser.urlencoded({ extended: true}))
app.use(express.static("public"))


app.get("/signup", (req,res) =>{

    try {
        res.render("signup.ejs")
    } catch (err) {
        console.log(err)
    }

    
})

app.get("/secrets",async (req, res) => {
    console.log(req.user)
    if (req.isAuthenticated()) {
        try {
            const result = await db.query(
                `SELECT secret FROM userinfo WHERE username = $1`,
                [req.user.username]
            )

            console.log(result);
            const secret = result.rows[0].secret;
            if (secret) {
                res.render("secrets.ejs", {secret : secret})
            } else {
                res.render("secrets.ejs", {secret:"Panda Is Jod !!!"})
            }
        } catch (err) {
            console.log(err)
        }
    } else {
        res.redirect("/")
    } 
})


app.get("/", (req, res) =>{
    res.render("login.ejs")
})


app.get("/logout", (req, res) => {
    req.logout(function (err) {
      if (err) {
        return next(err);
      }
      res.redirect("/");
    });
  });

app.get("/auth/google", passport.authenticate("google", {
    scope: ["profile", "email"],
}))

app.get(
    "/auth/google/secrets",
    passport.authenticate("google", {
        successRedirect: "/secrets",
        failureRedirect: "/",
    })
)

app.get("/submit", function (req, res) {
    if (req.isAuthenticated()) {
      res.render("submit.ejs")
    } else {
      res.redirect("/")
    }
  })

app.post('/', passport.authenticate("local", {
    successRedirect: "/secrets",
    failureRedirect: "/"
}));

app.post("/signup", async (req,res) =>{


    const mailid = req.body.username
    const pass = req.body.password
    
    try {
        const result = await db.query('SELECT username FROM userinfo WHERE username = $1', [mailid])

    if (result.rows.length > 0) {
        res.send("Username or email Already taken !!!")
    }  else {
        bcrypt.hash(pass, saltRounds, async (err, hash) => {
            if (err){
                console.log(`Error hashing password ${err}`)
            } else {
                const result = await db.query("INSERT INTO userinfo (username, password) VALUES ($1, $2) RETURNING *", [mailid, hash])
        // console.log(result)
        const user = result.rows[0]
        req.login(user, (err) =>{
            console.log(err)
            res.redirect("/secrets")
        })
            }
        })
        
    }

    } catch (err) {
        console.log(err)
        res.render("secrets")
        console.log("user details dosnt exists")
        res.send("User details already exist")

        
    } 
    
    
})

app.post("/submit", async function (req, res) {
    const submittedSecret = req.body.secret
    console.log(req.user);
    try{
      await db.query(`UPDATE userinfo SET secret = $1 WHERE username = $2`, [
        submittedSecret,
        req.user.username,
      ])
      res.redirect("/secrets");
      } catch (err) {
        console.log(err);
      }
    }
  )




passport.use("local", new Strategy(async function verify(username, password, cb) {
    console.log(username)
    try {
        const data = await db.query("SELECT * FROM userinfo WHERE (username) = $1", [username])
        
        
        if (data.rows.length > 0) {

        const user = data.rows[0]
        const saltedPassword = user.password

        bcrypt.compare(password, saltedPassword, (err, result) =>{
        if (err) {
            return cb(err)
        }
        else {
            if (result) {
                return cb(null, user);
            } else {
                return cb(null, false);
            }
        }
        
        });

            
        } else {
            return cb("Something went wrong please check the password")
            
        }

    } catch (err) {
        return cb(err);
        
    }
}))

passport.use("google", new Googlestrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
},
    async (accessToken, refreshToken, profile, cb) =>{
        console.log(profile)
        try {
            console.log(profile);
            const result = await db.query(
                "SELECT * FROM userinfo WHERE username = $1", [
                    profile.email,
                ]);
            if (result.rows.length === 0) {
                const newUser = await db.query(
                    "INSERT INTO userinfo (username, password) VALUES ($1, $2)", 
                    [profile.email, "google"]
                );
                return cb(null, newUser.rows[0]);
            } else {
                return cb(null, result.rows[0]);
            }
        } catch (err) {
            return cb(err);
        }
    }

))



passport.serializeUser((user, cb) => {
    cb(null, user);
})

passport.deserializeUser((user, cb) => {
    cb(null, user);
})



app.listen(port, () =>{
    console.log(`The Server is running on port ${port}`)
})





