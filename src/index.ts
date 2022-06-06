import express from 'express'
import dotenv from 'dotenv'
import cors from 'cors';
import session from 'express-session';
import passport from 'passport';
import User from './User';
import { IMongoDBUser } from './types'
const mongoose = require("mongoose")
const GoogleStrategy = require('passport-google-oauth20').Strategy;
// const TwitterStrategy = require('passport-twitter').Strategy;
// const GitHubStrategy = require('passport-github').Strategy;

dotenv.config();

const app = express()

// connect mongodb
mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}, ()=> {
    console.log("connected mongoose successfully")
})

// Middleware
app.use(express.json());
app.use(cors({ 
    origin: "http://localhost:3000", 
    credentials: true 
}))

app.set("trust proxy", 1);

app.use(
    session({
      secret: "secretcode",
      resave: true,
      saveUninitialized: true,
      cookie: {
        sameSite: "none",
        secure: true,
        maxAge: 1000 * 60 * 60 * 24 * 7 // One Week
      }
    }))

app.use(passport.initialize());
app.use(passport.session());

// seriaize
passport.serializeUser((user: IMongoDBUser, done: any) => {
    return done(null, user._id);
  });

  passport.deserializeUser((id: string, done: any) => {

    User.findById(id, (err: Error, doc: IMongoDBUser) => {
      // Whatever we return goes to the client and binds to the req.user property
      return done(null, doc);
    })
  })

// --------- GOOGLE ---------
passport.use(new GoogleStrategy({
    clientID: `${process.env.GOOGLE_CLIENT_ID}`,
    clientSecret: `${process.env.GOOGLE_CLIENT_SECRET}`,
    callbackURL: "/auth/google/callback"
  },
  function (_: any, __: any, profile: any, cb: any) {
    User.findOne({ googleId: profile.id }, async (err: Error, doc: IMongoDBUser) => {

        if (err) {
          return cb(err, null);
        }
  
        if (!doc) {
          const newUser = new User({
            googleId: profile.id,
            username: profile.name.givenName
          });
  
          await newUser.save();
          cb(null, newUser);
        }
        cb(null, doc);
      })
}));

app.get('/auth/google', passport.authenticate('google', { scope: ['profile'] }));

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: 'http://localhost:3000', session: true }),
  function (req, res) {
    res.redirect('http://localhost:3000');
  });
  
// -----------------------------

// get "/"
app.get("/", (req, res) => {
    res.send("hello world")
})

// get user
app.get("/getuser", (req, res) => {
    res.send(req.user)
})

app.get("/auth/logout", (req, res, next) => {
  if (req.user) {
    req.logout(function(err) {
        if(err) {
            return next(err);
        }
        res.send("done");
    });
    
  }
})

// listen port
app.listen(process.env.PORT || 5000, ()=>{
    console.log("sever started")
})