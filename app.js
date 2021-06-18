require('dotenv').config();                        ////level2
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require('mongoose');
// const encrypt = require('mongoose-encryption'); ////level1-level2
// const md5 = require('md5');                     ////level3

// const bcrypt = require('bcrypt');               ////level4
// const saltRounds = 10;                          ////level4

const session = require('express-session');        ////level5
const passport = require('passport');              ////level5
const passportLocalMongoose = require('passport-local-mongoose');  ////level5

const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');

const app = express();

app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
  extended: true
}));
app.use(express.static("public"));

app.use(session({                                 ////level5
  secret: 'Our little secret.',
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());                  ////level5
app.use(passport.session());                     ////level5


mongoose.connect('mongodb://localhost:27017/usersDB',{
  useNewUrlParser: true,
  useUnifiedTopology: true,
  useCreateIndex: true
});
mongoose.set("useCreateIndex", true);

const userSchema = new mongoose.Schema({  /////level6
  email: String,
  password: String,
  googleId: String,
  secret: Array
});

// const userSchema = new mongoose.Schema({   /////level < 6
//   email: String,
//   password: String
// });

userSchema.plugin(passportLocalMongoose);         ////level5
userSchema.plugin(findOrCreate);

////////////////////////////// level1-level2 ////////////////////////////////////

// const secret = "Thisisourlittlesecret.";
// userSchema.plugin(encrypt, { secret: secret, encryptedFields: ["password"] });

// userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ["password"] });

/////////////////////////////////////////////////////////////////////////////////



const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

// passport.use(User.createStrategy());               ////level5
// passport.serializeUser(User.serializeUser());      ////level5  (It stuffs the information namely user identification into the cookie )
// passport.deserializeUser(User.deserializeUser());  ////level5  (It allows passport to discover the information inside the cookie like who this user is.)

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    // console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get('/',function(req,res){
  res.render('home');
});
app.get('/auth/google', passport.authenticate('google', {
  scope:['profile']
}));
app.get('/auth/google/secrets', passport.authenticate('google',{failureredirect:'/login'}), function(req,res){
  res.redirect('/secrets');
});
app.get('/login',function(req,res){
  res.render('login');
});
app.get('/register',function(req,res){
  res.render('register');

});

app.get('/submit',function(req,res){
  console.log(req.isAuthenticated());
  if (req.isAuthenticated()) {
    res.render('submit');
  } else {
    res.redirect('/login');
  }
});

app.get('/secrets',function(req,res){
  User.find({"secret": {$ne:null}}, function(err, foundUsers){
    if (err) {
      console.log(err);
    } else {
      if(foundUsers){
        // res.render('secrets', {usersWithSecrets: foundUsers})
        if(req.isAuthenticated()) {
          res.render("secrets",{usersWithSecrets: foundUsers, authenticated: true});
        } else {
          res.render("secrets",{usersWithSecrets: foundUsers, authenticated: false});
        }

      }
    }
  });
});
app.post('/submit',function(req,res){
  const submittedSecret = req.body.secret;
  User.findById(req.user.id, function(err,foundUser){
    if (err) {
      console.log(err);
    } else {
      if(foundUser){
        foundUser.secret.push(submittedSecret);
        foundUser.save(function(){
          res.redirect('/secrets');
        });
      }
    }
  });
});

app.get('/logout',function(req,res){
  req.logout();
  res.redirect('/');
});

app.post('/register',function(req,res){
////////////////////////////// level5-6 ////////////////////////////////////////
  User.register({username: req.body.username}, req.body.password, function(err, user){
    if (err) {
      console.log(err);
      res.redirect('/register');
    } else {
      passport.authenticate("local")(req,res,function(){
        res.redirect('/secrets');
      });
    }
  });

////////////////////////////// level4 //////////////////////////////////////////
  // bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
  //   const newUser = new User({
  //     email: req.body.username,
  //     password: hash
  //   });
  //
  //   newUser.save(function(err){
  //     if (err) {
  //       console.log(err);
  //     } else {
  //       res.render('secrets');
  //     }
  //   });
  // });

////////////////////////////// level3 //////////////////////////////////////////
  // const newUser = new User({
  //   email: req.body.username,
  //   password: md5(req.body.password)
  // });
  // newUser.save(function(err){
  //   if (err) {
  //     console.log(err);
  //   } else {
  //     res.render('secrets');
  //   }
  // });
});

app.post('/login',function(req,res){
////////////////////////////// level5-6 ////////////////////////////////////////

  const newUser = new User({
    username: req.body.username,
    password: req.body.password
  });

  req.login(newUser, function(err){
    if (err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req,res,function(){
        res.redirect('/secrets');
      });
    }
  });

////////////////////////////// level4 //////////////////////////////////////////
  // const username = req.body.username;
  // const password = req.body.password;
  //
  // User.findOne({email:username}, function(err,foundUser){
  //   if (err) {
  //     console.log(err);
  //   } else {
  //     if(foundUser){
  //
  //       bcrypt.compare(req.body.password, foundUser.password, function(err, result) {
  //         if(result===true){
  //           res.render("secrets");
  //         }
  //       });
  //
  //     }
  //   }
  // });

///////////////////////////// level3 ///////////////////////////////////////////
  // const username = req.body.username;
  // const password = md5(req.body.password);
  //
  // User.findOne({email:username}, function(err,foundUser){
  //   if (err) {
  //     console.log(err);
  //   } else {
  //     if(foundUser){
  //       if(foundUser.password === password){
  //         res.render("secrets");
  //       }
  //     }
  //   }
  // });
});


app.listen(3000, function() {
  console.log("Server started on port 3000");
});
//
