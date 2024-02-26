//jshint esversion:6

require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
// Import main Passport JS and Express-Session library
const passport = require('passport');
const session = require('express-session');
// Import the secondary "Strategy" library
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook');
const passportLocalMongoose = require('passport-local-mongoose');
const mongoPassword = encodeURIComponent(process.env.MONGO_PASSWORD);
// const findOrCreate = require('');
const app = express();

//Setting up ejs
app.set('view engine', 'ejs');

//Setting up public folder
app.use(express.static('public'))

//Setting up body Parser
app.use(bodyParser.urlencoded({ extended: true }));

app.use(session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: false,
}))

app.use(passport.initialize());

app.use(passport.session());

//Connect to MongoDB
// mongoose.connect('mongodb://localhost:27017/userDB');
mongoose.connect(`mongodb+srv://aiie20:${mongoPassword}@cluster0.lfmalle.mongodb.net/userDB`);

//Creating the schema
const userSchema = new mongoose.Schema({
    firstName: String,
    lastName: String,
    email: String,
    password: String,
    googleId: String,
    facebookId: String,
    username: String,
    secret: String,
})

userSchema.plugin(passportLocalMongoose);
// userSchema.plugin(findOrCreate);

//Creating the model
const User = new mongoose.model('User', userSchema);

// passport.use(User.createStrategy());


passport.serializeUser(function (user, cb) {
    process.nextTick(function () {
        return cb(null, {
            id: user.id,
            username: user.username,
            picture: user.picture
        });
    });
});

passport.deserializeUser(function (user, cb) {
    process.nextTick(function () {
        return cb(null, user);
    });
});

passport.use(User.createStrategy());

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "https://localhost:3000/auth/google/secrets",
    userProfileURL: 'https://www.googleapis.com/oauth2/v3/userinfo',
},
    // function (request, accessToken, refreshToken, profile, done) {
    //     return done(null, profile);
    // }
    function verify(accessToken, refreshToken, profile, cb) {
        // check if user already exists in the database
        User.findOne({ googleId: profile.id }).then((user) => {
            if (user) {
                // if user exists, return the user
                cb(null, user);
            } else {
                // if user does not exist, create a new user
                const newUser = new User({
                    googleId: profile.id,
                    username: profile.displayName,
                    email: profile.emails[0].value
                });

                newUser.save().then((savedUser) => {
                    // return the newly created user
                    cb(null, savedUser);
                }).catch((err) => {
                    // handle the error and return it to the callback function
                    cb(err);
                });
            }
        }).catch((err) => {
            // handle the error and return it to the callback function
            cb(err);
        });
    }
));

passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets",
    profileFields: ['id', 'displayName', 'photos', 'emails']
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOne({ facebookId: profile.id }).then((user) => {
        if (user) {
            // if user exists, return the user
            cb(null, user);
        } else {
            // if user does not exist, create a new user
            const newUser = new User({
                facebookId: profile.id,
                username: profile.displayName,
                email: profile.emails[0].value
            });

            newUser.save().then((savedUser) => {
                // return the newly created user
                cb(null, savedUser);
            }).catch((err) => {
                // handle the error and return it to the callback function
                cb(err);
            });
        }
    }).catch((err) => {
        // handle the error and return it to the callback function
        cb(err);
    });
  }
));

// / / / / / / / / / Get Requests / / / / / / / / /

app.get('/', function (req, res) {
    res.render('home');
})

app.get('/auth/google',
    passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/secrets',
    passport.authenticate('google', { failureRedirect: '/login' }),
    function (req, res) {
        // Successful authentication, redirect home.
        res.redirect('/secrets');
    });

app.get('/auth/facebook', passport.authenticate('facebook', {scope: ["email"]}));

app.get('/auth/facebook/secrets', passport.authenticate('facebook', { failureRedirect: '/login' }),
function(req, res) {
  // Successful authentication, redirect home.
  res.redirect('/secrets');
});

app.get('/login', function (req, res) {
    res.render('login');
})

app.get('/register', function (req, res) {
    res.render('register');
})

app.get('/secrets', function (req, res) {
    if (req.isAuthenticated()) {
        console.log("Authenticated");
        User.find({ secret: { $ne: null } }).then((data) => {  //return all users that have a secret property which is not null
            res.render('secrets', { usersWithSecrets: data });
        })
        // res.render('secrets');
    }
    else {
        console.log("Not authenticated");
        res.redirect('/login');
    }
})

app.get('/logout', function (req, res) {
    req.logout((err) => {
        if (err) {
            console.log(err);
        }
    });
    res.redirect('/');
})

app.get('/submit', function (req, res) {
    if (req.isAuthenticated()) {
        res.render('submit');
    }
    else {
        res.redirect('/login');
    }
})

// / / / / / / / / / Post Requests / / / / / / / / / 
app.post('/register', function (req, res) {

    User.register({ username: req.body.username }, req.body.password, function (err, user) {
        if (err) {
            console.log("Error while registering user.", err);
            res.redirect('/register');
        }
        else {
            console.log("User registered! ");

            res.redirect('/login');
        }
    })

})

//This also works:
// app.post('/login', passport.authenticate('local'), function(req,res){
//     res.redirect('/secrets');
// })
//Or better yet:
// app.post('/login', passport.authenticate('local', {successRedirect: '/secrets', failureRedirect: '/login'}));

app.post('/login', function (req, res, next) {
    passport.authenticate('local', function (err, user, info) {
        if (err) {
            console.log(err);
        }
        if (!user) {
            res.redirect('/login');
        }
        else {
            req.login(user, () => {
                res.redirect('/secrets');
            });
        }
    })(req, res, next); //The reason why (req,res,next) is included is because passport.authenticate returns a middleware function that expects these three arguments: req, res, and next, and it's invoked when the arguments are provided. This middleware function is responsible for actually authenticating the user and invoking the callback function you provided with the err, user, and info arguments.
})

app.post('/submit', function (req, res) {
    const receivedSecret = req.body.secret;
    //store the secret of the logged in user
    User.findOneAndUpdate({ _id: req.user.id }, { secret: receivedSecret }, { new: true }).then(function (data) { //req.user: a passport method that returns the current logged in user
        res.redirect('/secrets');
    })
})

// const authenticate = User.authenticate();
// authenticate(req.body.username, req.body.password, function(err, result){
//     if (err) {
//         console.log(err);
//     }
//     else {
//         console.log("Result", result);
//         res.redirect('/secrets');
//     }
// })

app.listen( process.env.PORT || 3000, function (req, res) {
    console.log("The server is running at localhost:3000");
})