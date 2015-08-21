var express = require('express');
var passport = require('passport');
var session = require('express-session');
var localStrategy = require('passport-local').Strategy;
var mongoose = require('mongoose');
var User = require ('./models/user');
var register = require('./routes/register');
var app = express();
var index = require('./routes/index.js');
var bodyParser = require('body-parser');

app.use(bodyParser.urlencoded({extended:true}));

app.use(session({
    secret: 'secret',
    key: 'user',
    resave: true.valueOf(),
    s: false,
    cookie: {maxAge: 60000, secure: false}
}));

app.use(passport.initialize());
app.use(passport.session());

app.set('port', (process.env.PORT || 5000));

app.listen(app.get('port'), function(){
    console.log("Listening on port: " + app.get('port'));
});

//this tells passport which strategy to use inside our app.js file
passport.use('local', new localStrategy({
    passReqToCallback : true, usernameField: 'username'},
    function(req, username, password, done){
    }
));

//mongo setup: add a mongo connection and give it a unique document store name
var mongoURI = "mongodb://localhost:27017/prime_example_passport";
var MongoDB = mongoose.connect(mongoURI).connection;

//this tells mongo to let me know in the console if it experiences errors
MongoDB.on('error', function(err){
    console.log('mongodb connection error', err);
});

//this will trigger and tell me once mongo is working
MongoDB.once('open', function(){
    console.log('mongodb connection open');
});

//serialize and deserialize allow user information to be stored and retrieved from the session
passport.serializeUser(function(user, done){
    done(null, user.id);
});

passport.deserializeUser(function(id, done){
    User.findById(id, function(err, user){
        if(err) done(err);
        done(null, user);
    });
});

passport.use('local', new localStrategy({
    passReqToCallback : true,
    usernameField: 'username'
},
function(req, username, password, done){
    User.findOne({username: username}, function(err, user){
        if(err) throw err;
        if(!user)
            return done(null, false, {message: 'Incorrect username and password.'});

        //test a matching password
        user.comparePassword(password, function(err, isMatch){
            if(err) throw err;
            if(isMatch)
                return done(null, user);
            else
                done(null, false, {message: 'Incorrect username and password.'});
        });
    });
}));

app.use('/register', register);
app.use('/', index);