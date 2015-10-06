//Module dependencies
var express = require('express');
var http = require('http');
var passport = require('passport');
var session = require('express-session');
var bodyParser = require('body-parser');
var logger = require('morgan');
var OidcStrategy = require('./myopenidconnect').Strategy;
var config = require('config');

// Express configuration
var app = express();
app.set('views', __dirname + '/views');
app.set('view engine', 'jade');
app.use(bodyParser());
app.use(session({ secret: 'keyboard cat1'}));
app.use(logger('dev'));

app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser(function(user, done) {
  done(null, user.identifier);
});

passport.deserializeUser(function(identifier, done) {
  done(null, { identifier: identifier });
});

passport.use(new OidcStrategy({
                authorizationURL: config.get('authorization.serverurl') + '/dialog/authorize',
                tokenURL: config.get('authorization.serverurl') + '/oauth/token',
                userInfoURL: config.get('authorization.serverurl') + '/oauth/profile',
                clientID: config.get('client.id'),
                clientSecret: config.get('client.clientSecret'),
                callbackURL: config.get('authorization.callbackurl'),
                responseType: 'code'
            },
            function (iss, sub, profile, done) {
                var temp = 'test';
            })
);



app.get('/login',
    passport.authenticate('myopenidconnect', { failureRedirect: '/login', failureFlash: true }),
    function(req, res) {
        res.redirect('/');
    });

app.get('/callback',
  passport.authenticate('myopenidconnect', { failureRedirect: '/login' }),
  function(req, res) {
    res.redirect('/');
  });

if(config.has('server.port')){
  process.env.PORT = config.get('server.port');
}
if(config.has('server.ip')){
  process.env.IP = config.get('server.ip');
}
http.createServer(app).listen(process.env.PORT || 3000, process.env.IP || "0.0.0.0");
