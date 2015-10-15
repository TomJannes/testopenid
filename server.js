//Module dependencies
var express = require('express');
var http = require('http');
var passport = require('passport');
var session = require('express-session');
var bodyParser = require('body-parser');
var logger = require('morgan');
var OidcStrategy = require('./myopenidconnect').Strategy;
var config = require('config');
var User = require('./models/user');
var mongoose = require('mongoose');
var jwt = require('jsonwebtoken');
var fs = require('fs'); //todo move to application startup

mongoose.connect(config.get('connectionstring'));

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
  done(null, user.id);
});

passport.deserializeUser(function(identifier, done) {
  
  User.findById(function(err, user){
    if(err) { done(err, null); }
    if(!user) { done(null, false); }
       done(null, user);
    })
});

passport.use(new OidcStrategy({
                authorizationURL: config.get('authorization.serverurl') + '/dialog/authorize',
                tokenURL: config.get('authorization.serverurl') + '/oauth/token',
                userInfoURL: config.get('authorization.serverurl') + '/oauth/profile',
                clientID: config.get('client.id'),
                clientSecret: config.get('client.secret'),
                callbackURL: config.get('authorization.callbackurl'),
                responseType: 'code',
                prompt: 'none'
            },
            function (iss, sub, profile, accessToken, refreshToken, params, done) {
              var rawIdToken = params['id_token'];
              fs.readFile('public_key.pem', 'utf8', function(err, cert) {
                if (err) throw err;
                var verificationChecks = {
                  audience: config.get('client.id'),
                  issuer: config.get('openidconnect.issuer')
                };
                jwt.verify(rawIdToken, cert, verificationChecks, function(err, decoded) {
                  if(err) { done(err, null); }
                  User.findOne({sub: decoded.sub}, function(err, user){
                    if(err) { done(err, null); }
                    if(!user) { done(null, false); }
                    done(null, user);
                  });
                });
              });
            })
);

app.get('/',
  passport.authenticate('myopenidconnect', { failureRedirect: '/login' }),
  function(req, res) {
    res.send('woohoo');
  });

app.get('/login',
    passport.authenticate('myopenidconnect', { failureRedirect: '/login', failureFlash: true }),
    function(req, res) {
        res.redirect('/');
    });

app.get('/callback',
  passport.authenticate('myopenidconnect', { failureRedirect: '/login' }),
  function(req, res) {
    res.send('why cant i redirect here?');
  });

if(config.has('server.port')){
  process.env.PORT = config.get('server.port');
}
if(config.has('server.ip')){
  process.env.IP = config.get('server.ip');
}
http.createServer(app).listen(process.env.PORT || 3000, process.env.IP || "0.0.0.0");
