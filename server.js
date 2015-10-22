'use strict';
// Module dependencies

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
var fs = require('fs'); // todo move to application startup
var ensureLogin = require('connect-ensure-login');
var refresh = require('./openidRefresh');
var path = require('path');

mongoose.connect(config.get('connectionstring'));

// Express configuration
var app = express();
app.set('views', path.join(__dirname, '/views'));
app.set('view engine', 'jade');
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({
  extended: true
}));

app.use(session({
  secret: 'keyboard cat1',
  resave: false,
  saveUninitialized: true
}));
app.use(logger('dev'));

app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser(function(user, done) {
  return done(null, user.id);
});

passport.deserializeUser(function(identifier, done) {
  User.findById(identifier, function(err, user) {
    if (err) { return done(err, null); }
    if (!user) { return done(null, false); }
    var needsToRefresh = new Date() > new Date(user.accessToken.expiryDate.getTime() - config.get('openidconnect.refresh_treshold') * 60000);
    if (needsToRefresh) {
      refresh.requestNewAccessToken('myopenidconnect', user.refreshToken.token, function(refreshErr, accessToken, refreshToken, params) {
        if (refreshErr) { return done(refreshErr, null); }
        user.accessToken.token = accessToken;
        user.accessToken.expiryDate = params.expires_in;
        user.refreshToken.token = refreshToken;
        user.save(function(userSaveErr) {
          if (userSaveErr) { return done(userSaveErr, null); }
          return done(null, user);
        });
      });
    } else {
      return done(null, user);
    }
  });
});

var myopenidconnectStrategy = new OidcStrategy({
  authorizationURL: config.get('authorization.serverurl') + '/dialog/authorize',
  tokenURL: config.get('authorization.serverurl') + '/oauth/token',
  userInfoURL: config.get('authorization.serverurl') + '/oauth/profile',
  clientID: config.get('client.id'),
  clientSecret: config.get('client.secret'),
  callbackURL: config.get('authorization.callbackurl'),
  responseType: 'code',
  prompt: 'none'
},
function(iss, sub, profile, accessToken, refreshToken, params, done) {
  var rawIdToken = params.id_token;
  fs.readFile('public_key.pem', 'utf8', function(err, cert) {
    if (err) { throw err; }
    var verificationChecks = {
      audience: config.get('client.id'),
      issuer: config.get('openidconnect.issuer')
    };
    jwt.verify(rawIdToken, cert, verificationChecks, function(verificationErr, decoded) {
      if (verificationErr) { return done(verificationErr, null); }
      User.findOne({sub: decoded.sub}, function(findUserErr, user) {
        if (findUserErr) { return done(findUserErr, null); }
        if (!user) { return done(null, false); }
        user.accessToken = {
          token: accessToken,
          expiryDate: params.expires_in
        };
        user.refreshToken = {
          token: refreshToken
        };
        user.save(function(userSaveErr) {
          if (userSaveErr) { return done(userSaveErr); }
          return done(null, user);
        });
      });
    });
  });
});

passport.use('myopenidconnect', myopenidconnectStrategy);
refresh.use('myopenidconnect', myopenidconnectStrategy);

app.get('/',
  function(req, res) {
    res.send('woohoo');
    res.end();
  });

app.get('/login',
    passport.authenticate('myopenidconnect', { failureRedirect: '/login', session: true }),
    function(req, res) {
      res.redirect('/');
    });

app.get('/callback',
  passport.authenticate('myopenidconnect', { failureRedirect: '/login', session: true }),
  function(req, res) {
    res.render('callback');
  });

app.get('/refresh',
  ensureLogin.ensureLoggedIn(),
  function(req, res) {
    res.render('refresh');

  });

app.post('/refresh',
  ensureLogin.ensureLoggedIn(),
  function(req, res) {
    res.send('refreshed');
  });

if (config.has('server.port')) {
  process.env.PORT = config.get('server.port');
}
if (config.has('server.ip')) {
  process.env.IP = config.get('server.ip');
}
http.createServer(app).listen(process.env.PORT || 3000, process.env.IP || '0.0.0.0');
