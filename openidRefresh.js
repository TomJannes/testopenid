'use strict';

var OAuth2 = require('oauth').OAuth2;

var AuthTokenRefresh = {};

AuthTokenRefresh._strategies = {};

/**
 * Register a passport strategy so it can refresh an access token,
 * with optional `name`, overridding the strategy's default name.
 *
 * Examples:
 *
 *     refresh.use(strategy);
 *     refresh.use('facebook', strategy);
 *
 * @param {String|Strategy} name name of the strategy
 * @param {Strategy} passport strategy the actual strategy
 * @returns
 */
AuthTokenRefresh.use = function(name, strategy) {
  if (arguments.length === 1) {
    // Infer name from strategy
    strategy = name;
    name = strategy && strategy.name;
  }

  if (strategy == null) {
    throw new Error('Cannot register: strategy is null');
  }

  if (!name) {
    throw new Error('Cannot register: name must be specified, or strategy must include name');
  }

  AuthTokenRefresh._strategies[name] = strategy;
};

/**
 * Check if a strategy is registered for refreshing.
 * @param  {String}  name Strategy name
 * @return {Boolean}
 */
AuthTokenRefresh.has = function(name) {
  return !!AuthTokenRefresh._strategies[name];
};

/**
 * Request a new access token, using the passed refreshToken,
 * for the given strategy.
 * @param  {String}   name         Strategy name. Must have already
 *                                 been registered.
 * @param  {String}   refreshToken Refresh token to be sent to request
 *                                 a new access token.
 * @param  {Function} done         Callback when all is done.
 */
AuthTokenRefresh.requestNewAccessToken = function(name, refreshToken, done) {
  // Send a request to refresh an access token, and call the passed
  // callback with the result.
  var strategy = AuthTokenRefresh._strategies[name];
  if (!strategy) {
    return done(new Error('Strategy was not registered to refresh a token'));
  }

  var params = { grant_type: 'refresh_token', scope: 'openid profile' };
  var oauth2 = new OAuth2(strategy._clientID, strategy._clientSecret, '', strategy._authorizationURL, strategy._tokenURL);
  oauth2.getOAuthAccessToken(refreshToken, params, done);
};

module.exports = AuthTokenRefresh;
