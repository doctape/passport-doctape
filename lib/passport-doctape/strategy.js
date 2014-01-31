/**
 * Module dependencies.
 */
var util = require('util')
  , OAuth2Strategy = require('passport-oauth').OAuth2Strategy;


/**
 * `Strategy` constructor.
 *
 * The doctape authentication strategy authenticates requests by delegating to
 * doctape using the OAuth 2.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and service-specific `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `clientID`      your doctape application's client id
 *   - `clientSecret`  your doctape application's client secret
 *   - `callbackURL`   URL to which doctape will redirect the user after granting authorization
 *
 * Examples:
 *
 *     passport.use(new doctapeStrategy({
 *         clientID: '123-456-789',
 *         clientSecret: 'shhh-its-a-secret'
 *         callbackURL: 'https://www.example.net/auth/doctape/callback'
 *       },
 *       function(accessToken, refreshToken, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
  options = options || {};
  options.baseURL = options.baseURL || 'https://my.doctape.com';
  options.authorizationURL = options.authorizationURL || options.baseURL + '/oauth2';
  options.tokenURL = options.tokenURL || options.baseURL + '/oauth2/token';
  
  OAuth2Strategy.call(this, options, verify);
  this.name = 'doctape';
  this.baseURL = options.baseURL;
}

/**
 * Inherit from `OAuth2Strategy`.
 */
util.inherits(Strategy, OAuth2Strategy);


/**
 * Retrieve user profile from doctape.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `provider`         always set to `doctape`
 *   - `id`               the user's doctape ID
 *   - `username`         the user's doctape username
 *   - `displayName`      the user's full name
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */
Strategy.prototype.userProfile = function(accessToken, done) {
  // TODO: doctape provides user profile information in the access token
  //       response.  As an optimization, that information should be used, which
  //       would avoid the need for an extra request during this step.  However,
  //       the internal node-oauth module will have to be modified to support
  //       exposing this information.

  var self = this;

  this._oauth2.get(self.baseURL + '/v1/account', accessToken, function (err, body, res) {
    if (err) { return done(err); }
    
    try {
      var json = JSON.parse(body);

      var profile = { provider: 'doctape' };
      profile.username = json.result.username;
      profile.email = json.result.email;
      profile._raw = body;
      profile._json = json;
      
      done(null, profile);
    } catch(e) {
      done(e);
    }
  });
}


/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
