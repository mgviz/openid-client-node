//Import dependencies
var url = require('url');
var jwt = require('jwt-simple');

//Configuration values
var config = { id: '', secret: '', url: 'https://account.mgviz.org' };

//Set the client configuration
module.exports.config = function(obj)
{
  //Check for undefined object
  if(typeof obj !== 'object'){ return; }

  //Extend the configuration object
  config = Object.assign(config, obj);

  //Parse the client id
  if(typeof config.id === 'string'){ config.id = config.id.trim(); }

  //Parse the client secret key
  if(typeof config.secret === 'string'){ config.secret = config.secret.trim(); }
};

//Build the authentication url
module.exports.login = function(cb)
{
  //Check the client id
  if(typeof config.id !== 'string' || config.id === ''){ return cb(new Error('No client ID provided')); }

  //Check the client secret key
  if(typeof config.secret !== 'string' || config.secret === ''){ return cb(new Error('No client secret key provided')); }

  //Build the authorization url
  var auth_url = url.resolve(config.url, '/authorize?app_id=' + config.id);

  //Return the url
  return cb(null, auth_url);
};

//Decode and authenticate an user
module.exports.authenticate = function(token, cb)
{
  //Check the client id
  if(typeof config.id !== 'string' || config.id === ''){ return cb(new Error('No client ID provided')); }

  //Check the client secret key
  if(typeof config.secret !== 'string' || config.secret === ''){ return cb(new Error('No client secret key provided')); }

  //Decode the json
  try
  {
    //Decode the token
    var obj = jwt.decode(token, config.secret);

    //Check the creation and the expiration time
    if(typeof obj.iat !== 'number' || typeof obj.exp !== 'number'){ return cb(new Error('Invalid token'), {}); }

    //Get the actual time in seconds
    var time_now = new Date().getTime() / 1000;

    //Check for a valid token
    if(time_now < obj.iat){ return cb(new Error('Invalid token'), {}); }

    //check for an expired token
    if(obj.exp < time_now){ return cb(new Error('Expired token'), {}); }

    //Do the callback
    return cb(null, obj);
  }
  catch(error)
  {
    //Return with the error
    return cb(error, {});
  }
};

