const jwt = require('jsonwebtoken');
const User = require('../model/User');
const config = require('../config');


let checkUserToken = (req, res, next) => {
    let token = req.headers['x-access-token'] || req.headers['authorization']; // Express headers are auto converted to lowercase
  
  
    if (token) {
      if (token.startsWith('Bearer ')) {
          // Remove Bearer from string
          token = token.slice(7, token.length);
        }
        
      jwt.verify(token, config.secret, async (err, decoded) => {
        if (err) {
          return res.json([{
            success: false,
            message: 'Token is not valid'
          }]);
        } else {
          req.decoded = decoded;
          
          const user = await User.findOne({
            _id: decoded.id, 'tokens.token': token
        })
        
        if(!user){
          return res.json([{
            success: false,
            message: 'Please Authenticate'
          }]);
        }
        req.user = user
        req.userid = user._id;
          next();
        }
      });
    } else {
      return res.json([{
        success: false,
        message: 'Please Authenticate'
      }]);
    }
  };

  module.exports = checkUserToken;