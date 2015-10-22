var mongoose = require('mongoose');
var BaseSchema = require('./baseSchema');

var userSchema = new BaseSchema({
    sub: { type: String, required: true },
    firstname: { type: String, required: true },
    lastname: { type: String, required: true },
    email: { type: String, required: true },
    username: { type: String, required: true, unique: true },
    accessToken: { 
        token: { type: String },
        expiryDate: { type: Date }
    },
    refreshToken: { 
        token: { type: String }
    }
});

var User = mongoose.model('User', userSchema);
module.exports = User;