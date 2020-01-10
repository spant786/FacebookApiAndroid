const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const UserSchema = new Schema({

    firstname  : {
        type : String,
    },
    lastname : {
        type : String,
    },
    dob : {
        type : String,
    },
    gender : {
        type : String,
    },
    phonenumber:{
        type : Number,
    },
    email : {
        type : String,
    },
    password : {
        type : String,
    },
    image : {
        type : String,
        default : "profile.jpg"
    },
    tokens: [{
        token: {
            type: String,
            required: true
        }
    }]
});

const User = mongoose.model('user', UserSchema);
module.exports = User;