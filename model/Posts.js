const mongoose = require('mongoose');
 
const Schema = mongoose.Schema;

const PostSchema = new Schema({

    userid : 
        {
            type: Schema.Types.ObjectId, ref: 'User'
        },

        caption : {
            type : String,
        },
        image : {
            type : String,
        },
        created_at : { 
            type : Date, 
            default: Date.now 
        },
        updated_at : {
            type : String,
            default : null
        }


    

});

const Post = mongoose.model('post', PostSchema);

module.exports = Post;