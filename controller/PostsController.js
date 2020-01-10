const post = require('../model/Posts');
const user = require('../model/User');
const formidable = require('formidable');

const path = require('path');
class PostsController {


    addPosts(req, res){

        req.files.map(function(item){
            var imagename = item.filename;
            post.create({
                userid : req.userid,
                caption : req.body.caption,
                image : imagename,
                 
            }, function(err, postres){

                post.findById({_id : postres._id}).populate('userid','firstname lastname image', user).exec(function(err, posts){
                    if(err) return res.send([{
                        success : false,
                        message : "Something"
                    }]);
        
                    
                    return res.status(200).json([{
                        success : true,
                        message : "Post Uploaded Successfully",
                       posts : posts
                }]);
                   
                });
    
                
    
            });
        })

    }


    getPost(req, res){
        post.find().populate('userid','firstname lastname image', user).exec(function(err, posts){
        if(err) return res.send([{
            success : false,
            message : err.message
        }]);

        return res.status(200).send(
            
            
                 
                posts
               
            
        );

        })
    }

}

module.exports = PostsController;