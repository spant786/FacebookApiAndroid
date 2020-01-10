const express = require('express');
const router = express.Router();
const postscontrol = require('../controller/PostsController');
const auth = require('../middleware/checkWebToken');
const uploadimage = require('../middleware/uploadimage');
const postscontroller = new postscontrol;


router.post('/addpost', [auth, uploadimage], postscontroller.addPosts);
router.post('/getposts',auth, postscontroller.getPost);



module.exports = router;