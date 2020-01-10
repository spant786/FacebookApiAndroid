const express = require('express');
const router = express.Router();
const authcontrol = require('../controller/AuthController');
const authcontroller = new authcontrol;


router.post('/login', authcontroller.login);
router.post('/register', authcontroller.register);
router.post('/checkemail', authcontroller.checkEmailAvailability);




module.exports = router;