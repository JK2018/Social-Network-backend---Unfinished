const express = require('express');
const router = express.Router();
const { check, validationResult } = require('express-validator');
const gravatar = require('gravatar');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('config');

const User = require('../../models/User')

// @route       POST api/users
// @desc        Register user
// @access      Public
router.post('/',[
    check('name', 'Name is required').not().isEmpty(),
    check('email', 'Please include a valid email address').isEmail(),
    check('password', 'Please enter a password of 6 or more characters').isLength({min: 6})
], 
async (req, res) => {
    const errors = validationResult(req);
    if(!errors.isEmpty()){
        return res.status(400).json({errors: errors.array()})
    }
    const { name, email, password } = req.body;
    // check if user already exists
    try {
        let user = await User.findOne({ email });
        if(user){
            return res.status(400).json({ errors: [{ msg: 'User already exists'}]});
        }
        //else:
        //get avatar from gravatar
        const avatar = gravatar.url(email, {
            s: '200',
            r: 'pg',
            d: 'mm'
        });
        // create user
        user = new User({
            name,
            email,
            avatar,
            password
        });
        // hash password
        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(password, salt);
        //save user
        await user.save();
        // return jwt token
        const payload = {
            user: {
                id: user.id
            }
        }
        jwt.sign(payload, config.get('jwtSecret'), {expiresIn: 360000},
        (err, token) => {
            if(err) throw err;
            res.json({token});
        });

        //res.send('User route');
        //console.log(req.body)
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
    
});

module.exports = router;