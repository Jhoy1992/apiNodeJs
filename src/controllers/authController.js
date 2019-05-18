const express = require('express');

const User = require('../models/User');

const router = express.Router();

router.post('/register', async (req, resp) => {
    const { email } = req.body;

    try {
        if (await User.findOne({ email }))
            return resp.status(400).send({ error: 'User already exists' });

        const user = await User.create(req.body);

        user.password = undefined;
        
        return resp.send({ user });
    } catch (err){
        return resp.status(400).send({ error: 'Registration failed' });
    }
});

module.exports = app => app.use('/auth', router)