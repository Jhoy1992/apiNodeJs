const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken')
const crypto = require('crypto');
const mailer = require('../../modules/mailer');

const authConfig = require('../../config/auth.json')

const User = require('../models/User');

const router = express.Router();

function generateToken(params = {}) {
    return jwt.sign(params, authConfig.secret, {
        expiresIn: 86400,
    })    
}

router.post('/register', async (req, resp) => {
    const { email } = req.body;

    try {
        if (await User.findOne({ email }))
            return resp.status(400).send({ error: 'User already exists' });

        const user = await User.create(req.body);

        user.password = undefined;
        
        return resp.send({
            user,
            token: generateToken({ id: user.id }),
        });
        
    } catch (err){
        return resp.status(400).send({ error: 'Registration failed' });
    }
});

router.post('/authenticate', async (req, resp) =>{
    const { email, password } = req.body;

    const user = await User.findOne({ email }).select('+password') ;

    if (!user)
        return resp.status(400).send({ error: 'User not found'});

    if (!await bcrypt.compare(password, user.password))
        return resp.status(400).send({ error: 'Invalid password'});

    user.password = undefined;    

    resp.send({ 
        user, 
        token: generateToken({ id: user.id }),
    });
})

router.post('/forgot_password', async(req, res) => {
    const { email } = req.body;

    try {
        const user = await User.findOne({ email });

        if (!user)
            return res.status(400).send({ error: 'User not found'});

        const token = crypto.randomBytes(20).toString('hex');

        const now = new Date();
        now.setMinutes(now.getMinutes() + 15);

        await User.findByIdAndUpdate(user.id, {
            '$set': {
                passwordResetToken: token,
                passwordResetExpires: now,
            }
        });

        mailer.sendMail({
            to: email,
            from: 'jhonatanascari@gmail.com',
            subject: 'Recovery Passqord',
            html: `<p>Você esqueceu sua senha? Mão tem problema, utilize esse token: ${token}</p>`,
        }, (err) => {            
            if (err)                             
              return res.status(400) .send({ error: 'Cannot send forgot password mail' });

            return res.send();
        })

    } catch (err) {        
        res.status(400).send({ error: 'Error on forgot password, try again'});
    }
})

router.post('/reset_password', async(req, res) => {
    const { email, token, password }    = req.body;

    try {
        const user = await User.findOne({ email })
            .select('+passwordResetToken passwordResetExpires');

         if (!user)
            return res.status(400).send({ error: 'User not found' })

        if (token !== user.passwordResetToken)
            return res.status(400).send({ error: 'Token invalid' })

        const now = new Date();

        if (now > user.passwordResetExpires)
            return res.status(400).send({ error: 'Token expired, generate a new one' })

        user.password = password;
        user.passwordResetExpires = undefined;
        user.passwordResetToken = undefined;

        await user.save();

        res.send();
    } catch (err) {
        res.status(400).send({ error: 'Cannot reset password, try again' })
    }
})

module.exports = app => app.use('/auth', router)