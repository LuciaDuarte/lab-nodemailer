const { Router } = require('express');
const router = new Router();

const User = require('./../models/user');
const bcryptjs = require('bcryptjs');

const nodemailer = require('nodemailer');

const transport = nodemailer.createTransport({
  service: 'Gmail',
  auth: {
    user: process.env.NODEMAILER_EMAIL,
    pass: process.env.NODEMAILER_PASSWORD
  }
});

router.get('/', (req, res, next) => {
  res.render('index');
});

router.get('/sign-up', (req, res, next) => {
  res.render('sign-up');
});

router.post('/sign-up', (req, res, next) => {
  const { name, email, password } = req.body;

  const generateRandomToken = length => {
    const characters =
      '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    let token = '';
    for (let i = 0; i < length; i++) {
      token += characters[Math.floor(Math.random() * characters.length)];
    }
    return token;
  };

  let user;

  bcryptjs
    .hash(password, 10)
    .then(hash => {
      return User.create({
        name,
        email,
        passwordHash: hash,
        confirmationToken: generateRandomToken(15)
      });
    })
    .then(document => {
      user = document;
      req.session.user = user._id;
    })
    .then(() => {
      return transport.sendMail({
        from: process.env.NODEMAILER_EMAIL,
        to: process.env.NODEMAILER_EMAIL,
        subject: 'Confirm your account',
        html: `<html>
        <head>
        <style>
        div {
          background-color: #00b7ff;
        }

        p {
          text-align: center;
        }

        h2 {
          text-align: center;
        }
        </style>
        </head>
          <body>
            <div>
                <h2>Hello ${user.name}!</h2>
                <p>Thanks for joining us!</p> 
                <a href="http://localhost:3000/authentication/confirm-email?token=${user.confirmationToken}"> 
                <p>Please confirm your account!</p> 
                </a>
                <p>See you soon! 😎 </p> 
            </div>  
          </body>
        </html>`
      });
    })
    .then(() => {
      res.redirect('/');
    })
    .catch(error => {
      next(error);
    });
});

router.get('/sign-in', (req, res, next) => {
  res.render('sign-in');
});

router.post('/sign-in', (req, res, next) => {
  let userId;
  const { email, password } = req.body;
  User.findOne({ email })
    .then(user => {
      if (!user) {
        return Promise.reject(new Error("There's no user with that email."));
      } else {
        userId = user._id;
        return bcryptjs.compare(password, user.passwordHash);
      }
    })
    .then(result => {
      if (result) {
        req.session.user = userId;
        res.redirect('/');
      } else {
        return Promise.reject(new Error('Wrong password.'));
      }
    })
    .catch(error => {
      next(error);
    });
});

router.post('/sign-out', (req, res, next) => {
  req.session.destroy();
  res.redirect('/');
});

router.get('/authentication/confirm-email', (request, response, next) => {
  const token = request.query.token;

  User.findOneAndUpdate({ confirmationToken: token }, { status: 'active' })
    .then(() => {
      response.render('confirmation');
    })
    .catch(error => {
      next(error);
    });
});

const routeGuard = require('./../middleware/route-guard');

router.get('/private', routeGuard, (req, res, next) => {
  res.render('private');
});

router.get('/profile', routeGuard, (request, response, next) => {
  response.render('profile');
});

module.exports = router;
