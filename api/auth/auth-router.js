const router = require("express").Router();
const jwt = require('jsonwebtoken')
const bcrypt = require("bcryptjs")
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET } = require("../secrets"); // use this secret!'
const User = require('../users/users-model')

router.post("/register", validateRoleName, (req, res, next) => {
  const user = req.body

  const hash = bcrypt.hashSync(user.password, 8)
  user.password = hash
  user.role_name = req.role_name
  User.add(user)
  .then(newUser => {
    res.status(201).json(newUser)
  })
  .catch(err => next(err))
  
  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
});


router.post("/login", checkUsernameExists, (req, res, next) => {
  const {username, password} = req.body

  User.findBy({username: username})
    .then(([user]) => {
      if (user && bcrypt.compareSync(password, user.password)) {
        const token = buildToken(user)
        res.status(200).json({message: `${username} is back!`, token})
      } else {
        next({status: 401, message: "Invalid credentials"})
      }
    })
    .catch(next)
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
});

function buildToken(user) {
  const payload = {
    subject: user.user_id,
    username: user.username,
    role_name: user.role_name
  }
  const options = {
    expiresIn: '1d'
  }
  return jwt.sign(payload, JWT_SECRET, options)
}

module.exports = router;
