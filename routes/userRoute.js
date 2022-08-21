const express = require('express')
const router = express.Router()
const { getAllUsers } = require("../controllers/UsersController")
const verifyJWT = require("../middleware/verifyJWT")

router.get('/', verifyJWT, getAllUsers)

module.exports = router