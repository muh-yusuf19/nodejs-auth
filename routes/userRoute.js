const express = require("express")
const router = express.Router()
const { getAllUsers } = require("../controllers/UsersController")
const verifyJWT = require("../middleware/verifyJWT")
const verifyAdmin = require("../middleware/verifyAdmin")

router.get("/", verifyAdmin, getAllUsers)

module.exports = router
