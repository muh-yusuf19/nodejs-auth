const express = require('express')
const router = express.Router()
const { handleLogin, handleRegister, handleLogout, handleRefreshToken, handleForgotPassword, handleResetPassword } = require('../controllers/Authentication')

router.post('/auth', handleLogin)
router.post('/register', handleRegister)
router.get('/logout', handleLogout)
router.get('/refresh', handleRefreshToken)
router.post('/forgot-password', handleForgotPassword)
router.post('/reset-password', handleResetPassword)

module.exports = router