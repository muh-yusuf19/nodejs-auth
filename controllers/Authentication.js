const jwt = require("jsonwebtoken")
const bcrypt = require("bcrypt")
const User = require("../model/User")
const sendEmail = require("../Helpers/sendEmail")

const handleRegister = async (req, res) => {
    try {
        const { user, pwd } = req.body
        if (!user || !pwd)
            return res
                .status(400)
                .json({ message: "Username and password are required." })

        // check for duplicate usernames in the db
        const duplicate = await User.findOne({ username: user }).exec()

        // Conflic
        if (duplicate) return res.sendStatus(409)

        //encrypt the password
        const hashedPwd = await bcrypt.hash(pwd, 10)

        //create and store the new user
        const result = await User.create({
            username: user,
            email: req.body.email,
            password: hashedPwd,
        })

        res.status(201).json({ success: `New user ${user} created!` })
    } catch (err) {
        res.status(500).json(err)
    }
}

const handleLogin = async (req, res) => {
    try {
        const cookies = req.cookies
        // Test if cookie still available
        console.log(`cookie available at ${JSON.stringify(cookies)}`)

        const { user, pwd } = req.body
        if (!user || !pwd)
            return res
                .status(400)
                .json({ message: "Username and password are required." })

        const foundUser = await User.findOne({ username: user }).exec()
        if (!foundUser) return res.sendStatus(401) //Unauthorized

        // evaluate password
        const match = await bcrypt.compare(pwd, foundUser.password)
        if (match) {
            // Create access token
            const accessToken = jwt.sign(
                {
                    username: foundUser.username,
                    admin: foundUser.isAdmin,
                },
                process.env.JWT_SEC,
                { expiresIn: "20s" }
            )

            // Create refresh token
            const newRefreshToken = jwt.sign(
                { username: foundUser.username },
                process.env.JWT_SEC,
                { expiresIn: "30s" }
            )

            const newRefreshTokenArray = !cookies?.jwt
                ? foundUser.refreshToken
                : foundUser.refreshToken.filter((rt) => rt !== cookies.jwt)

            if (cookies.jwt)
                res.clearCookie("jwt", {
                    httpOnly: true,
                    sameSite: "None",
                    secure: true,
                })

            foundUser.refreshToken = [...newRefreshTokenArray, newRefreshToken]
            const result = await foundUser.save()

            console.log(result)

            // Creates secure cookie with refresh token
            res.cookie("jwt", newRefreshToken, {
                httpOnly: true,
                sameSite: "None",
                maxAge: 24 * 60 * 60 * 1000,
            })

            // Send authorization roles and access token to user
            res.json({ admin: foundUser.isAdmin, accessToken })
        } else {
            res.sendStatus(401)
        }
    } catch (err) {
        res.status(500).json(err)
    }
}

const handleRefreshToken = async (req, res) => {
    try {
        // Check cookies
        const cookies = req.cookies
        if (!cookies?.jwt) return res.status(401).json("Cannot find token")
        const refreshToken = cookies.jwt
        res.clearCookie("jwt", { httpOnly: true, sameSite: "None" })

        const foundUser = await User.findOne({ refreshToken }).exec()

        if (foundUser) {
            const newRefreshTokenArray = foundUser.refreshToken.filter(
                (rt) => rt !== refreshToken
            )

            // Verify jwt
            jwt.verify(
                refreshToken,
                process.env.JWT_SEC,
                async (err, decoded) => {
                    // Refresh token error
                    if (err) {
                        console.log("Expired refresh token")
                        foundUser.refreshToken = [...newRefreshTokenArray]
                        const result = await foundUser.save()
                        console.log(result)
                    }
                    if (err || decoded.username !== foundUser.username) {
                        console.log("Invalid Token")
                        return res.sendStatus(403)
                    } else {
                        // Create access token
                        const accessToken = jwt.sign(
                            {
                                username: foundUser.username,
                                admin: foundUser.isAdmin,
                            },
                            process.env.JWT_SEC,
                            { expiresIn: "30s" }
                        )

                        // Create refresh token
                        const newRefreshToken = jwt.sign(
                            { username: foundUser.username },
                            process.env.JWT_SEC,
                            { expiresIn: "1m" }
                        )

                        foundUser.refreshToken = [
                            ...newRefreshTokenArray,
                            newRefreshToken,
                        ]
                        const response = await foundUser.save()

                        // Creates secure cookie with refresh token
                        res.cookie("jwt", newRefreshToken, {
                            httpOnly: true,
                            sameSite: "None",
                            maxAge: 24 * 60 * 60 * 1000,
                        })

                        res.json({ admin: foundUser.isAdmin, accessToken })
                    }
                }
            )
        } else {
            // Detec refreshtoken reuse
            jwt.verify(
                refreshToken,
                process.env.JWT_SEC,
                async (err, decoded) => {
                    if (err) res.status(403).json("Cannot find the user")
                    const hackedUser = await User.findOne({
                        username: docoded.username,
                    }).exec()
                    hackedUser.refreshToken = []
                    const result = await hackedUser.save()
                    console.log(result)
                }
            )
            res.status(403).json("Cannot find the user")
        }
    } catch (err) {
        res.status(500).json(err)
    }
}

const handleLogout = async (req, res) => {
    // res.status(201).json("Logout")

    try {
        const cookies = req.cookies
        if (!cookies?.jwt) return res.sendStatus(204) //No content
        const refreshToken = cookies.jwt

        // Is refreshToken in db?
        const foundUser = await User.findOne({ refreshToken }).exec()
        if (!foundUser) {
            res.clearCookie("jwt", { httpOnly: true, sameSite: "None" })
            return res.sendStatus(204)
        }

        // Delete refreshToken in db
        foundUser.refreshToken = foundUser.refreshToken.filter(
            (rt) => rt !== refreshToken
        )
        const result = await foundUser.save()
        console.log(result)

        res.clearCookie("jwt", { httpOnly: true, sameSite: "None" })
        res.sendStatus(204)
    } catch (err) {
        res.status(500).json(err)
    }
}

const handleForgotPassword = async (req, res) => {
    try {
        const email = req.body.email
        if (!email) res.status(400).json("Email required")

        const foundUser = await User.findOne({ email: email }).exec()

        if (!foundUser) res.status(204).json("Invalid Email")

        const resetToken = jwt.sign(
            {
                email: foundUser.email,
                username: foundUser.username,
            },
            process.env.JWT_SEC,
            { expiresIn: "10m" }
        )

        foundUser.resetToken = [resetToken]
        const response = await foundUser.save()

        console.log(response)

        // //Send Email
        // const text = `Here your reset password link. Please don't share this link with anyone ${process.env.CLIENT}reset-password/${foundUser.email}/${resetToken}`

        // await sendEmail(foundUser.email, "Reset Password", text)
        res.cookie("resetToken", resetToken, {
            httpOnly: true,
            sameSite: "None",
            maxAge: 24 * 60 * 60 * 1000,
        })
        res.status(201).json(
            "Reset password link has been sended to your email. The link will be expired in 10 minutes"
        )
    } catch (err) {
        res.status(500).json(err)
    }
}

const handleResetPassword = async (req, res) => {
    const cookie = req.cookies
    if (!cookie.resetToken) res.status(401).json("Invalid link")

    const resetToken = cookie.refreshToken

    res.clearCookie("resetToken", { httpOnly: true, sameSite: "None" })

    const foundUser = await User.findOne({ resetToken }).exec()

    if (foundUser) {
        const newResetTokenArray = foundUser.resetToken.filter(
            (rt) => rt !== resetToken
        )

        jwt.verify(resetToken, process.env.JWT_SEC, async (err, decoded) => {
            if (err) {
                console.log("Expired refresh token")
                foundUser.resetToken = [...newResetTokenArray]
                const result = await foundUser.save()
                console.log(result)
            } else {
                const pwd = req.body.password
                const hashedPwd = await bcrypt.hash(pwd, 10)

                foundUser.password = hashedPwd
                foundUser.resetToken = []

                const result = await foundUser.save()

                res.status(201).json({
                    success: `User with email ${result.email} password has been reset`,
                })
            }
        })
    } else {
        jwt.verify(resetToken, process.env.JWT_SEC, async (err, decoded) => {
            if (err) res.status(403).json("Cannot find the user")
            const hackedUser = await User.findOne({
                username: docoded.email,
            }).exec()
            hackedUser.resetToken = []
            const result = await hackedUser.save()
            console.log(result)
        })
        res.status(403).json("Cannot find the user")
    }
}

module.exports = {
    handleRegister,
    handleLogin,
    handleLogout,
    handleRefreshToken,
    handleForgotPassword,
    handleResetPassword,
}
