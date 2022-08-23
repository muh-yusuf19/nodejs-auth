require("dotenv").config()
const express = require("express")
const app = express()
const path = require("path")
const cors = require("cors")
const corsOptions = require("./config/corsOptions")
const { logger } = require("./middleware/logEvents")
const errorHandler = require("./middleware/errorHandler")
const verifyJWT = require("./middleware/verifyJWT")
const cookieParser = require("cookie-parser")
const credentials = require("./middleware/credentials")
const mongoose = require("mongoose")
const connectDB = require("./config/dbConn")
const PORT = process.env.PORT || 3500
const authRoute = require("./routes/authRoute")
const userRoute = require("./routes/userRoute")

// Connect to MongoDB
connectDB()

// custom middleware logger
app.use(logger)

// Handle options credentials check - before CORS!
// and fetch cookies credentials requirement
app.use(credentials)

// Cross Origin Resource Sharing
app.use(cors(corsOptions))

// built-in middleware to handle urlencoded form data
app.use(express.urlencoded({ extended: false }))

// built-in middleware for json
app.use(express.json())

//middleware for cookies
app.use(cookieParser())

// routes
app.use(authRoute)

app.use(verifyJWT)
app.use("/users", userRoute)

app.use(errorHandler)

mongoose.connection.once("open", () => {
    console.log("Connected to MongoDB")
    app.listen(PORT, () => console.log(`Server running on port ${PORT}`))
})
