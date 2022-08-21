const mongoose = require("mongoose")

const connectDB = async () => {
    try {
        await mongoose.connect(process.env.MONGGO_URL, {
            useUnifiedTopology: true,
            useNewUrlParser: true,
        })
    } catch (err) {
        console.error(err)
    }
}

module.exports = connectDB
