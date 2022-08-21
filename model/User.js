const mongoose = require("mongoose")

const UserSchema = new mongoose.Schema(
    {
        username: {
            type: String,
            required: [true, "Username harus diisi"],
            unique: [true, "Username sudah terdaftar"],
        },
        email: { type: String, required: true, unique: true },
        password: { type: String, required: true, unique: true },
        isAdmin: { type: Boolean, default: false },
        refreshToken: [String],
        resetToken: [String]
    },
    {
        timestamps: true,
    }
)

module.exports = mongoose.model("User", UserSchema)
