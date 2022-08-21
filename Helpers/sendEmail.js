const nodemailer = require("nodemailer")

module.exports = async (email, subject, text) => {

	try{

		const transporter = nodemailer.createTransport({
			host: "smtp.mailtrap.io",
		 	port: 2525,
		 	auth: {
			    user: "a5a6a81b024888",
			    pass: "87fc357dafad8f"
			}
		})

		await transporter.sendMail({
			from: 'yusuf-nodejs@mail.com',
			to: email,
			subject: subject,
			text: text
		})

		console.log("Email sucessfully sended")

	}catch(err){

		console.log(err)

	}

}