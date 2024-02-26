const nodemailer = require("nodemailer");
const asyncHandler = require("express-async-handler");

const sendEmail = asyncHandler(async (data, req, res) => {
    const transporter = nodemailer.createTransport({
        host: "smtp.gmail.com",
        port: 465,
        secure: true,
        auth: {
            user: process.env.MAIL_ID, // generated ethereal user
            pass: process.env.MP, // generated ethereal password
        },
       
        debug: true,
    });

    let info; // Declare info outside the try block

    try {
        // send mail with defined transport object
        info = await transporter.sendMail({
            from: '"Hey 👻" <abc@gmail.com.com>',
            to: data.to,
            subject: data.subject,
            text: data.text,
            html: data.htm,
        });
        console.log("Message sent: %s", info.messageId);
    } catch (error) {
        console.error("Error sending email:", error);
    } finally {
        // Preview only available when sending through an Ethereal account
        if (info) {
            console.log("Preview URL: %s", nodemailer.getTestMessageUrl(info));
        }
        transporter.close();
    }
});

module.exports = { sendEmail };
