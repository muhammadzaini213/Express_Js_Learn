const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
  host: process.env.MAIL_HOST,
  port: process.env.MAIL_PORT,
  secure: true,
  auth: {
    user: process.env.MAIL_USER,
    pass: process.env.MAIL_PASSWORD,
  },
});

transporter.verify(function(error, success) {
  if (error) {
    console.log('Error connecting to mail server:', error);
  } else {
    console.log('Server is ready to take our messages:', success);
  }
});

module.exports = { transporter };
