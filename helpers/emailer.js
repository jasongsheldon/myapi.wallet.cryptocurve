var nodemailer = require('nodemailer')
var smtpTransport = require('nodemailer-smtp-transport')
var config = require('../config/config.js')

var emailer = {
  
  sendMail: function(subject, text, callback) {

    var mailOptions = {
      from: '"Shoprite Insurance" <processing@mfin.co.za>',
      to: 'tech@mfin.io',
      subject: subject,
      text: text
    }

    emailer._sendMail(mailOptions, callback)
  },

  _sendMail: function(mailOptions, callback) {
    var smtpConfig = {
      host: config.emailerHost,
      port: 587,
      secure: false, // use SSL
      tls : { rejectUnauthorized: false },
      auth: {
        user: config.emailerUser,
        pass: config.emailerPassword
      }
    }

    var transporter = nodemailer.createTransport(smtpTransport(smtpConfig))
    transporter.sendMail(mailOptions, function(error, info) {
      if (error) {
        console.log(error)
        return
      }
      console.log('Message sent: ' + info.response)

      if (callback != null) {
        callback(error, info)
      }
    })
  }
}

module.exports = emailer
