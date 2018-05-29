const aws = require('aws-sdk')

const multer = require("multer")
const multerS3 = require("multer-s3")

const s3 = new aws.S3({apiVersion: '2006-03-01'})

var upload = multer({
  storage: multerS3({
    s3: s3,
    bucket: 'kyc.cryptocurve.network',
    metadata: function (req, file, cb) {
      cb(null, {fieldName: file.fieldname});
    },
    key: function (req, file, cb) {
      cb(null, Date.now().toString())
    }
  })
})
