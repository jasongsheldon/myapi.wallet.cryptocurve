var express = require('express')
var router = express.Router()
var model = require('../models/model.js')
var bodyParser = require('body-parser')
const sha256 = require('sha256')

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
      console.log(req.query)
      cb(null, file.fieldname+"_"+file.originalname+"_"+req.query.emailAddress+"_"+Date.now().toString())
    }
  })
})


router.get('/', function (req, res, next) {
  res.status(400)
  next(null, req, res, next)
})
router.post('/api/v1/uploadFileKYC', upload.single('kyc'), function(req, res, next) {
  res.status(205)
  res.body = { 'status': 200, 'success': true, 'uuid': sha256(req.file.key) }
  return next(null, req, res, next)
})
router.post('/api/v1/uploadFileID', upload.single('id'), function(req, res, next) {
  res.status(205)
  res.body = { 'status': 200, 'success': true, 'uuid': sha256(req.file.key) }
  return next(null, req, res, next)
})

//Add a new user to the whitelist.cryptocurve.network endpoint
router.post('/api/v2/whitelist', bodyParser.json(), model.whitelist)

//Validate if a user has whitelisted via whitelist.cryptocurve.network endpoint
router.post('/api/v2/whitelistStatus', bodyParser.json(), model.whitelistStatus)

//Update the current state for whitelist participants
router.post('/api/v1/whitelistState', bodyParser.json(), model.whitelistState)
router.post('/api/v2/login', bodyParser.json(), model.login)
router.post('/api/v2/check', bodyParser.json(), model.check)

router.post('/api/v1/ethPrivateKeyUnlock', bodyParser.json(), model.ethPrivateKeyUnlock)
/*router.post('/api/v1/wanPrivateKeyUnlock', bodyParser.json(), model.wanPrivateKeyUnlock)
router.post('/api/v1/ethJsonv3Unlock', bodyParser.json(), model.ethJsonv3Unlock)
router.post('/api/v1/wanJsonv3Unlock', bodyParser.json(), model.wanJsonv3Unlock)
router.post('/api/v1/ethMnemonic', bodyParser.json(), model.ethMnemonic)
router.post('/api/v1/wanMnemonic', bodyParser.json(), model.wanMnemonic)*/


/* NETKI Integration Callback */
router.post('/api/v2/verificationCallback', bodyParser.json(), model.verificationCallback)

module.exports = router
