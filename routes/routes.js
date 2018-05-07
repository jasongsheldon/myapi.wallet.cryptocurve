var express = require('express')
var router = express.Router()
var model = require('../models/model.js')
var bodyParser = require('body-parser')


router.get('/', function (req, res, next) {
  res.status(400)
  next(null, req, res, next)
})

//Add a new user to the whitelist.cryptocurve.network endpoint
router.post('/api/v1/whitelist', bodyParser.json(), model.whitelist)

//Update the current state for whitelist participants
router.post('/api/v1/whitelistState', bodyParser.json(), model.whitelistState)

router.post('/api/v1/ethPrivateKeyUnlock', bodyParser.json(), model.ethPrivateKeyUnlock)
/*router.post('/api/v1/wanPrivateKeyUnlock', bodyParser.json(), model.wanPrivateKeyUnlock)
router.post('/api/v1/ethJsonv3Unlock', bodyParser.json(), model.ethJsonv3Unlock)
router.post('/api/v1/wanJsonv3Unlock', bodyParser.json(), model.wanJsonv3Unlock)
router.post('/api/v1/ethMnemonic', bodyParser.json(), model.ethMnemonic)
router.post('/api/v1/wanMnemonic', bodyParser.json(), model.wanMnemonic)*/

module.exports = router
