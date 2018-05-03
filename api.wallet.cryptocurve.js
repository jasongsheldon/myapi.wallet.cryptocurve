const express = require('express')
const compression = require('compression')
const routes  = require('./routes/routes')
const morgan = require('morgan')
const helmet = require('helmet')
const https = require('https')
const fs = require('fs')
const auth = require('http-auth')

/*  NDk5MUQ1OTJFN0ZFQTE1MDkyQ0IwNjhFQkZCREVFQzczNzNBMTk0NEU1MTA3QTFERDE5MUMzMTBENkY5MDRBMDowRkYxNUI0NDMxQjI0RkE0M0U5RTYwODIxMERGNEU0QTVBNjBCQ0MzMTUzREIzMTlEMTU1MUE4RjEzQ0ZEMkUx */
var basic = auth.basic({ realm: 'cryptocurve.network' }, function (username, password, callback) {
  callback(username === '4991D592E7FEA15092CB068EBFBDEEC7373A1944E5107A1DD191C310D6F904A0' && password === '0FF15B4431B24FA43E9E608210DF4E4A5A60BCC3153DB319D1551A8F13CFD2E1')
})

var app = express()


app.all('/*', function(req, res, next) {
  // CORS headers
  res.set('Content-Type', 'application/json')
  res.header('Access-Control-Allow-Origin', '*')//'https://whitelist.cryptocurve.network') // restrict it to the required domain
  res.header('Access-Control-Allow-Methods', 'POST,OPTIONS')
  // Set custom headers for CORS
  res.header('Access-Control-Allow-Headers', 'Content-Type,Accept,Authorization,Username,Password,Signature')
  if (req.method == 'OPTIONS') {
    res.status(200).end()
  } else {
    next()
  }
})

app.use(morgan('dev'))

app.use('/api/v1/*', auth.connect(basic))

app.use(helmet())
app.use(compression())

app.use('/', routes)

function handleData(req, res) {
  if (res.statusCode === 205) {
    if (res.body) {
      if (res.body.length === 0) {
        res.status(204)
        res.json({
          'status': 204,
          'message': 'No Content'
        })
      } else {
        res.status(200)
        res.json(res.body)
      }
    } else {
      res.status(204)
      res.json({
        'status': 204,
        'message': 'No Content'
      })
    }
  } else if (res.statusCode === 400) {
    res.status(res.statusCode)
    res.json({
      'status': res.statusCode,
      'message': 'Bad Request'
    })
  } else if (res.statusCode === 401) {
    res.status(res.statusCode)
    res.json({
      'status': res.statusCode,
      'message': 'Unauthorized'
    })
  } else if (res.statusCode) {
    res.status(res.statusCode)
    res.json(res.body)
  } else {
    res.status(200)
    res.json(res.body)
  }
}
app.use(handleData)
app.use(function(err, req, res) {
  if (err) {
    if (res.statusCode == 500) {
      res.status(250)
      res.json({
        'status': 250,
        'message': err
      })
    } else if (res.statusCode == 501) {
      res.status(250)
      res.json({
        'status': 250,
        'message': err
      })
    } else {
      res.status(500)
      res.json({
        'status': 500,
        'message': err.message
      })
    }
  } else {
    res.status(404)
    res.json({
      'status': 404,
      'message': 'Request not found'
    })
  }
})

var options = {}
https.globalAgent.maxSockets = 50
app.set('port', 8081)
var server = null
server = require('http').Server(app)
server.listen(app.get('port'), function () {
  console.log('cryptoreviews.api',server.address().port)
  module.exports = server
})

Array.prototype.contains = function(obj) {
  var i = this.length
  while (i--) {
    if (this[i] === obj) {
      return true
    }
  }
  return false
}
