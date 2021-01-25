# Import required packages
fs    = require 'fs'
tls   = require 'tls'
https = require 'https'

module.exports = class HTTPSServer
    constructor: (host, port, secure=false)->
        @options = {
            host: host
            port: port

            key: fs.readFileSync("#{__dirname}/certs/server/server.key")
            cert: fs.readFileSync("#{__dirname}/certs/server/server.crt")
            ca: [fs.readFileSync("#{__dirname}/certs/ca/ca.crt")]
            
            requestCert: secure, # Ask for a client cert
            rejectUnauthorized: false # Act on unauthorized clients at the app level
        }
    
    _app: (req, res) ->
        cert = req.socket.getPeerCertificate()
        if not req.client.authorized
            # err = "Sorry #{cert.subject.CN}, certificates from #{cert.issuer.CN} are not welcome here."
            console.log "CLIENT UNAUTHORIZED"
            res.writeHead 401
            res.end "UNAUTHORIZED"
        else
            console.log "CLIENT AUTHORIZED"
            res.writeHead 200, {'Content-Type': 'text/plain'}
            res.end "welcome! \n"
    
    start: ->
        @server = https.createServer @options, @_app    
        @server.listen @options.port
    
    stop: ->
        @server.close()