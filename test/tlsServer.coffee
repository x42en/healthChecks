# Import required packages
fs  = require 'fs'
tls = require 'tls'

module.exports = class TLSServer
    constructor: (host, port, secure=true)->
        @options = {
            host: host
            port: port

            key: fs.readFileSync("#{__dirname}/certs/server/server.key")
            cert: fs.readFileSync("#{__dirname}/certs/server/server.crt")
            ca: fs.readFileSync("#{__dirname}/certs/ca/ca.crt")
            
            requestCert: secure, # Ask for a client cert
            rejectUnauthorized: secure # Act on unauthorized clients at the app level
        }
    
    start: ->
        @server = tls.createServer @options, (socket) =>
            socket.write "welcome! \n"
            socket.setEncoding 'utf8'
            socket.pipe socket
        @server.on 'connection', (c) =>
        @server.on 'secureConnection', (c) =>
        @server.listen @options.port, () =>
    
    stop: ->
        @server.close()