fs  = require 'fs'
tls = require 'tls'

options = {
    key: fs.readFileSync('./certs/server.key')
    cert: fs.readFileSync('./certs/server.crt')
    rejectUnauthorized: true
}

server = tls.createServer options, (socket) =>
    authorized = if socket.authorized then 'authorized' else 'unauthorized'
    console.log 'server connected', authorized
    socket.write "welcome! \n"
    socket.setEncoding 'utf8'
    socket.pip socket

server.listen 8000, () =>
    console.log 'Server listening'