(function() {
  // Import required packages
  var TLSServer, fs, tls;

  fs = require('fs');

  tls = require('tls');

  module.exports = TLSServer = class TLSServer {
    constructor(host, port, secure = true) {
      this.options = {
        host: host,
        port: port,
        key: fs.readFileSync(`${__dirname}/certs/server/server.key`),
        cert: fs.readFileSync(`${__dirname}/certs/server/server.crt`),
        ca: fs.readFileSync(`${__dirname}/certs/ca/ca.crt`),
        requestCert: secure, // Ask for a client cert
        rejectUnauthorized: secure // Act on unauthorized clients at the app level
      };
    }

    start() {
      this.server = tls.createServer(this.options, (socket) => {
        socket.write("welcome! \n");
        socket.setEncoding('utf8');
        return socket.pipe(socket);
      });
      this.server.on('connection', (c) => {});
      this.server.on('secureConnection', (c) => {});
      return this.server.listen(this.options.port, () => {});
    }

    stop() {
      return this.server.close();
    }

  };

}).call(this);

//# sourceMappingURL=tlsServer.js.map
