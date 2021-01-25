(function() {
  // Import required packages
  var HTTPSServer, fs, https, tls;

  fs = require('fs');

  tls = require('tls');

  https = require('https');

  module.exports = HTTPSServer = class HTTPSServer {
    constructor(host, port, secure = false) {
      this.options = {
        host: host,
        port: port,
        key: fs.readFileSync(`${__dirname}/certs/server/server.key`),
        cert: fs.readFileSync(`${__dirname}/certs/server/server.crt`),
        ca: [fs.readFileSync(`${__dirname}/certs/ca/ca.crt`)],
        requestCert: secure, // Ask for a client cert
        rejectUnauthorized: false // Act on unauthorized clients at the app level
      };
    }

    _app(req, res) {
      var cert;
      cert = req.socket.getPeerCertificate();
      if (!req.client.authorized) {
        // err = "Sorry #{cert.subject.CN}, certificates from #{cert.issuer.CN} are not welcome here."
        console.log("CLIENT UNAUTHORIZED");
        res.writeHead(401);
        return res.end("UNAUTHORIZED");
      } else {
        console.log("CLIENT AUTHORIZED");
        res.writeHead(200, {
          'Content-Type': 'text/plain'
        });
        return res.end("welcome! \n");
      }
    }

    start() {
      this.server = https.createServer(this.options, this._app);
      return this.server.listen(this.options.port);
    }

    stop() {
      return this.server.close();
    }

  };

}).call(this);

//# sourceMappingURL=httpsServer.js.map
