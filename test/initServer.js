(function() {
  var fs, options, server, tls;

  fs = require('fs');

  tls = require('tls');

  options = {
    key: fs.readFileSync('./certs/server.key'),
    cert: fs.readFileSync('./certs/server.crt'),
    rejectUnauthorized: true
  };

  server = tls.createServer(options, (socket) => {
    var authorized;
    authorized = socket.authorized ? 'authorized' : 'unauthorized';
    console.log('server connected', authorized);
    socket.write("welcome! \n");
    socket.setEncoding('utf8');
    return socket.pip(socket);
  });

  server.listen(8000, () => {
    return console.log('Server listening');
  });

}).call(this);
