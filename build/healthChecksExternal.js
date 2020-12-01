(function() {
  var HealthChecks, axios, fs, net, tls,
    indexOf = [].indexOf;

  fs = require('fs');

  net = require('net');

  tls = require('tls');

  axios = require('axios');

  module.exports = HealthChecks = class HealthChecks {
    // Setup vulners API key and profile attribute
    constructor(config1 = {
        vulners: null,
        profiles: {}
      }) {
      this.config = config1;
    }

    // Add TLS/SSLV profile
    addProfile(name, keychain) {
      var error;
      try {
        this.config.profiles[name] = {
          key: fs.readFileSync(keychain.key),
          cert: fs.readFileSync(keychain.cert),
          ca: fs.readFileSync(keychain.ca)
        };
      } catch (error1) {
        error = error1;
        throw error;
      }
      return true;
    }

    // Check if remote port is open
    _checkPort(host, port) {
      return new Promise((resolve, reject) => {
        var net_socket, onError;
        // Check port is reachable
        net_socket = net.Socket();
        onError = () => {
          net_socket.destroy();
          return reject(Error(host));
        };
        return net_socket.setTimeout(1000).once('error', onError).once('timeout', onError).connect(port, host, () => {
          // Auto close socket
          net_socket.end();
          return resolve();
        });
      });
    }

    
      // Retrieve remote peer certificate
    _checkTLS(host, port, profile_name) {
      return new Promise((resolve, reject) => {
        var config, tlsSocket;
        config = {
          host: host,
          port: port
        };
        if (profile_name in this.config.profiles) {
          config.key = this.config.profiles[profile_name].key;
          config.cert = this.config.profiles[profile_name].cert;
          config.ca = this.config.profiles[profile_name].ca;
        }
        return tlsSocket = tls.connect(config, () => {
          // Give some time for certificate retrieval
          return setTimeout(() => {
            return tlsSocket.end();
          }, 100);
        }).setEncoding('utf8').on('error', (error) => {
          return reject(Error(error));
        }).on('data', (data) => {
          return resolve(tlsSocket.getPeerCertificate(true));
        });
      });
    }

    
      // Execute web request upon host
    _request(url, method, data, profile_name, json = false) {
      var config;
      if (method !== 'GET' && method !== 'POST' && method !== 'PUT' && method !== 'DELETE' && method !== 'HEAD' && method !== 'OPTIONS') {
        throw 'Sorry, unsupported method';
      }
      console.log(`${method} ${url}`);
      config = {
        url: url,
        method: method,
        headers: {
          'User-Agent': 'ProHacktive HealthChecks - Check https://github.com/ProHacktive for more infos'
        }
      };
      if (profile_name in this.config.profiles) {
        config.key = this.config.profiles[profile_name].key;
        config.cert = this.config.profiles[profile_name].cert;
        config.cacert = this.config.profiles[profile_name].ca;
      }
      if (data) {
        config.data = data;
      }
      return axios(config);
    }

    
      // Check if a service port is open
    // Return boolean()
    async checkPortIsOpen(host, port) {
      var port_status;
      port_status = this._checkPort(host, port);
      return (await port_status.then(function() {
        return true;
      }).catch(function(error) {
        return false;
      }));
    }

    // Gather remote peer certificate's issuer
    async checkCertificateIssuer(host, port, profile_name = null) {
      var tls_infos;
      tls_infos = this._checkTLS(host, port, profile_name);
      return (await tls_infos.then(function(infos) {
        var dn, issuers, k, ref, ref1, v;
        issuers = [];
        
        // Rebuild DN
        dn = '';
        ref = infos.issuer;
        for (k in ref) {
          v = ref[k];
          dn += `${k}=${v},`;
        }
        
        // Add issuer to list
        if (ref1 = dn.slice(0, -1), indexOf.call(issuers, ref1) < 0) {
          issuers.push(dn.slice(0, -1));
        }
        return issuers;
      }).catch(function(error) {
        return Error(error);
      }));
    }

    
      // Gather remote peer certificate's expiration date
    async checkCertificateExpiration(host, port, profile_name = null) {
      var tls_infos;
      tls_infos = this._checkTLS(host, port, profile_name);
      return (await tls_infos.then(function(infos) {
        return infos.valid_to;
      }).catch(function(error) {
        return Error(error);
      }));
    }

    
      // Return result of API call in json
    async checkAPICallContent(url, method, data, profile_name = null) {
      var api_infos;
      // Enable JSON flag
      api_infos = this._request(url, method, data, profile_name, true);
      return (await api_infos.then(function(infos) {
        return {
          status: infos.status,
          data: infos.data
        };
      }).catch(function(error) {
        return null;
      }));
    }

    // Return result of web page request
    async checkWebPageContent(url, profile_name = null) {
      var web_infos;
      web_infos = this._request(url, 'GET', null, profile_name);
      return (await web_infos.then(function(infos) {
        return {
          status: infos.status,
          data: infos.data
        };
      }).catch(function(error) {
        return null;
      }));
    }

    // Check if remote site has client authentication enforced
    // return boolean()
    async checkClientAuthentication(host, port) {
      var tls_infos;
      tls_infos = this._checkTLS(host, port);
      return (await tls_infos.then(function(infos) {
        // If can connect without certs
        return false;
      }).catch(function(error) {
        console.log(error);
        return true;
      }));
    }

    // Retrieve vulnerabilities based on app/version infos
    // Based on vulners.io service (use config for API key)
    checkVulnerabilities(app, version) {}

  };

}).call(this);

//# sourceMappingURL=healthChecksExternal.js.map