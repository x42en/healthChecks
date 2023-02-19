(function() {
  //###################################################
  //         healthChecksExternal - v1.2.3            #
  //                                                  #
  //        External Health Checks made easy          #
  //###################################################
  //             -    Copyright 2023    -             #
  //                                                  #
  //   License: Apache v 2.0                          #
  //   @Author: Ben Mz                                #
  //   @Email: 0x42en (at) users.noreply.github.com   #
  //                                                  #
  //###################################################

  // Licensed under the Apache License, Version 2.0 (the "License");
  // you may not use this file except in compliance with the License.
  // You may obtain a copy of the License at

  //     http://www.apache.org/licenses/LICENSE-2.0

  // Unless required by applicable law or agreed to in writing, software
  // distributed under the License is distributed on an "AS IS" BASIS,
  // WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  // See the License for the specific language governing permissions and
  // limitations under the License.

  // Set global vars
  var HealthChecks, VERSION, axios, fs, https, net,
    indexOf = [].indexOf;

  VERSION = '1.2.3';

  fs = require('fs');

  net = require('net');

  https = require('https');

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
          rejectUnauthorized: false,
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

    isProfileSet(name) {
      return this.config.profiles[name] != null;
    }

    // Check if remote port is open
    async _checkPort(host, port) {
      var promise;
      promise = new Promise((resolve, reject) => {
        var net_socket, onError;
        // Check port is reachable
        net_socket = net.Socket();
        onError = (err) => {
          net_socket.destroy();
          return reject(new Error(`${host}:${port} is unreachable: ${err}`));
        };
        net_socket.setTimeout(1000);
        net_socket.once('error', onError);
        net_socket.once('timeout', onError);
        return net_socket.connect(port, host, () => {
          // Auto close socket
          net_socket.end();
          return resolve();
        });
      });
      try {
        await promise;
        return true;
      } catch (error1) {
        return false;
      }
    }

    
      // Retrieve remote peer certificate (supporting vhosts)
    _checkHTTPS(vhost, port, profile_name) {
      return new Promise((resolve, reject) => {
        var cert, config, isAuthorized, req, secure;
        config = {
          host: vhost,
          port: port,
          method: 'get',
          path: '/',
          agent: false
        };
        secure = false;
        if (profile_name in this.config.profiles) {
          secure = true;
          config.key = this.config.profiles[profile_name].key;
          config.cert = this.config.profiles[profile_name].cert;
          config.ca = this.config.profiles[profile_name].ca;
        }
        cert = null;
        isAuthorized = false;
        req = https.request(config, (res) => {
          cert = res.connection.getPeerCertificate();
          isAuthorized = res.connection.authorized;
          return resolve({
            authorized: isAuthorized,
            certificate: cert
          });
        });
        req.on('error', (err) => {
          return reject(err.message);
        });
        return req.end();
      });
    }

    // Execute web request upon host
    _request(url, method, data, profile_name, json = false) {
      var config, ref;
      if ((ref = !method.toUpperCase()) === 'GET' || ref === 'POST' || ref === 'PUT' || ref === 'DELETE' || ref === 'HEAD' || ref === 'OPTIONS') {
        throw 'Sorry, unsupported method';
      }
      config = {
        url: url,
        method: method,
        headers: {
          'User-Agent': 'ProHacktive HealthChecks - Check https://github.com/ProHacktive for more infos'
        }
      };
      if (profile_name in this.config.profiles) {
        config.httpsAgent = new https.Agent(this.config.profiles[profile_name]);
      }
      if (data) {
        config.data = data;
      }
      return axios(config);
    }

    // Check if a service port is open
    // Return Boolean()
    async checkPortIsOpen(host, port) {
      return (await this._checkPort(host, port));
    }

    // Check latency of a service port
    // Return Number()
    async checkPortLatency(host, port) {
      var err, is_open, latency, now;
      try {
        now = new Date().getTime();
        is_open = (await this._checkPort(host, port));
        if (!is_open) {
          throw new Error('port closed');
        }
      } catch (error1) {
        err = error1;
        return -1;
      }
      
      // Calculate latency
      latency = (new Date().getTime()) - now;
      return latency;
    }

    
      // Gather remote peer certificate's DN
    async checkCertificateDN(host, port, profile_name = null) {
      var data, dn, err, k, ref, v;
      try {
        dn = '';
        // cert_infos = @_getCertificate host, port, profile_name
        data = (await this._checkHTTPS(host, port, profile_name));
        ref = data.certificate.subject;
        // Rebuild DN
        for (k in ref) {
          v = ref[k];
          dn += `${k}=${v},`;
        }
        dn = dn.slice(0, -1);
      } catch (error1) {
        err = error1;
        return new Error(err);
      }
      return dn;
    }

    
      // Gather remote peer certificate's issuer
    async checkCertificateIssuer(host, port, profile_name = null) {
      var data, dn, err, issuers, k, ref, v;
      try {
        issuers = [];
        dn = '';
        data = (await this._checkHTTPS(host, port, profile_name));
        ref = data.certificate.issuer;
        // Rebuild DN
        for (k in ref) {
          v = ref[k];
          dn += `${k}=${v},`;
        }
        dn = dn.slice(0, -1);
        // Add issuer to list
        if (indexOf.call(issuers, dn) < 0) {
          issuers.push(dn);
        }
      } catch (error1) {
        err = error1;
        return new Error(err);
      }
      return issuers;
    }

    
      // Gather remote peer certificate's expiration date
    async checkCertificateExpiration(host, port, profile_name = null) {
      var data, err;
      try {
        data = (await this._checkHTTPS(host, port, profile_name));
      } catch (error1) {
        err = error1;
        return new Error(err);
      }
      return data.certificate.valid_to;
    }

    
      // Gather remote peer certificate
    async checkRemoteCertificate(host, port, profile_name = null) {
      var data, err;
      try {
        data = (await this._checkHTTPS(host, port, profile_name));
      } catch (error1) {
        err = error1;
        return new Error(err);
      }
      return data.certificate;
    }

    
      // Check if remote site has client authentication enforced
    // return boolean()
    async checkClientAuthentication(host, port, profile_name = null) {
      var data, err;
      try {
        // Try a connection without profile
        data = (await this._checkHTTPS(host, port, profile_name));
        return data.authorized;
      } catch (error1) {
        err = error1;
        console.log(`Authentication error: ${err}`);
        return true;
      }
    }

    // Return result of API call in json
    async checkAPICallContent(url, method, data, profile_name = null) {
      var err, infos;
      try {
        // Enable JSON flag
        infos = (await this._request(url, method, data, profile_name, true));
      } catch (error1) {
        err = error1;
        return new Error(err);
      }
      return {
        status: infos.status,
        data: infos.data
      };
    }

    // Return result of web page request
    async checkWebPageContent(url, profile_name = null) {
      var err, infos;
      try {
        infos = (await this._request(url, 'GET', null));
      } catch (error1) {
        err = error1;
        return new Error(err);
      }
      return {
        status: infos.status,
        data: infos.data
      };
    }

    // Retrieve vulnerabilities based on app/version infos
    // Based on vulners.io service (use config for API key)
    checkVulnerabilities(app, version) {}

  };

}).call(this);

//# sourceMappingURL=healthChecksExternal.js.map
