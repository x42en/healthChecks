fs    = require 'fs'
net   = require 'net'
tls   = require 'tls'
axios = require 'axios'

module.exports = class HealthChecks

    # Setup vulners API key and profile attribute
    constructor: (@config={vulners: null, profiles: {}}) ->

    # Add TLS/SSLV profile
    addProfile: (name, keychain) ->
        try
            @config.profiles[name] = {
                key: fs.readFileSync keychain.key
                cert: fs.readFileSync keychain.cert
                ca: fs.readFileSync keychain.ca
            }
        catch error
            throw error
        
        return true

    # Check if remote port is open
    _checkPort: (host, port) ->
        return new Promise (resolve, reject) =>
            # Check port is reachable
            net_socket = net.Socket()

            onError = () =>
                net_socket.destroy()
                reject Error host

            net_socket.setTimeout(1000)
            .once('error', onError)
            .once('timeout', onError)
            .connect( port, host, () =>
                # Auto close socket
                net_socket.end()
                resolve()
            )
    
    # Retrieve remote peer certificate
    _checkTLS: (host, port, profile_name) ->
        return new Promise (resolve, reject) =>
            config = { 
                host: host
                port: port
            }
            if profile_name of @config.profiles
                config.key = @config.profiles[profile_name].key
                config.cert = @config.profiles[profile_name].cert
                config.ca = @config.profiles[profile_name].ca
            
            tlsSocket = tls.connect config, () =>
                # Give some time for certificate retrieval
                setTimeout( =>
                    tlsSocket.end()
                , 100)
            
            .setEncoding 'utf8'
            .on 'error', (error) =>
                reject Error error
            .on 'data', (data) =>
                resolve tlsSocket.getPeerCertificate(true)
    
    # Execute web request upon host
    _request: (url, method, data, profile_name, json=false) ->
        if method not in ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS']
            throw 'Sorry, unsupported method'

        console.log "#{method} #{url}"
        config = {
            url: url
            method: method
            headers: {
                'User-Agent': 'ProHacktive HealthChecks - Check https://github.com/ProHacktive for more infos'
            }
        }

        if profile_name of @config.profiles
            config.key = @config.profiles[profile_name].key
            config.cert = @config.profiles[profile_name].cert
            config.cacert = @config.profiles[profile_name].ca
        
        if data
            config.data = data
        
        return axios(config)
        

    # Check if a service port is open
    # Return boolean()
    checkPortIsOpen: (host, port) ->
        port_status = @_checkPort host, port
        await port_status.then () ->
            return true
        .catch ( error ) ->
            return false

    # Gather remote peer certificate's issuer
    checkCertificateIssuer: (host, port, profile_name=null) ->
        tls_infos = @_checkTLS host, port, profile_name
        await tls_infos.then (infos) ->
            issuers = []
            
            # Rebuild DN
            dn = ''
            for k, v of infos.issuer
                dn += "#{k}=#{v},"
            
            # Add issuer to list
            if dn.slice(0, -1) not in issuers
                issuers.push dn.slice(0, -1)
            
            return issuers
        .catch ( error ) ->
            return Error error
    
    # Gather remote peer certificate's expiration date
    checkCertificateExpiration: (host, port, profile_name=null) ->
        tls_infos = @_checkTLS host, port, profile_name
        await tls_infos.then (infos) ->
            return infos.valid_to
        .catch ( error ) ->
            return Error error
    
    # Return result of API call in json
    checkAPICallContent: (url, method, data, profile_name=null) ->
        # Enable JSON flag
        api_infos = @_request url, method, data, profile_name, true
        await api_infos.then (infos) ->
            return { status: infos.status, data: infos.data }
        .catch ( error ) ->
            return null

    # Return result of web page request
    checkWebPageContent: (url, profile_name=null) ->
        web_infos = @_request url, 'GET', null, profile_name
        await web_infos.then (infos) ->
            return { status: infos.status, data: infos.data }
        .catch ( error ) ->
            return null

    # Check if remote site has client authentication enforced
    # return boolean()
    checkClientAuthentication: (host, port) ->
        tls_infos = @_checkTLS host, port
        await tls_infos.then (infos) ->
            # If can connect without certs
            return false
        .catch ( error ) ->
            console.log error
            return true

    # Retrieve vulnerabilities based on app/version infos
    # Based on vulners.io service (use config for API key)
    checkVulnerabilities: (app, version) ->