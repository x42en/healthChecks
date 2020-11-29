fs    = require 'fs'
net   = require 'net'
tls   = require 'tls'
axios = require 'axios'

module.exports = class HealthChecks

    # Setup vulners API key and profile attribute
    constructor: (@config={vulners: null, profiles: {}}) ->

    # Add TLS/SSLV profile
    addProfile: (name, key, cert, cacert) ->
        try
            @config.profiles[name] = {
                key: fs.readFileSync key
                cert: fs.readFileSync cert
                cacert: fs.readFileSync cacert
            }
        catch error
            throw error

    _check_port: (host, port) ->
        return new Promise (resolve, reject) =>
            # Check port is reachable
            net_socket = net.Socket()

            onError = () =>
                net_socket.destroy()
                reject Error host

            net_socket.setTimeout(1000)
            net_socket.once('error', onError)
            net_socket.once('timeout', onError)
            net_socket.connect( port, host, () =>
                net_socket.end()
                resolve host
            )
    
    _request: (url, method, data, profile) ->
        if method not in ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS']
            throw 'Sorry, unsupported method'

        console.log "#{method} #{url}"
        config = {
            url: url
            method: method
            headers: { 'User-Agent': 'ProHacktive HealthChecks - Check https://github.com/ProHacktive for more infos' }
        }

        if profile_name and profile_name of @config.profiles
            config.key = @config.profiles[profile_name].key
            config.cert = @config.profiles[profile_name].cert
            config.cacert = @config.profiles[profile_name].cacert
        
        if data
            res = await axios(config, data)
        else
            res = await axios(config)
        
        console.log "Received: #{res.status} - #{res.statusText}"
        console.log res.data

        return [ res.status, res.data ]
        

    checkServiceIsOpen: (host, port) ->
        port_status = await @_check_port host, port
        port_status.then (infos) ->
            return true
        .catch ( error) ->
            return false

    checkCertificateIssuer: (host, port) ->
    checkCertificateExpiration: (host, port) ->
    checkAPICallContent: (hostname, protocol='http', port=443, path='/', method='POST', data=null, key=null, cert=null) ->
        if protocol not in ['http', 'https']
            throw 'Sorry, unsupported protocol'
        try
            res = @_request "#{protocol}://#{hostname}:#{port}#{path}", method, data, key, cert
            return [res.status, res.body]
        catch error
            throw error

    checkWebPageContent: (hostname, protocol='http', port=443, path='/', method='GET') ->
        if protocol not in ['http', 'https']
            throw 'Sorry, unsupported protocol'
        try
            res = @_request "#{protocol}://#{hostname}:#{port}#{path}", method, data, key, cert
            return [res.status, res.body]
        catch error
            throw error

    checkClientAuthentification: (host, port) ->
    checkVulnerabilities: (app, version) ->