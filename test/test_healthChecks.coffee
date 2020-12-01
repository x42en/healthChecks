# Import required packages
net   = require 'net'
chai  = require 'chai'
shoud = chai.should()
exec  = require('child_process').execSync
suppressLogs = require 'mocha-suppress-logs'

# Import test requirements
Server  = require "#{__dirname}/tlsServer"
Checker = require '../build/healthChecks'

# Allow self-signed for dev purpose
process.env['NODE_TLS_REJECT_UNAUTHORIZED'] = 0

host = 'localhost'
port = 8000

# Generate certificates
try
    console.log "Generate test certificates"
    exec "#{__dirname}/certs_init.sh localhost password &>/dev/null"
catch error
    console.error "Unable to generate certificates: #{error}"

# Instanciate test server TLSServer
server = new Server(host, port)

# Add client profile
client_keychain = {
    key: "#{__dirname}/certs/client/client.key"
    cert: "#{__dirname}/certs/client/client.crt"
    ca: "#{__dirname}/certs/ca/ca.crt"
}

# Instanciate healthChecks object
healthChecks = new Checker()
try
    raw = exec "openssl x509 -enddate -noout -in #{__dirname}/certs/server/server.crt | cut -d '=' -f 2"
    server_expiration = "#{raw}".replace(/(\r\n|\n|\r)/gm, "")
catch error
    console.error "Unable to get server certificates expiration: #{error}"

###################### UNIT TESTS ##########################
describe "HealthChecks working tests", ->

    # Remove output
    suppressLogs()
    
    # Set global timeout
    @timeout 4000

    before( () ->

        # Start server
        console.log "Start TLSServer"
        server.start()
    )

    after( () ->
        # Stop server
        console.log "Stop TLSServer"
        server.stop()
    )

    it 'Check add profile', (done) ->
        result = healthChecks.addProfile('client', client_keychain)
        result.should.be.a 'boolean'
        result.should.be.equal true
        
        done()
    
    it 'Check port open method', ->
        data = await healthChecks.checkPortIsOpen( host, port )
        data.should.be.a 'boolean'
        data.should.be.equal true
        
    it 'Check port closed method', ->
        data = await healthChecks.checkPortIsOpen( host, port+1 )
        data.should.be.a 'boolean'
        data.should.be.equal false
        
    it 'Check remote peer certificate issuer (1 node) method', ->
        data = await healthChecks.checkCertificateIssuer( host, port, 'client' )
        data.should.be.a 'array'
        data[0].should.be.equal 'C=FR,ST=PACA,L=GAP,O=ACME Signing Authority Inc,CN=CA'
    
    it 'Check remote peer certificate expiration method', ->
        data = await healthChecks.checkCertificateExpiration( host, port, 'client' )
        data.should.be.a 'string'
        data.should.be.equal server_expiration
    
    it 'Check API call method', ->
        data = await healthChecks.checkAPICallContent( 'https://my-json-server.typicode.com/x42en/healthchecks/posts/1', 'GET' )
        data.should.be.an 'object'
        data.should.have.deep.property 'status'
        data.should.have.deep.property 'data'
        
        data.status.should.be.equal 200
        data.data.should.be.an 'object'
        data.data.should.have.deep.property 'id'
        data.data.should.have.deep.property 'title'
        
        data.data.id.should.be.equal 1
        data.data.title.should.be.equal 'hello'
    
    it 'Check web page content method', ->
        data = await healthChecks.checkWebPageContent( 'https://api.ipify.org/' )
        data.should.be.an 'object'
        data.should.have.deep.property 'status'
        data.should.have.deep.property 'data'
        
        data.status.should.be.equal 200
        data.data.should.be.a 'string'
        net.isIPv4(data.data).should.be.equal true

    it 'Check remote client authentication method', ->
        data = await healthChecks.checkClientAuthentication( host, port )
        data.should.be.a 'boolean'
        data.should.be.equal true
    
    it 'Check remote client authentication failed method', ->
        # Instanciate test server TLSServer
        insecure_server = new Server(host, port+1, false)
        insecure_server.start()
        
        data = await healthChecks.checkClientAuthentication( host, port+1 )
        data.should.be.a 'boolean'
        data.should.be.equal false
        
        # Stop insecure server
        insecure_server.stop()