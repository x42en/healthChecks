# Import required packages
net   = require 'net'
chai  = require 'chai'
shoud = chai.should()
exec  = require('child_process').execSync
suppressLogs = require 'mocha-suppress-logs'

# Import test requirements
HttpsServer  = require "#{__dirname}/httpsServer"

Checker = require '../build/healthChecksExternal'

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

# Instanciate test server HTTPSServer
https_server = new HttpsServer(host, port)

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
        console.log "Start HTTPSServer"
        https_server.start()
    )

    after( () ->
        # Stop server
        console.log "Stop HTTPSServer"
        https_server.stop()
    )

    it 'Check add profile', (done) ->
        result = healthChecks.addProfile('client', client_keychain)
        result.should.be.a 'boolean'
        result.should.be.equal true
        
        done()
    
    it 'Check is profile set', (done) ->
        result = healthChecks.isProfileSet('client')
        result.should.be.a 'boolean'
        result.should.be.equal true
        
        done()
    
    it 'Check is profile set failed', (done) ->
        result = healthChecks.isProfileSet('test')
        result.should.be.a 'boolean'
        result.should.be.equal false
        
        done()
    
    it 'Check port open method', ->
        data = await healthChecks.checkPortIsOpen( host, port )
        data.should.be.a 'boolean'
        data.should.be.equal true
        
    it 'Check port closed method', ->
        data = await healthChecks.checkPortIsOpen( host, port+1 )
        data.should.be.a 'boolean'
        data.should.be.equal false
        
    it 'Check port latency method', ->
        data = await healthChecks.checkPortLatency( 'api.ipify.org', 443 )
        data.should.be.a 'number'
        data.should.be.above 0
        
    it 'Check port closed latency method', ->
        data = await healthChecks.checkPortLatency( host, port+1 )
        data.should.be.a 'number'
        data.should.be.equal -1
        
    it 'Check remote vhost certificate DN method', ->
        data = await healthChecks.checkCertificateDN( host, port, null )
        data.should.be.a 'string'
        data.should.be.equal 'C=FR,ST=.,L=.,O=ACME Signing Authority Inc,CN=localhost'
    
    it 'Check remote peer certificate DN method', ->
        data = await healthChecks.checkCertificateDN( host, port, 'client' )
        data.should.be.a 'string'
        data.should.be.equal 'C=FR,ST=.,L=.,O=ACME Signing Authority Inc,CN=localhost'
    
    it 'Check remote peer certificate issuer (1 node) method', ->
        data = await healthChecks.checkCertificateIssuer( host, port, 'client' )
        data.should.be.a 'array'
        data[0].should.be.equal 'C=FR,ST=PACA,L=GAP,O=ACME Signing Authority Inc,CN=CA'
    
    it 'Check remote peer certificate expiration method', ->
        data = await healthChecks.checkCertificateExpiration( host, port, 'client' )
        data.should.be.a 'string'
        data.should.be.equal server_expiration
    
    it 'Check remote peer certificate retrieval method', ->
        raw = await healthChecks.checkRemoteCertificate( host, port, 'client' )
        raw.should.be.an 'object'
        # Rebuild standard object for mochai compliance
        data = JSON.parse(JSON.stringify(raw))
        data.subject.should.exist
        data.issuer.should.exist
        data.bits.should.exist
        data.exponent.should.exist
        data.pubkey.should.exist
        data.valid_from.should.exist
        data.valid_to.should.exist
        data.fingerprint.should.exist
        data.serialNumber.should.exist
    
    it 'Check remote client authentication method', ->
        data = await healthChecks.checkClientAuthentication( host, port, 'client' )
        data.should.be.a 'boolean'
        data.should.be.equal true
    
    it 'Check remote client authentication failed method', ->
        data = await healthChecks.checkClientAuthentication( host, port )
        data.should.be.a 'boolean'
        data.should.be.equal false
    
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
        data = await healthChecks.checkWebPageContent( "https://api.ipify.org/", 'client' )
        data.should.be.an 'object'
        data.should.have.deep.property 'status'
        data.should.have.deep.property 'data'
        
        data.status.should.be.equal 200
        data.data.should.be.a 'string'
        net.isIPv4(data.data).should.be.equal true
