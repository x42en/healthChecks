# HealthChecks

[![NPM](https://nodei.co/npm/healthchecks.png?compact=true)](https://nodei.co/npm/healthchecks/)

[![Downloads per month](https://img.shields.io/npm/dm/healthchecks.svg?maxAge=2592000)](https://www.npmjs.org/package/healthchecks)
[![npm version](https://img.shields.io/npm/v/healthchecks.svg)](https://www.npmjs.org/package/healthchecks)
[![Build Status](https://travis-ci.org/x42en/healthchecks.svg?branch=master)](https://travis-ci.org/x42en/healthchecks)
[![Known Vulnerabilities](https://snyk.io/test/github/x42en/healthchecks/badge.svg)](https://snyk.io/test/github/x42en/healthchecks)



## Install

Install with npm:
  ```bash
    npm install healthchecks
  ```
  
## Basic Usage

Require the module:
  ```coffeescript
  HealthChecks = require 'healthChecks'
  ```

Start using HealthChecks...
  ```coffeescript
  healthCheck = new HealthChecks()
  
  check = ->
    res = await healthCheck.checkPortIsOpen 'google.com', 443
    return res
  
  status = if check() then 'UP' else 'DOWN'
  console.log "Google is #{status}"
  ```

## Supported methods

Several checks are available:  
* [addProfile](https://github.com/x42en/healthChecks#addprofile)
* [checkPortIsOpen](https://github.com/x42en/healthChecks#checkPortIsOpen)
* [checkCertificateIssuer](https://github.com/x42en/healthChecks#checkCertificateIssuer)
* [checkCertificateExpiration](https://github.com/x42en/healthChecks#checkCertificateExpiration)
* [checkAPICallContent](https://github.com/x42en/healthChecks#checkAPICallContent)
* [checkWebPageContent](https://github.com/x42en/healthChecks#checkWebPageContent)
* [checkClientAuthentication](https://github.com/x42en/healthChecks#checkClientAuthentication)

### addProfile
Add a complete TLS/SSL profile, useful for requests against client authentified endpoints.  
```
A profile object is composed with:  
- key: the private certificate path
- cert: the public certificate path
- ca: the certificate authority path  
```

**Args:** `name` (string), `profile` (object) 
**Return:** boolean

### checkPortIsOpen
Verify that a remote TCP port is open.  
**Args:** `host` (string), `port` (number)  
**Return:** boolean

### checkCertificateIssuer
Verify ~~complete~~ chain of remote peer certificate issuers.  
**Args:** `host` (string), `port` (number) [, `profile_name` (string)] 
**Return:** array of `issuer` (string)

### checkCertificateExpiration
Verify remote peer certificate expiration date.  
**Args:** `host` (string), `port` (number) [, `profile_name` (string)] 
**Return:** expiration_date (string)

### checkAPICallContent
Verify API call (using JSON POST method by default).  
**Args:** `url` (string), `method` (string) [, `profile_name` (string)] 
**Return:** answer (object) {status: 'status_code', data: data}

### checkWebPageContent
Verify Web page content (using GET method by default).  
**Args:** `url` (string), `method` (string) [, `profile_name` (string)] 
**Return:** answer (object) {status: 'status_code', data: data}

### checkClientAuthentication
Verify remote server is enforcing client authentication or not.  
**Args:** `host` (string), `port` (number)  
**Return:** boolean

## Developers

If you want to contribute to this project you are more than welcome !  

### Run tests
```bash
npm test
```

**Please use Coffeescript for development language**  

### Compilation

Use coffeescript to compile your tests
```bash
coffee -wc ./test
```

Use npm to compile your changes in HealthChecks
```bash
npm run build
```

### Publish

The NPM publishing is automated, just commit (or better merge) into master in order to publish corresponding package in NPM and GitHub repositories.

## TODO
* write better doc
* support full certificate chain validation of issuers
* add UDP support
* add vulners check
* add some crazy checks
* unittests vulners check