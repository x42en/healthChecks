# HealthChecks-External

[![NPM](https://nodei.co/npm/healthchecks-external.png?compact=true)](https://nodei.co/npm/healthchecks-external/)

[![Downloads per month](https://img.shields.io/npm/dm/healthchecks-external.svg?maxAge=2592000)](https://www.npmjs.org/package/healthchecks-external)
[![npm version](https://img.shields.io/npm/v/healthchecks-external.svg)](https://www.npmjs.org/package/healthchecks-external)
[![Build Status](https://travis-ci.org/x42en/healthchecks-external.svg?branch=master)](https://travis-ci.org/x42en/healthchecks-external)
[![Known Vulnerabilities](https://snyk.io/test/github/x42en/healthchecks-external/badge.svg)](https://snyk.io/test/github/x42en/healthchecks-external)

[[_TOC_]]

---

## Install

Install with npm:
  ```bash
    npm install healthchecks-external
  ```
  
## Basic Usage

Require the module:
  ```coffeescript
  HealthChecks = require 'healthchecks-external'
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
- [HealthChecks-External](#healthchecks-external)
  - [Install](#install)
  - [Basic Usage](#basic-usage)
  - [Supported methods](#supported-methods)
    - [addProfile](#addprofile)
    - [checkPortIsOpen](#checkportisopen)
    - [checkPortLatency](#checkportlatency)
    - [checkCertificateDN](#checkcertificatedn)
    - [checkCertificateIssuer](#checkcertificateissuer)
    - [checkCertificateExpiration](#checkcertificateexpiration)
    - [checkAPICallContent](#checkapicallcontent)
    - [checkWebPageContent](#checkwebpagecontent)
    - [checkClientAuthentication](#checkclientauthentication)
  - [Developers](#developers)
    - [Run tests](#run-tests)
    - [Compilation](#compilation)
    - [Publish](#publish)
  - [TODO](#todo)

### addProfile
Add a complete TLS/SSL profile, useful for requests against client authentified endpoints.  
```
A profile object is composed with:  
- key: the private certificate path
- cert: the public certificate path
- ca: the certificate authority path  
```

- **Args:** `name` (string), `profile` (object) 
- **Return:** boolean

### checkPortIsOpen
Verify that a remote TCP port is open.  
- **Args:** `host` (string), `port` (number)  
- **Return:** boolean

### checkPortLatency
Verify latency of a remote TCP port (in ms).  
- **Args:** `host` (string), `port` (number)  
- **Return:** boolean

### checkCertificateDN
Verify DN of remote peer certificate.  
- **Args:** `host` (string), `port` (number) [, `profile_name` (string)] 
- **Return:** array of `issuer` (string)

### checkCertificateIssuer
Verify ~~complete~~ chain of remote peer certificate issuers.  
- **Args:** `host` (string), `port` (number) [, `profile_name` (string)] 
- **Return:** array of `issuer` (string)

### checkCertificateExpiration
Verify remote peer certificate expiration date.  
- **Args:** `host` (string), `port` (number) [, `profile_name` (string)] 
- **Return:** expiration_date (string)

### checkAPICallContent
Verify API call (using JSON POST method by default).  
- **Args:** `url` (string), `method` (string) [, `profile_name` (string)] 
- **Return:** answer (object) {status: 'status_code', data: data}

### checkWebPageContent
Verify Web page content (using GET method by default).  
- **Args:** `url` (string), `method` (string) [, `profile_name` (string)] 
- **Return:** answer (object) {status: 'status_code', data: data}

### checkClientAuthentication
Verify remote server is enforcing client authentication or not.  
- **Args:** `host` (string), `port` (number)  
- **Return:** boolean

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

The NPM publishing is automated, just merge PR from develop into master in order to publish corresponding package in NPM and GitHub repositories.

## TODO
- [ ] write better doc
- [ ] support full certificate chain validation of issuers
- [ ] add UDP support
- [ ] add vulners check
- [ ] add some crazy checks
- [ ] unittests vulners check
