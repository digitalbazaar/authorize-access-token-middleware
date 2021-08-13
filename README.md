# JWT Access Token Authorization Middleware _(@digitalbazaar/authorize-access-token-middleware)_

[![Node.js CI](https://github.com/digitalbazaar/authorize-access-token-middleware/workflows/Node.js%20CI/badge.svg)](https://github.com/digitalbazaar/authorize-access-token-middleware/actions?query=workflow%3A%22Node.js+CI%22)

> An opinionated Express-like middleware to protect API endpoints via OAuth 2.0 access tokens.

## Table of Contents

- [Background](#background)
- [Security](#security)
- [Install](#install)
- [Usage](#usage)
- [Contribute](#contribute)
- [Commercial Support](#commercial-support)
- [License](#license)

## Background

This is primarily intended for app authorization (for applications using the
`client_credentials` OAuth 2 grant type), rather than for user (`sub`ject)
authentication (for that, Passport is more useful).

Assumptions:

* Access tokens will be passed via HTTP headers, using `Bearer <token>` scheme.
* Assumes a required allow-list of approved issuers.

Not supported in v1.0:

* Optional authorization (that is, if you use this middleware, an access token
  is required).
* Encrypted access tokens.
* DPoP / proof of possession header functionality.

## Security

TBD

## Install

- Node.js 12+ is required.

To install locally (for development):

```
git clone https://github.com/digitalbazaar/authorize-access-token-middleware.git
cd authorize-access-token-middleware
npm install
```

## Usage

### Importing

```js
import {authorizeAccessToken} from '@digitalbazaar/authorize-access-token-middleware';
// or
const {authorizeAccessToken} = require('@digitalbazaar/authorize-access-token-middleware');
```

### Adding authorization to an api route

```js
app.post('/example/api/endpoint',
  authorizeAccessToken({
    // OAuth2 scope required for this endpoint
    requiredScope: 'my.custom.scope',
    // List of allowed issuers of tokens
    validIssuers: ['https://issuer.example.com'],

    loadClientRegistration: async ({client_id}) => {
      // Required callback - load client registration from database or other
      // storage so that the access token scope can be compared with the client's
      // granted scope. You can also do custom client validation here
      // (has the client been revoked? ran over quota or metering limits?)
    },
    
    // Custom verify callback should verify algorithm and signature (using a remote KMS or similar)
    verifySignature: async ({alg, kid, data, signature}) => {
    },

    validateClaims: async ({claims}) => {
      // Optional custom claim validation callback (for example, you can
      // validate the `aud`ience claim)
    },

    decorateError: async ({errorResponse}) => {
      // Optional callback to decorate/add to the error response.
      // By default, error responses follow the OAuth 2.0 error response format 
      // @see https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
      // This is typically used to add other application-specific fields to the JSON error response
      errorResponse.appSpecificErrorCode = '1234';
      return errorResponse;
    },
    
    // Optional logger object (such as console, pino, winston, and so on)
    logger: console
  }),
  (req, res, next) => {
    // ... continue with your route handling as usual
    // `req.clientMetadata` will be set with
    // the decoded and validated claims from the token
  }
)
```

## Contribute

See [the contribute file](https://github.com/digitalbazaar/bedrock/blob/master/CONTRIBUTING.md)!

PRs accepted.

If editing the Readme, please conform to the
[standard-readme](https://github.com/RichardLitt/standard-readme) specification.

## Commercial Support

Commercial support for this library is available upon request from
Digital Bazaar: support@digitalbazaar.com

## License

[New BSD License (3-clause)](LICENSE) © Digital Bazaar
