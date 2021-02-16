/*!
 * Copyright (c) 2021 Digital Bazaar, Inc. All rights reserved.
 */
import * as authorization from 'auth-header';
import * as JWT from '@digitalbazaar/minimal-jwt';
// import {tokenizers} from 'bedrock-tokenizer';
import base64url from 'base64url-universal';

const DEFAULT_ALLOWED_JWT_ALGS = new Set(['HS256', 'ES256']);

/**
 * Authorizes an incoming request for a route (parses Authorization: header,
 * decodes access token, verifies it, checks the decoded token claims against
 * the provided scope, sets the `req.clientMetadata` property).
 *
 * @param {object} options - Options hashmap.
 * @param {string} options.scope - Scope required for the route guarded by this
 *   `authorize()` usage.
 * @param {Function} [options.customValidate] - Optional custom authorization
 *   callback with the signature `async ({req, claims}) => {}`.
 * @param {object} [options.cache] - Optional LRU cache to store the decoded
 *   token claims). The cache API must be compatible with the lru-cache NPM
 *   module.
 * @param {string[]} options.validIssuers - List of allowed issuers of
 *   access tokens (e.g. 'https://example.com').
 * @param {Function} options.loadClientRegistration -
 * @returns {Function} Returns an Express.js middleware route handler.
 */
export function authorizeAccessToken({
  scope, cache, validIssuers, loadClientRegistration, customValidate
}) {
  return async (req, res, next) => {
    try {
      // Extract access token from Authorization: header (throw otherwise)
      let clientAccessToken;
      try {
        // parse throws if the authorization header is missing
        const auth = authorization.parse(req.get('authorization'));
        if(!(auth.scheme === 'Bearer' && auth.token)) {
          throw new BedrockError('Missing or invalid "authorization" header.',
            'NotAllowedError', {
              httpStatusCode: 401,
              public: true
            });
        }
        ({token: clientAccessToken} = auth);
      } catch(e) {
        throw new BedrockError('Missing or invalid "authorization" header.',
          'NotAllowedError', {
            httpStatusCode: 401,
            public: true
          });
      }

      // validate and unpack the claims from the clientAccessToken
      // use the cache as appropriate
      // verify JWT w/cache-backed helper
      const {valid, claims: tokenClaims, errors} = await _verifyClaimsFromJwt({
        claimsCache: cache,
        jwt: clientAccessToken,
        validIssuers
      });
      if(!valid) {
        const tokenError = new BedrockError(
          'Invalid access token.', 'NotAllowedError', {
            // errors is an array of errors which cannot be used as the
            // BedrockError cause
            errors,
            httpStatusCode: 401,
            public: true,
          });
        tokenError.errorId = 'invalid_token';
        throw tokenError;
      }

      // use the client_id claim to load the OAuth2 Client Registration
      // Load Agent metadata based on client id
      const {client_id} = tokenClaims;
      let clientRegistration;
      try {
        (clientRegistration = await loadClientRegistration({client_id}));
      } catch(e) {
        throw new BedrockError(
          'Could not load a registered agent for the provided client ID.',
          'NotAllowedError', {
            client_id,
            httpStatusCode: 401,
            public: true,
          }, e);
      }

      // Check against provided scope
      const {scope: tokenScope} = clientRegistration;
      if(!(typeof tokenScope === 'string' && tokenScope.includes(scope))) {
        throw new Error(`Access denied for token scope ${tokenScope}.` +
          `Scope required: ${scope}.`);
      }

      // Invoke the custom authorization callback (throws error if invalid)
      if(customValidate) {
        await customValidate({req, claims: clientRegistration});
      }

      // if not allowed, throw a 403 Unauthorized error
      req.clientMetadata = {...tokenClaims};
      // otherwise, just continue
    } catch(e) {
      // Return the error back to the OAuth2 client
      return next(e);
    }
    next();
  };
}

async function _verifyClaimsFromJwt({jwt, validIssuers, claimsCache} = {}) {
  let promise;
  promise = claimsCache.get(jwt);
  if(promise) {
    return promise;
  }

  // cache miss, do verification and cache promise
  promise = _verifyJwt({jwt, validIssuers});
  claimsCache.set(jwt, promise);

  let response;
  try {
    response = await promise;
  } catch(e) {
    claimsCache.del(jwt);
    throw e;
  }
  return response;
}

async function _verifyJwt({jwt, validIssuers}) {
  let payload;
  try {
    ({payload} = await JWT.verify({jwt, verifyFn: _verifyFn}));
    const {exp, iss} = payload;

    _validateExpiration({exp});
    _validateIssuer({iss, validIssuers});
  } catch(e) {
    return {
      valid: false,
      errors: [e]
    };
  }
  return {
    valid: true,
    claims: {
      ...payload
    }
  };
}



async function _verifyFn({alg, kid, data, signature}) {
  if(!ALLOWED_JWT_ALGS.has(alg)) {
    throw new Error(`"${alg}" is invalid.`);
  }
  let hmac;
  try {
    ({hmac} = await tokenizers.get({id: kid}));
  } catch(e) {
    throw new Error(`Unable to verify token with kid: "${kid}"`);
  }

  const encodedSignature = base64url.encode(signature);
  return hmac.verify({data, signature: encodedSignature});
}

function _validateExpiration({exp}) {
  // Date() works in milliseconds
  const now = Date.now();

  const expirationDate = new Date(exp * 1000);
  if(expirationDate.getTime() < now) {
    throw new Error('Access token has expired.');
  }
}

function _validateIssuer({iss, validIssuers}) {
  if(!validIssuers.find(allowedIssuer => iss === allowedIssuer)) {
    throw new Error('Invalid issuer of access token.');
  }
}
