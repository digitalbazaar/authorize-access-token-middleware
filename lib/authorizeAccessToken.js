/*!
 * Copyright (c) 2021 Digital Bazaar, Inc. All rights reserved.
 */
import assert from 'assert-plus';
import * as authorization from 'auth-header';
import * as JWT from '@digitalbazaar/minimal-jwt';
import {LruCache} from '@digitalbazaar/lru-memoize';
import {InvalidRequest, AccessDenied} from '@interop/oauth2-errors';
import noopLogger from './noopLogger';

/**
 * Authorizes an incoming request for a route (parses Authorization: header,
 * decodes access token, verifies it, checks the decoded token claims against
 * the provided scope, sets the `req.clientMetadata` property).
 *
 * @param {object} options - Options hashmap.
 * @param {string} options.requiredScope - Scope required for the route guarded
 *   by this middleware.
 * @see https://tools.ietf.org/html/rfc6749#section-3.3
 * @param {string[]} options.validIssuers - List of allowed issuers of
 *   access tokens (e.g. 'https://example.com').
 * @param {Function} options.loadClientRegistration - A function that
 *    loads a client.
 * @param {Function} options.verifySignature - Signature verification function
 *   (validates the algorithm and verifies the signature). Expected function
 *   signature: async ({alg, kid, data, signature}) => boolean.
 * @see https://github.com/digitalbazaar/minimal-jwt#verify
 * @param {Function} [options.validateClaims] - Optional custom validation
 *   callback with the signature `async ({claims}) => {}`.
 * @param {object} [options.logger] - Logger.
 * @param {object} [options.claimsCache] - Optional `lru-memoize` instance for
 *   storing decoded token claims). By default, the cache will be initialized
 *   with a max of 100 items, and an expiration of 5 seconds.
 *
 * @returns {Function} Returns an Express.js middleware route handler.
 */
export function authorizeAccessToken({
  requiredScope, validIssuers, loadClientRegistration, verifySignature,
  validateClaims, logger = noopLogger,
  claimsCache = new LruCache({max: 100, maxAge: 5000})
}) {
  assert.string(requiredScope, 'options.requiredScope');
  assert.arrayOfString(validIssuers, 'options.validIssuers');
  assert.func(loadClientRegistration, 'options.loadClientRegistration');
  assert.func(verifySignature, 'options.verifySignature');
  assert.optionalFunc(verifySignature, 'options.validateClaims');

  // Returns an Express middleware handler
  return async (req, res, next) => {
    try {
      // Extract access token from Authorization: header
      const {clientAccessToken} = _tokenFromHeader({
        authorizationHeader: req.get('authorization')
      });

      // Decode and validate claims, verify signature
      const {valid, errors, claims: tokenClaims} = await claimsCache.memoize({
        key: clientAccessToken,
        fn: () => _decodeAndValidateClaims({
          jwt: clientAccessToken,
          validIssuers,
          validateClaims,
          verifySignature
        })
      });
      if(!valid) {
        const tokenError = new AccessDenied({
          description: 'Invalid access token. The access token could not ' +
            'be verified.'
        });
        tokenError.errorId = 'invalid_token';
        tokenError.cause = errors;
        throw tokenError;
      }

      // Use the client_id to load the OAuth2 Client Registration with the
      // provided `loadClientRegistration()` callback
      const {client_id} = tokenClaims;
      let clientRegistration;
      try {
        (clientRegistration = await loadClientRegistration({client_id}));
      } catch(e) {
        throw new InvalidRequest({
          description: 'Could not load a registered agent for the ' +
            'provided client ID.'
        });
      }

      // Check saved registration scope against provided token scope
      const {scope: tokenScope} = tokenClaims;
      const {scope: registeredScope} = clientRegistration;
      _assertScope({tokenScope, registeredScope, requiredScope});

      // Success, set the decoded and validated `clientMetadata` property
      req.clientMetadata = {...tokenClaims};
    } catch(error) {
      _handleError({error, logger, res});
    }
    next();
  };
}

/**
 * Checks that the access token scope matches the required API endpoint's
 * scope, and also matches the scope granted to the client on registration.
 *
 * Scope is a whitespace-separated unordered list of substrings. Example valid
 * scopes:
 * - 'my.custom.scope' -- a single scope.
 * - 'read write' and 'write read' are equivalent, with an implicit AND.
 *
 * Throws an `AccessDenied` error if scopes do not match.
 *
 * @see https://tools.ietf.org/html/rfc6749#section-3.3
 *
 * @param {object} options - Options hashmap.
 * @param {string} options.tokenScope - Scope extracted from access_token.
 * @param {string} options.registeredScope - Scope given to client at
 *   registration (this is what a client is allowed to do).
 * @param {string} options.requiredScope - Scope required for a particular
 *   api endpoint.
 */
export function _assertScope({
  tokenScope, registeredScope, requiredScope
} = {}) {
  assert.string(tokenScope, 'options.tokenScope');
  assert.string(registeredScope, 'options.registeredScope');

  // Handle simple case (when there's a single scope or exact match)
  if(tokenScope === requiredScope && tokenScope === registeredScope) {
    return;
  }

  const tokenScopes = tokenScope.split(' ');
  const requiredScopes = requiredScope.split(' ');
  const registeredScopes = registeredScope.split(' ');

  // Every required scope must be included in the token scope
  if(!requiredScopes.every(r => tokenScopes.includes(r))) {
    throw new AccessDenied({
      description: `Access denied for token scope "${tokenScope}". ` +
        `Scope required: "${requiredScope}".`
    });
  }

  // Every token scope must be included in the registered client scope
  if(!tokenScopes.every(r => registeredScopes.includes(r))) {
    throw new AccessDenied({
      description: `Access denied. Token scope "${tokenScope}" does not ` +
        'match registered client scope.'
    });
  }
}

/**
 * Extracts the client access token from an incoming 'Authorization:` header.
 *
 * @example
 * // Incoming request has header: `Authorization: Bearer abcd12345`
 * _tokenFromHeader({authorizationHeader: req.get('authorization)};
 * // abcd12345
 *
 * @param {string} authorizationHeader - `authorization:` header value.
 *
 * @returns {string} Returns the extracted client access token.
 */
function _tokenFromHeader({authorizationHeader}) {
  let auth;
  try {
    // parse throws if the authorization header is missing
    auth = authorization.parse(authorizationHeader);
  } catch(e) {
    throw new InvalidRequest({
      description: 'Missing "authorization" header.'
    });
  }
  if(!(auth.scheme === 'Bearer' && auth.token)) {
    throw new InvalidRequest({
      description: 'Invalid "authorization" header.'
    });
  }
  return {clientAccessToken: auth.token};
}

/**
 * Decodes and validates JSON Web Token claims.
 * - Delegates checking of the algorithm, kid, and signature to the
 *   `verifySignature()` callback.
 * - Validates expiration (simple comparison, no leeway / clock skew).
 * - Validates token issuer against list of allowed issuers.
 *
 * @param {object} options - Options hashmap.
 * @param {string} options.jwt - JSON Web Token (compact serialization).
 * @param {string[]} options.validIssuers - List of allowed issuers.
 * @param {Function} options.verifySignature - Signature verification function
 *   (validates the algorithm and verifies the signature). Expected function
 *   signature: async ({alg, kid, data, signature}) => boolean
 * @param {Function} [options.validateClaims] - Optional custom validation
 *   function (you can validate audience, any custom claims, etc).
 *
 * @returns {Promise<{valid: boolean, claims}|{valid: boolean, errors: *[]}>}
 *   Resolves with validation result.
 */
async function _decodeAndValidateClaims({
  jwt, validIssuers, verifySignature, validateClaims
} = {}) {
  let payload;
  try {
    ({payload} = await JWT.verify({jwt, verifyFn: verifySignature}));
    const {exp, iss} = payload;

    _validateExpiration({exp});
    _validateIssuer({iss, validIssuers});

    if(validateClaims) {
      await validateClaims({claims: payload});
    }
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

function _validateExpiration({exp}) {
  // Date() works in milliseconds
  const now = Date.now();

  const expirationDate = new Date(exp * 1000);
  if(expirationDate.getTime() < now) {
    throw new InvalidRequest({
      description: 'Access token has expired.'
    });
  }
}

function _validateIssuer({iss, validIssuers}) {
  if(!validIssuers.includes(iss)) {
    throw new InvalidRequest({
      description: `Invalid issuer of access token: "${iss}".`
    });
  }
}

function _handleError({error, logger, res}) {
  logger.error('Authorization error:', {error});
  const {
    error: errorId, error_description: description, error_uri: uri
  } = error;

  const statusCode = error.statusCode || 400;
  const oauth2ErrorResponse = {
    error: errorId || 'invalid_request',
    error_description: description || error.message,
    error_uri: uri
  };
  res.set({
    'Cache-Control': 'no-store',
    Pragma: 'no-cache'
  });
  return res.status(statusCode).json(oauth2ErrorResponse);
}
