/*!
 * Copyright (c) 2021 Digital Bazaar, Inc. All rights reserved.
 */
import assert from 'assert-plus';
import * as authorization from 'auth-header';
import {LruCache} from '@digitalbazaar/lru-memoize';
import {InvalidRequest, InvalidToken, InvalidScope, InsufficientScope}
  from '@interop/oauth2-errors';
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
 * @param {string[]} [options.validIssuers] - List of allowed issuers of
 *   access tokens (e.g. ['https://example.com']). If missing, issuer validation
 *   should be performed in the validateClaims() callback.
 * @param {Function} [options.verify] - Decoding and signature verification
 *   function (validates the algorithm and verifies the signature).
 *   Expected function signature: async ({token}) => claims.
 * @param {Function} [options.validateClaims] - Optional custom validation
 *   callback with the signature `async ({claims})`, should throw appropriate
 *   errors.
 * @param {object} [options.logger] - Logger.
 * @param {object} [options.claimsCache] - Optional `lru-memoize` instance for
 *   storing decoded token claims). By default, the cache will be initialized
 *   with a max of 100 items, and an expiration of 5 seconds.
 * @param {Function} [options.decorateError] - Optional callback to customize
 *   the error response body (by default, uses the 3 fields from
 *   https://datatracker.ietf.org/doc/html/rfc6749#section-5.2).
 *
 * @returns {Function} Returns an Express.js middleware route handler.
 */
export function authorizeAccessToken({
  requiredScope, validIssuers, verify, validateClaims, decorateError,
  logger = noopLogger, claimsCache = new LruCache({max: 100, maxAge: 5000})
}) {
  assert.string(requiredScope, 'options.requiredScope');
  assert.optionalArrayOfString(validIssuers, 'options.validIssuers');
  assert.func(verify, 'options.verify');
  assert.optionalFunc(validateClaims, 'options.validateClaims');
  assert.optionalFunc(decorateError, 'options.decorateError');

  // Returns an Express middleware handle
  return async (req, res, next) => {
    try {
      // Extract access token from Authorization: header
      const {clientAccessToken} = _tokenFromHeader({
        authorizationHeader: req.get('authorization')
      });

      // Decode claims, verify signature
      let claims;
      try {
        (claims = await claimsCache.memoize({
          key: clientAccessToken,
          fn: async () => verify({token: clientAccessToken})
        }));
      } catch(e) {
        logger.debug('Error verifying access token.',
          {token: clientAccessToken, error: e});
        throw new InvalidToken({
          description: 'Error verifying the access token.'
        });
      }

      const {iss, exp, scope} = claims;

      // simple comparison, no leeway / clock skew
      _assertExpiration({exp});

      if(validIssuers) {
        _assertIssuer({iss, validIssuers});
      }

      if(validateClaims) {
        await validateClaims({claims});
      }

      _assertScope({tokenScope: scope, requiredScope, logger});

      // Success, set the decoded and validated `clientMetadata` property
      req.clientMetadata = {...claims};
    } catch(error) {
      return _handleError({error, logger, decorateError, res});
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
 * @throws {InvalidScope} If scope is missing or not a string.
 * @throws {InsufficientScope} If scopes do not match.
 *
 * @see https://tools.ietf.org/html/rfc6749#section-3.3
 *
 * @param {object} options - Options hashmap.
 * @param {string} options.tokenScope - Scope extracted from access_token.
 * @param {string} options.requiredScope - Scope required for a particular
 *   api endpoint.
 * @param {object} options.logger - Optional logger object.
 */
export function _assertScope({
  tokenScope, requiredScope, logger = noopLogger
} = {}) {
  if(typeof tokenScope !== 'string') {
    throw new InvalidScope(
      {description: `Invalid scope "${tokenScope}".`});
  }

  // Handle simple case (when there's a single scope or exact match)
  if(tokenScope === requiredScope) {
    return;
  }

  const tokenScopes = tokenScope.split(' ');
  const requiredScopes = requiredScope.split(' ');

  // Every required scope must be included in the token scope
  if(!requiredScopes.every(r => tokenScopes.includes(r))) {
    logger.debug(`Access denied for token scope "${tokenScope}". ` +
      `Scope required: "${requiredScope}".`);
    throw new InsufficientScope(
      {description: `Access denied for token scope "${tokenScope}".`});
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

function _assertExpiration({exp}) {
  // Date() works in milliseconds, `exp` is in seconds
  const now = Date.now();

  const expirationDate = new Date(exp * 1000);
  if(expirationDate.getTime() < now) {
    throw new InvalidToken({
      description: 'Access token has expired.',
      name: 'ConstraintError'
    });
  }
}

function _assertIssuer({iss, validIssuers}) {
  if(!validIssuers.includes(iss)) {
    throw new InvalidToken({
      description: `Token issuer "${iss}" is not authorized.`,
      name: 'NotAllowedError'
    });
  }
}

function _handleError({error, logger, decorateError, res}) {
  logger.error('Authorization error:', {error});
  const {
    error: errorId, error_description: description, error_uri: uri, name
  } = error;

  const statusCode = error.statusCode || 400;
  const oauth2ErrorResponse = {
    error: errorId || 'invalid_request',
    error_description: description || error.message,
    error_uri: uri,
    name
  };

  if(decorateError) {
    decorateError({errorResponse: oauth2ErrorResponse});
  }

  res.set({
    'Cache-Control': 'no-store',
    Pragma: 'no-cache'
  });
  return res.status(statusCode).json(oauth2ErrorResponse);
}
