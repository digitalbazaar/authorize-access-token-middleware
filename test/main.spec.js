/*!
 * Copyright (c) 2021 Digital Bazaar, Inc. All rights reserved.
 */
import assert from 'assert-plus';
import chai from 'chai';
import chaiHttp from 'chai-http';
import crypto from 'crypto';
import express from 'express';

import {authorizeAccessToken} from '../lib';
import {_assertScope} from '../lib/authorizeAccessToken.js';
import {InvalidRequest} from '@interop/oauth2-errors';
import base64url from 'base64url-universal';
const DEFAULT_ALLOWED_JWT_ALGS = new Set(['HS256', 'ES256']);

chai.use(chaiHttp);
chai.should();
const {expect} = chai;

const INVALID_MOCK_ACCESS_TOKEN = 'eyJhbGciOiJFUzI1NiIsImtpZCI6Ijc3In0' +
  '.eyJpc3MiOiJodHRwOi8vYXV0aG9yaXphdGlvbi1zZXJ2ZXIuZXhhbXBsZS5jb20iLCJzdW' +
  'IiOiJfX2JfYyIsImV4cCI6MTU4ODQyMDgwMCwic2NvcGUiOiJjYWxlbmRhciIsImF1ZCI6I' +
  'mh0dHBzOi8vY2FsLmV4YW1wbGUuY29tLyJ9.nNWJ2dXSxaDRdMUKlzs-cYI' +
  'j8MDoM6Gy7pf_sKrLGsAFf1C2bDhB60DQfW1DZL5npdko1_Mmk5sUfzkiQNVpYw';

const VALID_MOCK_ACCESS_TOKEN = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9' +
  '.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlLmNvbSIsImlhdCI6MTYxMzY1NTAyM' +
  'CwiZXhwIjoxNjQ1MTkxMDIwLCJhdWQiOiIiLCJzdWIiOiIiLCJjbGllbnRfaWQiOiJzNkJoZFJ' +
  'rcXQzIiwic2NvcGUiOiJyZWFkIHdyaXRlIn0.Hv3I-bgcsxn4IaCmU0dcywaP8Sw' +
  '_LBLrEgA_pSVc5zM';

function _createVerifyFn({tokenizer}) {
  return async function verifySignature({
    alg, kid, data, signature, ALLOWED_JWT_ALGS = DEFAULT_ALLOWED_JWT_ALGS
  }) {
    if(!ALLOWED_JWT_ALGS.has(alg)) {
      throw new InvalidRequest({
        description: `"${alg}" is invalid.`
      });
    }
    let hmac;
    try {
      ({hmac} = await tokenizer.get({id: kid}));
    } catch(e) {
      throw new InvalidRequest({
        description: `Unable to verify token with kid: "${kid}"`
      });
    }

    const encodedSignature = base64url.encode(signature);
    return hmac.verify({data, signature: encodedSignature});
  };
}

async function hashClientSecret({clientSecret}) {
  assert.string(clientSecret, 'clientSecret');
  const digest = crypto.createHash('sha256').update(clientSecret).digest();
  // format as multihash digest
  // sha2-256: 0x12, length: 32 (0x20), digest value
  const mh = Buffer.alloc(34);
  mh[0] = 0x12;
  mh[1] = 0x20;
  mh.set(digest, 2);
  return mh;
}

const mockTokenizer = {
  async get({id, alg}) {
    return {
      id,
      hmac: {
        // eslint-disable-next-line max-len
        id: 'https://localhost:18443/kms/keystores/z19wuB5GSxny6xVDsLgaAibd6/keys/z19rQ9Hjr4tCUSSQTmDiTE771',
        type: 'Sha256HmacKey2019',
        algorithm: alg,
        invocationSigner: {
          // eslint-disable-next-line max-len
          id: 'did:key:z6Mkj582WrF84bRJKSFjn9QkEAbUY346Qh7EhHoMoqE7175P#z6Mkj582WrF84bRJKSFjn9QkEAbUY346Qh7EhHoMoqE7175P',
          type: 'Ed25519VerificationKey2018'
        },
        kmsClient: {
          // eslint-disable-next-line max-len
          keystore: 'https://localhost:18443/kms/keystores/z19wuB5GSxny6xVDsLgaAibd6',
          httpsAgent: {}
        },
        cache: {},
        _pruneCacheTimer: null,
        // eslint-disable-next-line no-unused-vars
        verify: ({data, signature}) => {
          return true;
        }
      }
    };
  }
};

// eslint-disable-next-line no-unused-vars
const mockLoadClientRegistration = async ({clientId = 's6BhdRkqt3'}) => {
  return {
    client_id: clientId,
    client_secret_hash: await hashClientSecret({
      clientSecret: 'testClientSecret'
    }),
    scope: 'read write'
  };
};

describe('authorizeAccessToken()', () => {
  const app = express();
  app.post('/api/example',
    authorizeAccessToken({
      // scope required for this endpoint
      requiredScope: 'read write',
      loadClientRegistration: mockLoadClientRegistration,
      validIssuers: ['https://issuer.example.com'],
      // eslint-disable-next-line no-unused-vars
      validateClaims: async ({claims}) => {
        // perform custom validation on access token claims here
      },
      verifySignature: _createVerifyFn({tokenizer: mockTokenizer}),
      logger: console
    }),
    // eslint-disable-next-line no-unused-vars
    (req, res, next) => {
      res.send('OK');
    }
  );

  let requester;

  before(async () => {
    requester = chai.request(app).keepOpen();
  });

  after(async () => {
    requester.close();
  });

  it('should error if missing authorization header', async () => {
    const res = await requester.post('/api/example')
      .send({});
    expect(res).to.have.status(400);
    expect(res).to.be.json;
    expect(res.body.error).to.equal('invalid_request');
    expect(res.body.error_description)
      .to.equal('Missing "authorization" header.');
  });

  it('should error if authorization header is invalid', async () => {
    const res = await requester.post('/api/example')
      .set('authorization', `notBearer ${VALID_MOCK_ACCESS_TOKEN}`)
      .send({});
    expect(res).to.have.status(400);
    expect(res).to.be.json;
    expect(res.body.error).to.equal('invalid_request');
    expect(res.body.error_description)
      .to.equal('Invalid "authorization" header.');
  });

  it('should error if cannot verify access token', async () => {
    const res = await requester.post('/api/example')
      .set('authorization', `Bearer ${INVALID_MOCK_ACCESS_TOKEN}`)
      .send({});
    expect(res).to.have.status(403);
    expect(res).to.be.json;
    expect(res.body.error).to.equal('access_denied');
    expect(res.body.error_description).to.equal(
      'Invalid access token. The access token could not be verified.');
  });

  it('should successfully authorize access token', async () => {
    const res = await requester.post('/api/example')
      .set('content-type', 'application/json')
      .set('authorization', `Bearer ${VALID_MOCK_ACCESS_TOKEN}`)
      .send({});
    expect(res).to.have.status(200);
  });
});

describe('_assertScope', () => {
  it('should throw on missing params', () => {
    expect(() => _assertScope())
      .to.throw(assert.AssertionError,
        'options.tokenScope (string) is required');
    expect(() => _assertScope({tokenScope: 'read'}))
      .to.throw(assert.AssertionError,
        'options.registeredScope (string) is required');
  });

  it('should throw on token scope/required scope mismatch', () => {
    let error;
    try {
      _assertScope({
        tokenScope: 'read', registeredScope: 'read', requiredScope: 'write'
      });
    } catch(e) {
      error = e;
    }
    expect(error).to.exist;
    expect(error.error).to.equal('access_denied');
    expect(error.error_description).to
      .equal('Access denied for token scope "read". Scope required: "write".');
    expect(error.statusCode).to.equal(403);
  });

  it('should throw on token scope/registered scope mismatch', () => {
    let error;
    try {
      _assertScope({
        tokenScope: 'write', registeredScope: 'read', requiredScope: 'write'
      });
    } catch(e) {
      error = e;
    }
    expect(error).to.exist;
    expect(error.error).to.equal('access_denied');
    expect(error.error_description).to
      .equal('Access denied. Token scope "write" does not match registered ' +
        'client scope.');
    expect(error.statusCode).to.equal(403);
  });

  it('should succeed on match between token, required and registered', () => {
    let error;
    try {
      _assertScope({
        tokenScope: 'read', registeredScope: 'read', requiredScope: 'read'
      });
    } catch(e) {
      error = e;
    }
    expect(error).to.not.exist;
  });

  it('should succeed when token scope contains required scope', () => {
    let error;
    try {
      _assertScope({
        tokenScope: 'read write', registeredScope: 'read write',
        requiredScope: 'read'
      });
    } catch(e) {
      error = e;
    }
    expect(error).to.not.exist;
  });

  it('should succeed when registered scope contains token scope', () => {
    let error;
    try {
      _assertScope({
        tokenScope: 'read', registeredScope: 'read write',
        requiredScope: 'read'
      });
    } catch(e) {
      error = e;
    }
    expect(error).to.not.exist;
  });

  it('should fail when token scope is a subset of registered/required', () => {
    let error;
    try {
      _assertScope({
        tokenScope: 'read', registeredScope: 'read write',
        requiredScope: 'write read'
      });
    } catch(e) {
      error = e;
    }
    expect(error).to.exist;
    expect(error.error).to.equal('access_denied');
    expect(error.error_description).to
      .equal('Access denied for token scope "read". ' +
        'Scope required: "write read".');
    expect(error.statusCode).to.equal(403);
  });

  it('should succeed when token scope matches (order-independent)', () => {
    let error;
    try {
      _assertScope({
        tokenScope: 'read write', registeredScope: 'read write',
        requiredScope: 'write read'
      });
    } catch(e) {
      error = e;
    }
    try {
      _assertScope({
        tokenScope: 'read write', registeredScope: 'write read',
        requiredScope: 'write read'
      });
    } catch(e) {
      error = e;
    }
    expect(error).to.not.exist;
  });
});
