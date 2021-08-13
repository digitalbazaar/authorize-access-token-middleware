/*!
 * Copyright (c) 2021 Digital Bazaar, Inc. All rights reserved.
 */
import assert from 'assert-plus';
import chai from 'chai';
import chaiHttp from 'chai-http';
import crypto from 'crypto';
import express from 'express';
import * as JWT from '@digitalbazaar/minimal-jwt';

import {authorizeAccessToken} from '../lib';
import {_assertScope} from '../lib/authorizeAccessToken.js';

chai.use(chaiHttp);
chai.should();
const {expect} = chai;

const SECRET = '<the-best-kept-secret>';
const MOCK_CLIENT_ID = 's6BhdRkqt3';

const INVALID_MOCK_ACCESS_TOKEN = 'eyJhbGciOiJFUzI1NiIsImtpZCI6Ijc3In0' +
  '.eyJpc3MiOiJodHRwOi8vYXV0aG9yaXphdGlvbi1zZXJ2ZXIuZXhhbXBsZS5jb20iLCJzdW' +
  'IiOiJfX2JfYyIsImV4cCI6MTU4ODQyMDgwMCwic2NvcGUiOiJjYWxlbmRhciIsImF1ZCI6I' +
  'mh0dHBzOi8vY2FsLmV4YW1wbGUuY29tLyJ9.nNWJ2dXSxaDRdMUKlzs-cYI' +
  'j8MDoM6Gy7pf_sKrLGsAFf1C2bDhB60DQfW1DZL5npdko1_Mmk5sUfzkiQNVpYw';

async function signFn({data}) {
  return crypto.createHmac('sha256', Buffer.from(SECRET)).update(data).digest();
}

async function verifyFn({alg, kid, data, signature}) {
  if(alg === 'HS256') {
    const expectedSignature = await signFn({data});

    return crypto.timingSafeEqual(
      Buffer.from(signature),
      Buffer.from(expectedSignature)
    );
  } else {
    throw new Error(`Key "${kid}" is not supported.`);
  }
}

const mockLoadClientRegistration = async ({client_id}) => {
  if(client_id !== MOCK_CLIENT_ID) {
    throw new Error('Not found.');
  }
  return {
    client_id,
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
      verifySignature: verifyFn,
      // logger: console
    }),
    // eslint-disable-next-line no-unused-vars
    (req, res, next) => {
      res.json(
        req.clientMetadata
      );
    }
  );

  let requester;
  let validAccessToken;
  let unregisteredClientToken;

  before(async () => {
    validAccessToken = await JWT.sign({
      header: {typ: 'JWT', alg: 'HS256', kid: '194B72684'},
      payload: {
        iss: 'https://issuer.example.com',
        iat: 1613655020,
        exp: 1645191020,
        client_id: MOCK_CLIENT_ID,
        scope: 'read write'
      },
      signFn
    });

    unregisteredClientToken = await JWT.sign({
      header: {typ: 'JWT', alg: 'HS256', kid: '194B72684'},
      payload: {
        iss: 'https://issuer.example.com',
        iat: 1613655020,
        exp: 1645191020,
        client_id: '<unregistered client id>',
        scope: 'read write'
      },
      signFn
    });

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
      .set('authorization', `notBearer ${validAccessToken}`)
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

  it('should error if client id belongs to unregistered client', async () => {
    const res = await requester.post('/api/example')
      .set('authorization', `Bearer ${unregisteredClientToken}`)
      .send({});
    expect(res).to.have.status(400);
    expect(res).to.be.json;
    expect(res.body.error).to.equal('invalid_request');
    expect(res.body.error_description).to.equal(
      'Could not load a registered agent for the provided client ID.');
  });

  it('should error if issuer is not authorized', async () => {
  });

  it('should error if token expired', async () => {
  });

  it('should successfully authorize access token', async () => {
    const res = await requester.post('/api/example')
      .set('content-type', 'application/json')
      .set('authorization', `Bearer ${validAccessToken}`)
      .send({});
    expect(res).to.have.status(200);
    expect(res.body.iss).to.equal('https://issuer.example.com');
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
