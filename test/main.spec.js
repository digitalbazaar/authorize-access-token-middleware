/*!
 * Copyright (c) 2021 Digital Bazaar, Inc. All rights reserved.
 */
import assert from 'assert-plus';
import chai from 'chai';
import chaiHttp from 'chai-http';
import crypto from 'crypto';
import express from 'express';
import LRU from 'lru-cache';

import {authorizeAccessToken} from '../lib';
import noopLogger from '../lib/noopLogger';

chai.use(chaiHttp);
chai.should();
const {expect} = chai;
const cache = new LRU({
  max: 1000,
  // 5 minutes
  maxAge: 300000
});

const bodyParserUrl = express.urlencoded({extended: true});

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
    client: {
      client_id: clientId,
      client_secret_hash: await hashClientSecret({
        clientSecret: 'testClientSecret'
      }),
      scope: 'read write'
    }
  };
};

describe('authorizeAccessToken', async () => {
  const app = express();
  app.post('/api/example',
    bodyParserUrl,
    authorizeAccessToken({
      cache,
      // scope required for this endpoint
      scope: 'read write',
      loadClientRegistration: mockLoadClientRegistration,
      validIssuers: ['https://issuer.example.com'],
      // eslint-disable-next-line no-unused-vars
      customValidate: async ({req, claims}) => {
        // perform custom validation on access token claims here
      },
      tokenizer: mockTokenizer,
      noopLogger
    })
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
      .set('content-type', 'application/x-www-form-urlencoded')
      .set('authorization', `Bearer ${VALID_MOCK_ACCESS_TOKEN}`)
      .send({});
    // the res status is 404 since there is no handler that forwards it along to
    expect(res).to.have.status(404);
  });
});
