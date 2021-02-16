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
// import noopLogger from '../lib/noopLogger';

chai.use(chaiHttp);
chai.should();
const {expect} = chai;
const cache = new LRU({
  max: 1000,
  // 5 minutes
  maxAge: 300000
});

const bodyParserUrl = express.urlencoded({extended: true});

const MOCK_ACCESS_TOKEN = 'eyJhbGciOiJFUzI1NiIsImtpZCI6Ijc3In0' +
  '.eyJpc3MiOiJodHRwOi8vYXV0aG9yaXphdGlvbi1zZXJ2ZXIuZXhhbXBsZS5jb20iLCJzdW' +
  'IiOiJfX2JfYyIsImV4cCI6MTU4ODQyMDgwMCwic2NvcGUiOiJjYWxlbmRhciIsImF1ZCI6I' +
  'mh0dHBzOi8vY2FsLmV4YW1wbGUuY29tLyJ9.nNWJ2dXSxaDRdMUKlzs-cYI' +
  'j8MDoM6Gy7pf_sKrLGsAFf1C2bDhB60DQfW1DZL5npdko1_Mmk5sUfzkiQNVpYw';

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

// eslint-disable-next-line no-unused-vars
const mockLoadClientRegistration = async ({clientId}) => {
  return {
    client: {
      client_id: 's6BhdRkqt3',
      client_secret_hash: await hashClientSecret({
        clientSecret: 'testClientSecret'
      }),
      scope: ['read', 'write']
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
      }
    })
  );

  let requester;

  before(async () => {
    requester = chai.request(app).keepOpen();
  });

  after(async () => {
    requester.close();
  });

  // it('test', async () => {
  //   const res = await requester.post('/api/example')
  //     .set('authorization', `Bearer ${MOCK_ACCESS_TOKEN}`)
  //     .send({});
  //   // console.log(res);
  // });

  it('should error if called un-authenticated', async () => {
    const res = await requester.post('/api/example').send({});
    expect(res).to.have.status(403);
    expect(res).to.be.json;
    expect(res.body.error).to.equal('access_denied');
    // expect(res.body.error_description)
    //   .to.equal('Authentication Code required.');
  });
});
