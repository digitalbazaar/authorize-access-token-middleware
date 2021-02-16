/*!
 * Copyright (c) 2021 Digital Bazaar, Inc. All rights reserved.
 */
import {authorizeAccessToken} from '../../lib';
import chai from 'chai';
import chaiHttp from 'chai-http';
import express from 'express';
import LRU from 'lru-cache';

chai.use(chaiHttp);
chai.should();
// const {expect} = chai;
const claimsCache = new LRU({
  max: 1000,
  // 5 minutes
  maxAge: 300000
});
const bodyParserUrl = express.urlencoded({extended: true});
const issueCredential = '/vc-issuer/issue';
const MOCK_ACCESS_TOKEN = 'eyJhbGciOiJFUzI1NiIsImtpZCI6Ijc3In0' +
  '.eyJpc3MiOiJodHRwOi8vYXV0aG9yaXphdGlvbi1zZXJ2ZXIuZXhhbXBsZS5jb20iLCJzdW' +
  'IiOiJfX2JfYyIsImV4cCI6MTU4ODQyMDgwMCwic2NvcGUiOiJjYWxlbmRhciIsImF1ZCI6I' +
  'mh0dHBzOi8vY2FsLmV4YW1wbGUuY29tLyJ9.nNWJ2dXSxaDRdMUKlzs-cYI' +
  'j8MDoM6Gy7pf_sKrLGsAFf1C2bDhB60DQfW1DZL5npdko1_Mmk5sUfzkiQNVpYw';

describe('authorizeAccessToken', async () => {
  const app = express();
  app.post(
    issueCredential,
    bodyParserUrl,
    authorizeAccessToken({
      cache: claimsCache,
      // scope required for this endpoint
      scope: 'custom-action-scope',
      // eslint-disable-next-line no-unused-vars
      loadClientRegistration: async ({clientId}) => {
        // do stuff to load the client registration from db or config
      },
      validIssuers: 'localhost',
      // customValidate  // optional
    })
  );

  let requester;

  before(async () => {
    requester = chai.request(app).keepOpen();
  });

  after(async () => {
    requester.close();
  });

  it('', async () => {
    const res = await requester.post('/vc-issuer/issue')
      .set('authorization', `Bearer ${MOCK_ACCESS_TOKEN}`)
      .send({});
    console.log(res);
  });
});
