// /*!
//  * Copyright (c) 2021 Digital Bazaar, Inc. All rights reserved.
//  */
// import chai from 'chai';
// import chaiHttp from 'chai-http';
// import express from 'express';
// import {InvalidClient} from '@interop/oauth2-errors';
// import authorizeAccessToken from '../lib';

// chai.use(chaiHttp);
// chai.should();
// const {expect} = chai;

// const bodyParserUrl = express.urlencoded({extended: true});

// const tokenUrl = '/token';
// const MOCK_ACCESS_TOKEN = 'eyJhbGciOiJFUzI1NiIsImtpZCI6Ijc3In0' +
//   '.eyJpc3MiOiJodHRwOi8vYXV0aG9yaXphdGlvbi1zZXJ2ZXIuZXhhbXBsZS5jb20iLCJzdW' +
//   'IiOiJfX2JfYyIsImV4cCI6MTU4ODQyMDgwMCwic2NvcGUiOiJjYWxlbmRhciIsImF1ZCI6I' +
//   'mh0dHBzOi8vY2FsLmV4YW1wbGUuY29tLyJ9.nNWJ2dXSxaDRdMUKlzs-cYI' +
//   'j8MDoM6Gy7pf_sKrLGsAFf1C2bDhB60DQfW1DZL5npdko1_Mmk5sUfzkiQNVpYw';

// const mockAuthenticateClient = async ({client, clientSecret}) => {
//   if(!client) {
//     throw new InvalidClient({
//       description: 'Unknown client identifier.'
//     });
//   }

//   const {client_secret: storedClientSecret} = client;

// NOTE: a timing safe comparison is required, this example is NOT secure
//   return {authenticated: clientSecret === storedClientSecret};
// };

// // eslint-disable-next-line no-unused-vars
// const mockGetClient = async ({clientId}) => {
//   return {
//     client: {
//       client_id: 's6BhdRkqt3',
//       client_secret: '7Fjfp0ZBr1KtDRbnfVdmIw',
//       scope: ''
//     }
//   };
// };

// // eslint-disable-next-line no-unused-vars
// const mockIssue = async ({client, resource, scope, body, defaultMaxAge}) => {
//   return {
//     accessToken: MOCK_ACCESS_TOKEN,
//     expiresIn: 3600
//   };
// };

// describe('authorizeAccessToken', () => {
//   const app = express();
//   app.post(
//     tokenUrl,
//     bodyParserUrl,
//     authorizeAccessToken({
//       cache,
//       // scope required for this endpoint
//       scope: 'custom-action-scope',
//       loadClientRegistration: async ({clientId}) => {
//         // do stuff to load the client registration from db or config
//       },
//       logger,
//       customValidate  // optional
//     })
//   );

//   let requester;

//   before(async () => {
//     requester = chai.request(app).keepOpen();
//   });

//   after(async () => {
//     requester.close();
//   });

//   it(``, async () => {

//   });
// });