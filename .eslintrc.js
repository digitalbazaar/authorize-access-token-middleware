module.exports = {
  root: true,
  extends: [
    'eslint-config-digitalbazaar',
    'eslint-config-digitalbazaar/jsdoc'
  ],
  env: {
    node: true,
    mocha: true
  },
  rules: {
    'jsdoc/check-examples': 0
  }
};
