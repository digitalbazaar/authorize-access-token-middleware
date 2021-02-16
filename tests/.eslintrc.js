module.exports = {
  globals: {
    should: true,
    assertNoError: true
  },
  env: {
    node: true,
    mocha: true
  },
  extends: [
    'digitalbazaar',
    'digitalbazaar/jsdoc'
  ],
  ignorePatterns: ['node_modules/']
};
