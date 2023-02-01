module.exports = {
  root: true,
  env: {
    node: true,
    mocha: true
  },
  extends: [
    'digitalbazaar',
    'digitalbazaar/jsdoc',
    'digitalbazaar/module'
  ],
  ignorePatterns: ['node_modules/']
};
