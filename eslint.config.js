// ESLint flat config: the recommended rules, plus the right globals for each part of the app.
const js = require('@eslint/js');
const globals = require('globals');

module.exports = [
  { ignores: ['node_modules/'] },
  js.configs.recommended,
  {
    files: ['**/*.js'],
    languageOptions: { ecmaVersion: 2023, sourceType: 'commonjs', globals: globals.node },
    rules: {
      // Unused catch bindings are fine. ignoreRestSiblings allows `({ snapshot, ...rest }) => rest`,
      // the idiom src/handover.js uses to drop a field from an object.
      'no-unused-vars': ['error', { caughtErrors: 'none', ignoreRestSiblings: true }],
    },
  },
  {
    // Front end: plain browser scripts, no modules, no build step
    files: ['public/**/*.js'],
    languageOptions: { sourceType: 'script', globals: globals.browser },
  },
];
