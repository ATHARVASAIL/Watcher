// ESLint flat config. Security-relevant rules are errors, not warnings.
import js from '@eslint/js';
import globals from 'globals';
import noUnsanitized from 'eslint-plugin-no-unsanitized';

const security = {
  'no-eval': 'error',
  'no-implied-eval': 'error',
  'no-new-func': 'error',
  'no-script-url': 'error',
  'no-proto': 'error',
  'no-caller': 'error',
  'no-restricted-properties': [
    'error',
    { object: 'document', property: 'write', message: 'Never write HTML strings into a document.' },
    { object: 'document', property: 'writeln', message: 'Never write HTML strings into a document.' },
  ],
  'no-restricted-syntax': [
    'error',
    {
      selector: "CallExpression[callee.property.name='setAttribute'][arguments.0.value=/^on/]",
      message: 'Do not set inline event handlers; use addEventListener.',
    },
  ],
};

const quality = {
  eqeqeq: ['error', 'always'],
  'no-var': 'error',
  'prefer-const': 'error',
  'no-shadow': 'error',
  'no-unused-vars': ['error', { argsIgnorePattern: '^_', caughtErrors: 'none' }],
  'no-param-reassign': ['error', { props: false }],
  'object-shorthand': 'error',
  'prefer-template': 'error',
};

export default [
  { ignores: ['node_modules/**', 'dist/**', 'coverage/**', 'test-site/**/*.map'] },
  js.configs.recommended,
  noUnsanitized.configs.recommended,
  { rules: { ...security, ...quality } },

  // Extension classic scripts (page isolated world, popup <script>, shared).
  {
    files: ['extension/shared/**/*.js', 'extension/scanner/**/*.js'],
    languageOptions: {
      ecmaVersion: 2024,
      sourceType: 'script',
      globals: { ...globals.browser, ...globals.webextensions },
    },
    rules: { strict: ['error', 'function'] },
  },
  // Popup ES modules.
  {
    files: ['extension/popup/**/*.js'],
    languageOptions: {
      ecmaVersion: 2024,
      sourceType: 'module',
      globals: { ...globals.browser, ...globals.webextensions },
    },
  },
  // Service worker (module).
  {
    files: ['extension/background/**/*.js'],
    languageOptions: {
      ecmaVersion: 2024,
      sourceType: 'module',
      globals: { ...globals.serviceworker, ...globals.webextensions },
    },
  },
  // Fixture site (runs in the browser).
  {
    files: ['test-site/**/*.js'],
    languageOptions: { ecmaVersion: 2024, sourceType: 'module', globals: globals.browser },
  },
  // Node tooling and tests.
  {
    files: ['**/*.mjs', 'eslint.config.js'],
    languageOptions: { ecmaVersion: 2024, sourceType: 'module', globals: globals.node },
  },
  // Playwright evaluate() callbacks run in the browser.
  {
    files: ['tests/e2e.test.mjs'],
    languageOptions: { globals: { ...globals.node, ...globals.browser, ...globals.webextensions } },
  },
];
