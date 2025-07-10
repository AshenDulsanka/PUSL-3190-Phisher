import js from '@eslint/js'
import globals from 'globals'

export default [
  { ignores: ['node_modules', 'dist'] },
  {
    files: ['**/*.js'],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'module',
      globals: {
        ...globals.node,
        ...globals.es2021
      }
    },
    rules: {
      ...js.configs.recommended.rules,
      'no-unused-vars': ['error', { 
        varsIgnorePattern: '^_', 
        argsIgnorePattern: '^_' 
      }],
      'no-console': ['warn', { 
        allow: ['info', 'warn', 'error'] 
      }],
      'semi': ['error', 'never'],
      'quotes': ['error', 'single']
    }
  }
]