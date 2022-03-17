module.exports = {
  root: true,
  env: {
    // グローバル変数の設定。 => https://eslint.org/docs/user-guide/configuring/language-options#specifying-environments
    es6: true,
    node: true,
  },
  parser: '@typescript-eslint/parser', // ESLintがTypeScriptを理解するParserを指定
  parserOptions: {
    sourceType: 'module', // これがないとパースできない
    project: './tsconfig.eslint.json', // TypeScriptの対象を指定
  },
  plugins: [
    '@typescript-eslint', // TypeScript用ESLintのルールプラグインを導入
  ],
  extends: [
    // ルールセット
    'eslint:recommended', // ESLintの推奨設定（eslint:recommended）：https://eslint.org/docs/rules/
    'plugin:@typescript-eslint/recommended', // TypeScript用ルールセット（型を必要としない基本ルールセット）（@typescript-eslint/recommended）
    'plugin:@typescript-eslint/recommended-requiring-type-checking', // TypeScript用ルールセット（型を必要とする基本ルールセット）（@typescript-eslint/recommended-requiring-type-checking）
    'prettier',
  ],
  rules: {
    // 個別のルールがある場合は追記
    '@typescript-eslint/no-unsafe-assignment': 'off',
    '@typescript-eslint/require-await': 'off',
  },
}

