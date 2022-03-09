const path = require('path')
const nodeExternals = require('webpack-node-externals')
const Dotenv = require('dotenv-webpack')

module.exports = {
  target: 'node',
  entry: {
    edge: path.resolve(__dirname, './lambda/edge/index.ts'),
    auth: path.resolve(__dirname, './lambda/auth/index.ts'),
  },
  // build時は`dependencies`だけを読み込むようにする
  externals: [
    nodeExternals({
      modulesFromFile: {
        includeInBundle: ['dependencies'],
        excludeFromBundle: ['devDependencies'],
      },
    }),
  ],

  output: {
    filename: '[name]/index.js',
    path: path.resolve(__dirname, './dist/'),
    libraryTarget: 'commonjs2', // ライブラリの形式 tsconfig.jsonのmoduleとほぼ同じ。commonjs2かクライアントサイドならumdを設定することが多い。
  },
  // source-mapの種類 => https://webpack.js.org/configuration/devtool/
  devtool: 'inline-source-map',

  plugins: [
    new Dotenv({
      USER_POOL_ID: process.env.USER_POOL_ID,
      CLIENT_ID: process.env.CLIENT_ID,
    }),
  ],

  module: {
    rules: [
      {
        test: /\.ts$/,
        exclude: path.resolve(__dirname, './node_modules'),
        use: [
          {
            loader: 'ts-loader',
          },
        ],
      },
    ],
  },

  resolve: {
    extensions: ['.ts', '.js'],
  },
}
