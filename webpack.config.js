const path = require('path');

module.exports = {
  entry: './index.js',
  mode:"none",
  output: {
    filename: 'index.js',
    path: path.resolve(__dirname, 'dist'),
  },
};