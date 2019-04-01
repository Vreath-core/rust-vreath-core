
const path = require('path').join(__dirname, 'rust_vreath_core_bg.wasm');
const bytes = require('fs').readFileSync(path);
let imports = {};
imports['./rust_vreath_core'] = require('./rust_vreath_core');
imports['env'] = require('env');

const wasmModule = new WebAssembly.Module(bytes);
const wasmInstance = new WebAssembly.Instance(wasmModule, imports);
module.exports = wasmInstance.exports;
