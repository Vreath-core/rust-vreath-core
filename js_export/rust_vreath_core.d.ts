/* tslint:disable */
/**
* @param {Uint8Array} data 
* @returns {string} 
*/
export function wasm_get_sha256(data: Uint8Array): string;
/**
* @returns {string} 
*/
export function wasm_generate_key(): string;
/**
* @param {Uint8Array} private_key 
* @returns {string} 
*/
export function wasm_private2public(private_key: Uint8Array): string;
/**
* @param {Uint8Array} private_key 
* @param {Uint8Array} public_key 
* @returns {string} 
*/
export function wasm_get_shared_secret(private_key: Uint8Array, public_key: Uint8Array): string;
/**
* @param {Uint8Array} private_key 
* @param {Uint8Array} data 
* @returns {string} 
*/
export function wasm_recoverable_sign(private_key: Uint8Array, data: Uint8Array): string;
/**
* @param {Uint8Array} data 
* @param {Uint8Array} sign 
* @param {number} recover_id 
* @returns {string} 
*/
export function wasm_recover_public_key(data: Uint8Array, sign: Uint8Array, recover_id: number): string;
/**
* @param {Uint8Array} data 
* @param {Uint8Array} sign 
* @param {Uint8Array} public_key 
* @returns {boolean} 
*/
export function wasm_verify_sign(data: Uint8Array, sign: Uint8Array, public_key: Uint8Array): boolean;
