import * as wasm from './rust_vreath_core_bg';

let cachegetUint8Memory = null;
function getUint8Memory() {
    if (cachegetUint8Memory === null || cachegetUint8Memory.buffer !== wasm.memory.buffer) {
        cachegetUint8Memory = new Uint8Array(wasm.memory.buffer);
    }
    return cachegetUint8Memory;
}

let WASM_VECTOR_LEN = 0;

function passArray8ToWasm(arg) {
    const ptr = wasm.__wbindgen_malloc(arg.length * 1);
    getUint8Memory().set(arg, ptr / 1);
    WASM_VECTOR_LEN = arg.length;
    return ptr;
}

const lTextDecoder = typeof TextDecoder === 'undefined' ? require('util').TextDecoder : TextDecoder;

let cachedTextDecoder = new lTextDecoder('utf-8');

function getStringFromWasm(ptr, len) {
    return cachedTextDecoder.decode(getUint8Memory().subarray(ptr, ptr + len));
}

let cachedGlobalArgumentPtr = null;
function globalArgumentPtr() {
    if (cachedGlobalArgumentPtr === null) {
        cachedGlobalArgumentPtr = wasm.__wbindgen_global_argument_ptr();
    }
    return cachedGlobalArgumentPtr;
}

let cachegetUint32Memory = null;
function getUint32Memory() {
    if (cachegetUint32Memory === null || cachegetUint32Memory.buffer !== wasm.memory.buffer) {
        cachegetUint32Memory = new Uint32Array(wasm.memory.buffer);
    }
    return cachegetUint32Memory;
}
/**
* @param {Uint8Array} data
* @returns {string}
*/
export function wasm_get_sha256(data) {
    const ptr0 = passArray8ToWasm(data);
    const len0 = WASM_VECTOR_LEN;
    const retptr = globalArgumentPtr();
    try {
        wasm.wasm_get_sha256(retptr, ptr0, len0);
        const mem = getUint32Memory();
        const rustptr = mem[retptr / 4];
        const rustlen = mem[retptr / 4 + 1];

        const realRet = getStringFromWasm(rustptr, rustlen).slice();
        wasm.__wbindgen_free(rustptr, rustlen * 1);
        return realRet;


    } finally {
        wasm.__wbindgen_free(ptr0, len0 * 1);

    }

}

/**
* @returns {string}
*/
export function wasm_generate_key() {
    const retptr = globalArgumentPtr();
    wasm.wasm_generate_key(retptr);
    const mem = getUint32Memory();
    const rustptr = mem[retptr / 4];
    const rustlen = mem[retptr / 4 + 1];

    const realRet = getStringFromWasm(rustptr, rustlen).slice();
    wasm.__wbindgen_free(rustptr, rustlen * 1);
    return realRet;

}

/**
* @param {Uint8Array} private_key
* @returns {string}
*/
export function wasm_private2public(private_key) {
    const ptr0 = passArray8ToWasm(private_key);
    const len0 = WASM_VECTOR_LEN;
    const retptr = globalArgumentPtr();
    try {
        wasm.wasm_private2public(retptr, ptr0, len0);
        const mem = getUint32Memory();
        const rustptr = mem[retptr / 4];
        const rustlen = mem[retptr / 4 + 1];

        const realRet = getStringFromWasm(rustptr, rustlen).slice();
        wasm.__wbindgen_free(rustptr, rustlen * 1);
        return realRet;


    } finally {
        wasm.__wbindgen_free(ptr0, len0 * 1);

    }

}

/**
* @param {Uint8Array} private_key
* @param {Uint8Array} public_key
* @returns {string}
*/
export function wasm_get_shared_secret(private_key, public_key) {
    const ptr0 = passArray8ToWasm(private_key);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm(public_key);
    const len1 = WASM_VECTOR_LEN;
    const retptr = globalArgumentPtr();
    try {
        wasm.wasm_get_shared_secret(retptr, ptr0, len0, ptr1, len1);
        const mem = getUint32Memory();
        const rustptr = mem[retptr / 4];
        const rustlen = mem[retptr / 4 + 1];

        const realRet = getStringFromWasm(rustptr, rustlen).slice();
        wasm.__wbindgen_free(rustptr, rustlen * 1);
        return realRet;


    } finally {
        wasm.__wbindgen_free(ptr0, len0 * 1);
        wasm.__wbindgen_free(ptr1, len1 * 1);

    }

}

/**
* @param {Uint8Array} private_key
* @param {Uint8Array} data
* @returns {string}
*/
export function wasm_recoverable_sign(private_key, data) {
    const ptr0 = passArray8ToWasm(private_key);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm(data);
    const len1 = WASM_VECTOR_LEN;
    const retptr = globalArgumentPtr();
    try {
        wasm.wasm_recoverable_sign(retptr, ptr0, len0, ptr1, len1);
        const mem = getUint32Memory();
        const rustptr = mem[retptr / 4];
        const rustlen = mem[retptr / 4 + 1];

        const realRet = getStringFromWasm(rustptr, rustlen).slice();
        wasm.__wbindgen_free(rustptr, rustlen * 1);
        return realRet;


    } finally {
        wasm.__wbindgen_free(ptr0, len0 * 1);
        wasm.__wbindgen_free(ptr1, len1 * 1);

    }

}

/**
* @param {Uint8Array} data
* @param {Uint8Array} sign
* @param {number} recover_id
* @returns {string}
*/
export function wasm_recover_public_key(data, sign, recover_id) {
    const ptr0 = passArray8ToWasm(data);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm(sign);
    const len1 = WASM_VECTOR_LEN;
    const retptr = globalArgumentPtr();
    try {
        wasm.wasm_recover_public_key(retptr, ptr0, len0, ptr1, len1, recover_id);
        const mem = getUint32Memory();
        const rustptr = mem[retptr / 4];
        const rustlen = mem[retptr / 4 + 1];

        const realRet = getStringFromWasm(rustptr, rustlen).slice();
        wasm.__wbindgen_free(rustptr, rustlen * 1);
        return realRet;


    } finally {
        wasm.__wbindgen_free(ptr0, len0 * 1);
        wasm.__wbindgen_free(ptr1, len1 * 1);

    }

}

/**
* @param {Uint8Array} data
* @param {Uint8Array} sign
* @param {Uint8Array} public_key
* @returns {boolean}
*/
export function wasm_verify_sign(data, sign, public_key) {
    const ptr0 = passArray8ToWasm(data);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm(sign);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm(public_key);
    const len2 = WASM_VECTOR_LEN;
    try {
        return (wasm.wasm_verify_sign(ptr0, len0, ptr1, len1, ptr2, len2)) !== 0;

    } finally {
        wasm.__wbindgen_free(ptr0, len0 * 1);
        wasm.__wbindgen_free(ptr1, len1 * 1);
        wasm.__wbindgen_free(ptr2, len2 * 1);

    }

}

export function __wbindgen_throw(ptr, len) {
    throw new Error(getStringFromWasm(ptr, len));
}

const heap = new Array(32);

heap.fill(undefined);

heap.push(undefined, null, true, false);

let heap_next = heap.length;

function dropObject(idx) {
    if (idx < 36) return;
    heap[idx] = heap_next;
    heap_next = idx;
}

export function __wbindgen_object_drop_ref(i) { dropObject(i); }

