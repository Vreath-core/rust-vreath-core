/* tslint:disable */
export const memory: WebAssembly.Memory;
export function wasm_get_sha256(a: number, b: number, c: number): void;
export function wasm_generate_key(a: number): void;
export function wasm_private2public(a: number, b: number, c: number): void;
export function wasm_get_shared_secret(a: number, b: number, c: number, d: number, e: number): void;
export function wasm_recoverable_sign(a: number, b: number, c: number, d: number, e: number): void;
export function wasm_recover_public_key(a: number, b: number, c: number, d: number, e: number, f: number): void;
export function wasm_verify_sign(a: number, b: number, c: number, d: number, e: number, f: number): number;
export function __wbindgen_global_argument_ptr(): number;
export function __wbindgen_malloc(a: number): number;
export function __wbindgen_free(a: number, b: number): void;
