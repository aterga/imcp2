/* tslint:disable */
/* eslint-disable */

/**
 * Decode Candid reply bytes to textual Candid, type-less (field names appear as
 * their wire-format hashes). Prefer `decode_rets_with_did` when an interface is
 * available.
 */
export function decode_args(bytes: Uint8Array): string;

/**
 * Decode reply bytes against a method's declared return types (from the `.did`),
 * recovering record/variant field names instead of hashes.
 */
export function decode_rets_with_did(did: string, method: string, bytes: Uint8Array): string;

/**
 * Encode textual Candid arguments (e.g. `(record { amount = 5 })`) to bytes.
 */
export function encode_args(text: string): Uint8Array;

/**
 * Encode textual Candid args against a method's declared argument types (from
 * the canister's `.did`), coercing literals to the right Candid types.
 */
export function encode_args_with_did(did: string, method: string, text: string): Uint8Array;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly decode_args: (a: number, b: number) => [number, number, number, number];
    readonly decode_rets_with_did: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly encode_args: (a: number, b: number) => [number, number, number, number];
    readonly encode_args_with_did: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
