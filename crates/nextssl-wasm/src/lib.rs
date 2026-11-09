//! wasm-bindgen stub: exposes the safe API (hash, encode, decode) to JS.

use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn hash(alg: &str, data: &[u8]) -> Result<Vec<u8>, JsError> {
    nextssl::hash(alg, data).map_err(|e| JsError::new(&e.to_string()))
}

#[wasm_bindgen]
pub fn encode(alg: &str, data: &[u8]) -> Result<Vec<u8>, JsError> {
    nextssl::encode(alg, data).map_err(|e| JsError::new(&e.to_string()))
}

#[wasm_bindgen]
pub fn decode(alg: &str, text: &[u8]) -> Result<Vec<u8>, JsError> {
    nextssl::decode(alg, text).map_err(|e| JsError::new(&e.to_string()))
}
