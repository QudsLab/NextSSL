//! Table of live objects behind opaque `u64` handles (DRBG, PAKE and threshold sessions).
//!
//! A handle is a counter value, never a pointer, and is never reused, so a stale or forged
//! handle is `NEXTSSL_ERR_BAD_HANDLE` instead of memory corruption. The table is bounded.

use crate::ops::Fail;
use nextssl_core::{Drbg, Error, PakeState, ThresholdState};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

/// Most live handles at once.
pub const NEXTSSL_MAX_HANDLES: usize = 4096;

pub enum Obj {
    Drbg(Box<dyn Drbg>),
    Pake(Box<dyn PakeState>),
    Threshold(Box<dyn ThresholdState>),
}

static TABLE: Mutex<BTreeMap<u64, Obj>> = Mutex::new(BTreeMap::new());
static NEXT: AtomicU64 = AtomicU64::new(1);

fn table() -> MutexGuard<'static, BTreeMap<u64, Obj>> {
    TABLE.lock().unwrap_or_else(PoisonError::into_inner)
}

pub fn insert(obj: Obj) -> Result<u64, Fail> {
    let mut t = table();
    if t.len() >= NEXTSSL_MAX_HANDLES {
        return Err(Error::Backend("too many open handles").into());
    }
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    t.insert(id, obj);
    Ok(id)
}

/// Puts an object back under an id it was taken from (state machines advance by value).
pub fn restore(id: u64, obj: Obj) -> Result<(), Fail> {
    table().insert(id, obj);
    Ok(())
}

pub fn remove(id: u64) -> Result<Obj, Fail> {
    table().remove(&id).ok_or(Fail::BadHandle)
}

fn remove_if(id: u64, want: impl Fn(&Obj) -> bool) -> Result<Obj, Fail> {
    let mut t = table();
    match t.get(&id) {
        Some(o) if want(o) => t.remove(&id).ok_or(Fail::BadHandle),
        _ => Err(Fail::BadHandle),
    }
}

pub fn remove_drbg(id: u64) -> Result<Obj, Fail> {
    remove_if(id, |o| matches!(o, Obj::Drbg(_)))
}

pub fn remove_pake(id: u64) -> Result<Obj, Fail> {
    remove_if(id, |o| matches!(o, Obj::Pake(_)))
}

pub fn remove_threshold(id: u64) -> Result<Obj, Fail> {
    remove_if(id, |o| matches!(o, Obj::Threshold(_)))
}

/// Runs `f` on the DRBG behind `id`.
pub fn with_drbg<T>(id: u64, f: impl FnOnce(&mut dyn Drbg) -> Result<T, Error>) -> Result<T, Fail> {
    let mut t = table();
    match t.get_mut(&id) {
        Some(Obj::Drbg(d)) => Ok(f(&mut **d)?),
        _ => Err(Fail::BadHandle),
    }
}

/// Number of live handles (tests).
#[cfg(test)]
pub fn live() -> usize {
    table().len()
}
