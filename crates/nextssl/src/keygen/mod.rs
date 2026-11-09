//! Key generation engines (REBUILD_PLAN.md section 6): `seed` (deterministic) and `password`
//! (memory-hard). Both are generic over the registry and take the tier policy explicitly.

pub mod password;
pub mod seed;
