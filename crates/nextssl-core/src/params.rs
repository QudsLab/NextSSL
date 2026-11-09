use crate::{Error, Result};
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

/// Declared type of a parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParamType {
    U32,
    U64,
    /// Byte string; `min`/`max` bound its length.
    Bytes,
    /// UTF-8 string; `min`/`max` bound its length in bytes.
    Str,
    /// One of a closed set of strings (the value is carried as [`Value::Str`]). Any other
    /// string is an error, never a fallback. `ParamSpec::default` is an index into the list;
    /// `min`/`max` are not used.
    Enum(&'static [&'static str]),
}

/// Parameter value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    U32(u32),
    U64(u64),
    Bytes(Vec<u8>),
    Str(String),
}

/// Schema entry for one parameter (generated from `algo.toml`).
#[derive(Debug, Clone, Copy)]
pub struct ParamSpec {
    pub name: &'static str,
    pub ty: ParamType,
    pub min: u64,
    pub max: u64,
    pub required: bool,
    /// Default for `U32`/`U64` parameters; for `Enum` the index of the default value.
    /// `Str` and `Bytes` have no default (use `required`).
    pub default: Option<u64>,
}

/// A set of named, typed parameters.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Params(BTreeMap<String, Value>);

impl Params {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&mut self, name: &str, value: Value) -> &mut Self {
        self.0.insert(String::from(name), value);
        self
    }

    pub fn with(mut self, name: &str, value: Value) -> Self {
        self.set(name, value);
        self
    }

    pub fn get(&self, name: &str) -> Option<&Value> {
        self.0.get(name)
    }

    pub fn get_u32(&self, name: &str) -> Option<u32> {
        match self.0.get(name) {
            Some(Value::U32(v)) => Some(*v),
            _ => None,
        }
    }

    pub fn get_u64(&self, name: &str) -> Option<u64> {
        match self.0.get(name) {
            Some(Value::U64(v)) => Some(*v),
            _ => None,
        }
    }

    pub fn get_bytes(&self, name: &str) -> Option<&[u8]> {
        match self.0.get(name) {
            Some(Value::Bytes(v)) => Some(v),
            _ => None,
        }
    }

    pub fn get_str(&self, name: &str) -> Option<&str> {
        match self.0.get(name) {
            Some(Value::Str(v)) => Some(v),
            _ => None,
        }
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Validates against `specs`: rejects unknown names, wrong types, out-of-range values and
    /// missing required parameters. Returns a copy with numeric defaults filled in.
    pub fn validate(&self, specs: &[ParamSpec]) -> Result<Params> {
        for name in self.0.keys() {
            if !specs.iter().any(|s| s.name == name.as_str()) {
                return Err(Error::ParamUnknown);
            }
        }
        let mut out = Params::new();
        for spec in specs {
            match self.0.get(spec.name) {
                Some(v) => {
                    check_value(spec, v)?;
                    out.0.insert(String::from(spec.name), v.clone());
                }
                None => {
                    if spec.required {
                        return Err(Error::ParamMissing(spec.name));
                    }
                    if let Some(d) = spec.default {
                        let v = match spec.ty {
                            ParamType::U32 => Value::U32(
                                u32::try_from(d).map_err(|_| Error::ParamOutOfRange(spec.name))?,
                            ),
                            ParamType::U64 => Value::U64(d),
                            ParamType::Enum(values) => {
                                let i = usize::try_from(d)
                                    .map_err(|_| Error::ParamOutOfRange(spec.name))?;
                                let v = values.get(i).ok_or(Error::ParamOutOfRange(spec.name))?;
                                Value::Str(String::from(*v))
                            }
                            _ => return Err(Error::ParamType(spec.name)),
                        };
                        check_value(spec, &v)?;
                        out.0.insert(String::from(spec.name), v);
                    }
                }
            }
        }
        Ok(out)
    }
}

fn check_value(spec: &ParamSpec, v: &Value) -> Result<()> {
    if let ParamType::Enum(values) = spec.ty {
        return match v {
            Value::Str(s) if values.contains(&s.as_str()) => Ok(()),
            Value::Str(_) => Err(Error::ParamOutOfRange(spec.name)),
            _ => Err(Error::ParamType(spec.name)),
        };
    }
    let n = match (spec.ty, v) {
        (ParamType::U32, Value::U32(x)) => u64::from(*x),
        (ParamType::U64, Value::U64(x)) => *x,
        (ParamType::Bytes, Value::Bytes(b)) => b.len() as u64,
        (ParamType::Str, Value::Str(s)) => s.len() as u64,
        _ => return Err(Error::ParamType(spec.name)),
    };
    if n < spec.min || n > spec.max {
        return Err(Error::ParamOutOfRange(spec.name));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    const SPECS: &[ParamSpec] = &[
        ParamSpec {
            name: "t",
            ty: ParamType::U32,
            min: 1,
            max: 10,
            required: false,
            default: Some(3),
        },
        ParamSpec {
            name: "salt",
            ty: ParamType::Bytes,
            min: 4,
            max: 8,
            required: true,
            default: None,
        },
    ];

    #[test]
    fn missing_required() {
        assert_eq!(
            Params::new().validate(SPECS),
            Err(Error::ParamMissing("salt"))
        );
    }

    #[test]
    fn out_of_range() {
        let p = Params::new()
            .with("salt", Value::Bytes(vec![0; 4]))
            .with("t", Value::U32(11));
        assert_eq!(p.validate(SPECS), Err(Error::ParamOutOfRange("t")));
        let p = Params::new().with("salt", Value::Bytes(vec![0; 9]));
        assert_eq!(p.validate(SPECS), Err(Error::ParamOutOfRange("salt")));
        let p = Params::new().with("salt", Value::Bytes(vec![0; 3]));
        assert_eq!(p.validate(SPECS), Err(Error::ParamOutOfRange("salt")));
    }

    #[test]
    fn type_and_unknown() {
        let p = Params::new().with("salt", Value::U32(5));
        assert_eq!(p.validate(SPECS), Err(Error::ParamType("salt")));
        let p = Params::new()
            .with("salt", Value::Bytes(vec![0; 4]))
            .with("zz", Value::U32(1));
        assert_eq!(p.validate(SPECS), Err(Error::ParamUnknown));
    }

    const ENUM_SPECS: &[ParamSpec] = &[ParamSpec {
        name: "hash",
        ty: ParamType::Enum(&["sha256", "sha384", "sha512"]),
        min: 0,
        max: 0,
        required: false,
        default: Some(0),
    }];

    #[test]
    fn enum_default_and_validation() {
        let p = Params::new().validate(ENUM_SPECS).unwrap();
        assert_eq!(p.get_str("hash"), Some("sha256"));
        let p = Params::new()
            .with("hash", Value::Str("sha512".into()))
            .validate(ENUM_SPECS)
            .unwrap();
        assert_eq!(p.get_str("hash"), Some("sha512"));
        // unknown value: explicit error, no fallback to the default
        let p = Params::new().with("hash", Value::Str("md5".into()));
        assert_eq!(p.validate(ENUM_SPECS), Err(Error::ParamOutOfRange("hash")));
        // case matters
        let p = Params::new().with("hash", Value::Str("SHA256".into()));
        assert_eq!(p.validate(ENUM_SPECS), Err(Error::ParamOutOfRange("hash")));
        let p = Params::new().with("hash", Value::U32(1));
        assert_eq!(p.validate(ENUM_SPECS), Err(Error::ParamType("hash")));
    }

    #[test]
    fn required_str() {
        const S: &[ParamSpec] = &[ParamSpec {
            name: "hrp",
            ty: ParamType::Str,
            min: 1,
            max: 83,
            required: true,
            default: None,
        }];
        assert_eq!(Params::new().validate(S), Err(Error::ParamMissing("hrp")));
        let p = Params::new().with("hrp", Value::Str("".into()));
        assert_eq!(p.validate(S), Err(Error::ParamOutOfRange("hrp")));
        let p = Params::new().with("hrp", Value::Str("bc".into()));
        assert!(p.validate(S).is_ok());
    }

    #[test]
    fn defaults_filled() {
        let p = Params::new()
            .with("salt", Value::Bytes(vec![0; 4]))
            .validate(SPECS)
            .unwrap();
        assert_eq!(p.get_u32("t"), Some(3));
    }
}
