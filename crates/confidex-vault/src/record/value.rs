use super::{Error, Value};
use rmpv::ValueRef;
use zeroize::{Zeroize, Zeroizing};

const _: () =
    assert!(std::mem::size_of::<Value>() <= 64 && std::mem::size_of::<ValueRef<'static>>() <= 64);

pub(super) struct Owned(pub Value);
impl Owned {
    pub fn take(mut self) -> Value {
        std::mem::replace(&mut self.0, Value::Nil)
    }
}
impl Drop for Owned {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

pub(super) fn owned(value: ValueRef<'_>) -> Result<Owned, Error> {
    Ok(match value {
        ValueRef::Nil => Owned(Value::Nil),
        ValueRef::Boolean(v) => Owned(Value::Boolean(v)),
        ValueRef::Integer(v) => Owned(Value::Integer(v)),
        ValueRef::F32(v) => Owned(Value::F32(v)),
        ValueRef::F64(v) => Owned(Value::F64(v)),
        ValueRef::String(v) => {
            let s = v.as_str().ok_or(Error::InvalidEncoding)?;
            let mut text = Zeroizing::new(String::new());
            text.try_reserve_exact(s.len())
                .map_err(|_| Error::Allocation)?;
            text.push_str(s);
            Owned(Value::String(std::mem::take(&mut *text).into()))
        }
        ValueRef::Binary(v) => Owned(Value::Binary(copy(v)?)),
        ValueRef::Ext(tag, v) => Owned(Value::Ext(tag, copy(v)?)),
        ValueRef::Array(values) => {
            let mut out = Owned(Value::Array(Vec::new()));
            let Value::Array(rows) = &mut out.0 else {
                unreachable!()
            };
            rows.try_reserve_exact(values.len())
                .map_err(|_| Error::Allocation)?;
            for v in values {
                rows.push(owned(v)?.take());
            }
            out
        }
        ValueRef::Map(values) => {
            let mut out = Owned(Value::Map(Vec::new()));
            let Value::Map(rows) = &mut out.0 else {
                unreachable!()
            };
            rows.try_reserve_exact(values.len())
                .map_err(|_| Error::Allocation)?;
            for (key, value) in values {
                let k = owned(key)?;
                let v = owned(value)?;
                rows.push((k.take(), v.take()));
            }
            out
        }
    })
}
fn copy(data: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = Zeroizing::new(Vec::new());
    out.try_reserve_exact(data.len())
        .map_err(|_| Error::Allocation)?;
    out.extend_from_slice(data);
    Ok(std::mem::take(&mut *out))
}
pub(super) fn wipe(value: &mut Value) {
    match value {
        Value::Nil => (),
        Value::Boolean(v) => v.zeroize(),
        Value::F32(v) => v.zeroize(),
        Value::F64(v) => v.zeroize(),
        Value::Integer(v) => {
            // The pointer has exclusive access to a live integer slot.
            unsafe {
                std::ptr::write_volatile(v, 0.into());
            }
        }
        Value::String(_) => {
            let Value::String(text) = std::mem::replace(value, Value::Nil) else {
                unreachable!()
            };
            text.into_bytes().zeroize();
        }
        Value::Binary(data) => data.zeroize(),
        Value::Ext(tag, data) => {
            tag.zeroize();
            data.zeroize();
        }
        Value::Array(values) => {
            for v in values.iter_mut() {
                wipe(v);
            }
            values.clear();
        }
        Value::Map(values) => {
            for (k, v) in values.iter_mut() {
                wipe(k);
                wipe(v);
            }
            values.clear();
        }
    }
    *value = Value::Nil;
}
