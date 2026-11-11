//! Draft copies share bytes. The last owner clears the buffer.
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::sync::Arc;
use zeroize::Zeroizing;

#[derive(Clone, Default, PartialEq, Eq)]
pub struct Bytes(Arc<Zeroizing<Vec<u8>>>);
impl From<Vec<u8>> for Bytes {
    fn from(bytes: Vec<u8>) -> Self {
        Self(Arc::new(Zeroizing::new(bytes)))
    }
}
impl std::ops::Deref for Bytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.0.as_slice()
    }
}
impl Serialize for Bytes {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.as_slice().serialize(serializer)
    }
}
impl<'de> Deserialize<'de> for Bytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Vec::<u8>::deserialize(deserializer).map(Self::from)
    }
}
