use std::time::Duration;
use serde::{self, Deserialize, Serializer, Deserializer};

pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer
{
    serializer.serialize_u64(duration.as_secs())
}

pub fn deserialize<D>(deserializer: D) -> Result<Duration, D::Error>
    where D: Deserializer
{
    let duration = u64::deserialize(deserializer)?;
    Ok(Duration::from_secs(duration))
}
