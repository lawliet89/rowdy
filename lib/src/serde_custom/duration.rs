//! Custom serializer and deserializer for `std::time::Duration`. Serializes to seconds, and deserializes from seconds.
use std::time::Duration;
use serde::{Deserialize, Serializer, Deserializer};

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

#[cfg(test)]
mod tests {
    use std::time::Duration;
    use serde_json;
    use super::*;

    #[derive(Serialize, Deserialize, Eq, PartialEq, Debug)]
    struct TestStruct {
        #[serde(with = "super")]
        duration: Duration,
    }

    #[test]
    fn serialization_round_trip() {
        let structure = TestStruct { duration: Duration::from_secs(1234) };

        let expected_json = "{\"duration\":1234}";
        let actual_json = not_err!(serde_json::to_string(&structure));
        assert_eq!(expected_json, actual_json);

        let deserialized_struct: TestStruct = not_err!(serde_json::from_str(&actual_json));
        assert_eq!(structure, deserialized_struct);
    }
}
