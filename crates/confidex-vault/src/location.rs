//! Coordinates are in degrees. This module does not use network services.
use crate::record::{Mapping, ValueError};

pub const FIELDS: [&str; 3] = ["name", "latitude", "longitude"];
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Invalid;

fn valid(number: f64, maximum: f64) -> bool {
    number.is_finite() && number.abs() <= maximum
}
pub fn parse(latitude: &str, longitude: &str) -> Result<Option<(f64, f64)>, Invalid> {
    if latitude.is_empty() && longitude.is_empty() {
        return Ok(None);
    }
    let coordinate = |text: &str, maximum| {
        if text.len() > 64 {
            return Err(Invalid);
        }
        let number = text
            .trim()
            .replace(',', ".")
            .parse::<f64>()
            .map_err(|_| Invalid)?;
        if !valid(number, maximum) {
            return Err(Invalid);
        }
        Ok(number)
    };
    Ok(Some((
        coordinate(latitude, 90.)?,
        coordinate(longitude, 180.)?,
    )))
}
pub fn read(value: &Mapping) -> Result<Option<(f64, f64)>, ValueError> {
    if value
        .get("name")
        .is_some_and(|name| name.as_str().is_none())
    {
        return Err(ValueError::WrongType("name"));
    }
    if !value.contains_key("latitude") && !value.contains_key("longitude") {
        return Ok(None);
    }
    let coordinate = |key, maximum| {
        let number = value
            .get(key)
            .ok_or(ValueError::Missing(key))?
            .as_f64()
            .ok_or(ValueError::WrongType(key))?;
        if !valid(number, maximum) {
            return Err(ValueError::InvalidValue(key));
        }
        Ok(number)
    };
    Ok(Some((
        coordinate("latitude", 90.)?,
        coordinate("longitude", 180.)?,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::Value;
    #[test]
    fn coordinates_require_a_finite_bounded_pair_and_allow_a_name_only() {
        assert_eq!(read(&Mapping::new()), Ok(None));
        assert_eq!(
            read(&Mapping::from_iter([(
                "name".into(),
                Value::from("Public place")
            )])),
            Ok(None)
        );
        let mut value = Mapping::from_iter([
            ("latitude".into(), Value::from(90)),
            ("longitude".into(), Value::from(-180)),
        ]);
        assert_eq!(read(&value), Ok(Some((90., -180.))));
        value.insert("latitude".into(), Value::F64(52.37));
        assert_eq!(read(&value), Ok(Some((52.37, -180.))));
        for bad in [
            Value::F64(f64::NAN),
            Value::F64(f64::INFINITY),
            Value::F64(90.1),
            Value::from("52.37"),
        ] {
            value.insert("latitude".into(), bad);
            assert!(read(&value).is_err());
        }
        value.remove("latitude");
        assert!(read(&value).is_err());
        assert_eq!(parse("52,37", "4.9"), Ok(Some((52.37, 4.9))));
        assert!(parse("1", "").is_err());
    }
}
