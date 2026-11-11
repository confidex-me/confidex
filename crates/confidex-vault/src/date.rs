//! Calendar values use numeric components and do not use a time zone.
use crate::record::{Mapping, Value, ValueError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Precision {
    Day,
    Month,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Civil {
    pub year: u16,
    pub month: u8,
    pub day: Option<u8>,
}
impl Civil {
    pub fn text(self) -> String {
        match self.day {
            Some(day) => format!("{day:02}/{:02}/{:04}", self.month, self.year),
            None => format!("{:02}/{:04}", self.month, self.year),
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Invalid;
pub fn parse(text: &str, precision: Precision) -> Result<Option<Civil>, Invalid> {
    if text.is_empty() {
        return Ok(None);
    }
    if text.len() > 10 {
        return Err(Invalid);
    }
    let parts: Vec<_> = text.split('/').collect();
    let widths: &[usize] = if precision == Precision::Day {
        &[2, 2, 4]
    } else {
        &[2, 4]
    };
    if parts.len() != widths.len()
        || parts
            .iter()
            .zip(widths)
            .any(|(s, n)| s.len() != *n || !s.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(Invalid);
    }
    let year = parts[parts.len() - 1].parse::<u16>().map_err(|_| Invalid)?;
    let month = parts[parts.len() - 2].parse::<u8>().map_err(|_| Invalid)?;
    let day = if precision == Precision::Day {
        Some(parts[0].parse::<u8>().map_err(|_| Invalid)?)
    } else {
        None
    };
    let value = Civil { year, month, day };
    if !value.valid() {
        return Err(Invalid);
    }
    Ok(Some(value))
}

impl Precision {
    pub fn from_type(kind: &str) -> Option<Self> {
        match kind {
            "date/v1" => Some(Self::Day),
            "month-year/v1" => Some(Self::Month),
            _ => None,
        }
    }
    pub fn keys(self) -> &'static [&'static str] {
        match self {
            Self::Day => &["year", "month", "day"],
            Self::Month => &["year", "month"],
        }
    }
}
impl Civil {
    fn valid(self) -> bool {
        if self.year == 0 || self.year > 9999 || !(1..=12).contains(&self.month) {
            return false;
        }
        let leap = self.year.is_multiple_of(4)
            && (!self.year.is_multiple_of(100) || self.year.is_multiple_of(400));
        let days = [
            31,
            if leap { 29 } else { 28 },
            31,
            30,
            31,
            30,
            31,
            31,
            30,
            31,
            30,
            31,
        ][usize::from(self.month - 1)];
        self.day.is_none_or(|day| day > 0 && day <= days)
    }
    pub fn value(self) -> Mapping {
        let mut value = Mapping::from_iter([
            ("year".into(), Value::from(self.year)),
            ("month".into(), Value::from(self.month)),
        ]);
        if let Some(day) = self.day {
            value.insert("day".into(), day.into());
        }
        value
    }
}
pub fn read(value: &Mapping, precision: Precision) -> Result<Option<Civil>, ValueError> {
    if precision.keys().iter().all(|key| !value.contains_key(*key)) {
        return Ok(None);
    }
    let number = |key| {
        value
            .get(key)
            .ok_or(ValueError::Missing(key))?
            .as_u64()
            .ok_or(ValueError::WrongType(key))
    };
    let date = Civil {
        year: u16::try_from(number("year")?).map_err(|_| ValueError::InvalidValue("year"))?,
        month: u8::try_from(number("month")?).map_err(|_| ValueError::InvalidValue("month"))?,
        day: if precision == Precision::Day {
            Some(u8::try_from(number("day")?).map_err(|_| ValueError::InvalidValue("day"))?)
        } else {
            None
        },
    };
    if !date.valid() {
        return Err(ValueError::InvalidValue("date"));
    }
    Ok(Some(date))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn numeric_dates_keep_precision_and_reject_invalid_components() {
        for (text, precision) in [
            ("29/02/2024", Precision::Day),
            ("02/2024", Precision::Month),
        ] {
            let civil = parse(text, precision).unwrap().unwrap();
            let value = civil.value();
            assert_eq!(read(&value, precision), Ok(Some(civil)));
            assert_eq!(value.contains_key("day"), precision == Precision::Day);
            assert_eq!(read(&Mapping::new(), precision), Ok(None));
        }
        for text in [
            "29/02/1900",
            "31/04/2024",
            "00/01/2024",
            "01/13/2024",
            "01/01/0000",
            "partial",
        ] {
            assert!(parse(text, Precision::Day).is_err());
        }
        assert!(parse("29/02/2000", Precision::Day).is_ok());
        let valid = parse("29/02/2024", Precision::Day)
            .unwrap()
            .unwrap()
            .value();
        for (key, bad) in [
            ("day", Value::from(30)),
            ("month", Value::from(13)),
            ("year", Value::from(2023)),
            ("year", Value::from(10000)),
            ("year", Value::from("2024")),
            ("day", Value::F64(29.)),
        ] {
            let mut value = valid.clone();
            value.insert(key.into(), bad);
            assert!(read(&value, Precision::Day).is_err());
        }
        let mut partial = valid;
        partial.remove("day");
        assert!(read(&partial, Precision::Day).is_err());
    }
}
