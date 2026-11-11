use confidex_vault::{
    record::{Entry, Mapping, Record, Value, ValueError},
    resources::MAX_OPEN_MEMORY,
    wifi::{Auth, Credentials, QUIET_ZONE, Qr},
};

fn scan(qr: &Qr) -> Vec<u8> {
    let scale = 4;
    let side = (qr.size() + 2 * QUIET_ZONE) * scale;
    let mut image = vec![255; side * side];
    for y in 0..qr.size() {
        for x in 0..qr.size() {
            if qr.dark(x, y) {
                for dy in 0..scale {
                    for dx in 0..scale {
                        image[((y + QUIET_ZONE) * scale + dy) * side
                            + (x + QUIET_ZONE) * scale
                            + dx] = 0;
                    }
                }
            }
        }
    }
    let mut decoder = quircs::Quirc::default();
    let codes: Vec<_> = decoder.identify(side, side, &image).collect();
    assert_eq!(codes.len(), 1);
    codes
        .into_iter()
        .next()
        .unwrap()
        .unwrap()
        .decode()
        .unwrap()
        .payload
}

#[test]
fn escaped_credentials_and_independent_qr_decoder_preserve_exact_payload() {
    for (ssid, auth, password, hidden, expected) in [
        (
            "Cafe",
            Auth::Open,
            None,
            false,
            "WIFI:T:nopass;S:\"Cafe\";H:false;;",
        ),
        (
            "a;P:evil,\\\"",
            Auth::Wpa,
            Some("pass;,:\\\"word"),
            true,
            "WIFI:T:WPA;S:a\\;P\\:evil\\,\\\\\\\";P:pass\\;\\,\\:\\\\\\\"word;H:true;;",
        ),
        (
            "Сеть café",
            Auth::Wpa,
            Some("test passphrase"),
            false,
            "WIFI:T:WPA;S:Сеть café;P:test passphrase;H:false;;",
        ),
        (
            "ABCD",
            Auth::Wpa,
            Some("deadbeef"),
            false,
            "WIFI:T:WPA;S:\"ABCD\";P:\"deadbeef\";H:false;;",
        ),
        (
            "Legacy",
            Auth::Wep,
            Some("0123456789"),
            false,
            "WIFI:T:WEP;S:Legacy;P:0123456789;H:false;;",
        ),
    ] {
        let credentials = Credentials::new(ssid, auth, password, hidden).unwrap();
        assert_eq!(credentials.payload().unwrap().as_str(), expected);
        let qr = credentials.qr().unwrap();
        assert!((21..=65).contains(&qr.size()));
        assert!(!qr.dark(usize::MAX, 0));
        assert!(!qr.dark(0, usize::MAX));
        assert_eq!(scan(&qr), expected.as_bytes());
    }
}

#[test]
fn maximum_escaped_input_and_raw_keys_still_fit_the_bounded_encoder() {
    let ssid = ";".repeat(32);
    let password = "\\".repeat(63);
    let credentials = Credentials::new(&ssid, Auth::Wpa, Some(&password), true).unwrap();
    assert_eq!(
        scan(&credentials.qr().unwrap()),
        credentials.payload().unwrap().as_bytes()
    );
    let raw_key = "a".repeat(64);
    let credentials = Credentials::new("Wifi", Auth::Wpa, Some(&raw_key), false).unwrap();
    assert!(
        credentials
            .payload()
            .unwrap()
            .contains(&format!("P:{raw_key};"))
    );
    assert_eq!(
        scan(&credentials.qr().unwrap()),
        credentials.payload().unwrap().as_bytes()
    );
    for key in ["12345", "0123456789abc", "00112233445566778899aabbcc"] {
        Credentials::new("Wifi", Auth::Wep, Some(key), false).unwrap();
    }
}

#[test]
fn invalid_credentials_fail_explicitly_but_remain_readable_as_record_values() {
    for ssid in ["", "line\nbreak", "\0", &"x".repeat(33), &"é".repeat(17)] {
        assert_eq!(
            Credentials::new(ssid, Auth::Open, None, false).err(),
            Some(ValueError::InvalidValue("ssid"))
        );
    }
    for (auth, password) in [
        (Auth::Open, "extra"),
        (Auth::Wpa, ""),
        (Auth::Wpa, "1234567"),
        (Auth::Wpa, &"g".repeat(64)),
        (Auth::Wpa, "abcdefgh\n"),
        (Auth::Wpa, "éééé"),
        (Auth::Wep, "1234"),
        (Auth::Wep, "g".repeat(10).as_str()),
    ] {
        assert_eq!(
            Credentials::new("Wifi", auth, Some(password), false).err(),
            Some(ValueError::InvalidValue("password"))
        );
    }
    let mut entry = Entry {
        name: String::new(),
        type_name: "wifi/v1".into(),
        value: Mapping::from([
            ("ssid".into(), "Wifi".into()),
            ("auth".into(), "nopass".into()),
            ("future".into(), Value::Ext(9, vec![255])),
        ]),
        extra: Mapping::new(),
    };
    assert_eq!(entry.validate_value(), Ok(()));
    for (field, bad, expected) in [
        ("ssid", Value::Nil, ValueError::WrongType("ssid")),
        ("auth", 1.into(), ValueError::WrongType("auth")),
        ("auth", "WPA2-EAP".into(), ValueError::InvalidValue("auth")),
        ("hidden", "true".into(), ValueError::WrongType("hidden")),
        ("password", Value::Nil, ValueError::WrongType("password")),
    ] {
        let old = entry.value.insert(field.into(), bad);
        assert_eq!(entry.validate_value(), Err(expected));
        if let Some(v) = old {
            entry.value.insert(field.into(), v);
        } else {
            entry.value.remove(field);
        }
    }
    entry.value.remove("auth");
    assert_eq!(entry.validate_value(), Err(ValueError::Missing("auth")));
    let record = Record {
        tags: Vec::new(),
        entries: vec![entry],
        extra: Mapping::new(),
    };
    let encoded = record.encode_content(MAX_OPEN_MEMORY).unwrap();
    let decoded = Record::decode_content(&encoded.bytes, MAX_OPEN_MEMORY).unwrap();
    assert_eq!(record.entries[0].value, decoded.record.entries[0].value);
}
