use crate::record::{Mapping, ValueError};
use qrcodegen_no_heap::{QrCode, QrCodeEcc, Version};
use zeroize::Zeroizing;

pub const QUIET_ZONE: usize = 4;
const MAX_PAYLOAD: usize = 256;
const BUFFER: usize = 530;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Auth {
    Open,
    Wpa,
    Wep,
}
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Allocation,
    Encoding,
}

pub struct Credentials<'a> {
    ssid: &'a str,
    auth: Auth,
    password: &'a str,
    hidden: bool,
}
pub struct Qr {
    size: usize,
    pixels: Zeroizing<Vec<u8>>,
}
impl Qr {
    pub fn size(&self) -> usize {
        self.size
    }
    pub fn dark(&self, x: usize, y: usize) -> bool {
        x < self.size && y < self.size && self.pixels[y * self.size + x] != 0
    }
}
impl<'a> Credentials<'a> {
    pub fn new(
        ssid: &'a str,
        auth: Auth,
        password: Option<&'a str>,
        hidden: bool,
    ) -> Result<Self, ValueError> {
        if ssid.is_empty() || ssid.len() > 32 || ssid.chars().any(char::is_control) {
            return Err(ValueError::InvalidValue("ssid"));
        }
        let password = password.unwrap_or("");
        if password.len() > 64 {
            return Err(ValueError::InvalidValue("password"));
        }
        let printable = password.bytes().all(|b| (32..=126).contains(&b));
        let hex = password.bytes().all(|b| b.is_ascii_hexdigit());
        let valid = match auth {
            Auth::Open => password.is_empty(),
            Auth::Wpa => {
                ((8..=63).contains(&password.len()) && printable) || (password.len() == 64 && hex)
            }
            Auth::Wep => {
                (matches!(password.len(), 5 | 13) && printable)
                    || (matches!(password.len(), 10 | 26) && hex)
            }
        };
        if !valid {
            return Err(ValueError::InvalidValue("password"));
        }
        Ok(Self {
            ssid,
            auth,
            password,
            hidden,
        })
    }
    pub fn from_value(value: &'a Mapping) -> Result<Self, ValueError> {
        let text = |field| {
            value
                .get(field)
                .ok_or(ValueError::Missing(field))?
                .as_str()
                .ok_or(ValueError::WrongType(field))
        };
        let ssid = text("ssid")?;
        let auth = match text("auth")? {
            "nopass" => Auth::Open,
            "WPA" => Auth::Wpa,
            "WEP" => Auth::Wep,
            _ => return Err(ValueError::InvalidValue("auth")),
        };
        let password = value
            .get("password")
            .map(|v| v.as_str().ok_or(ValueError::WrongType("password")))
            .transpose()?;
        let hidden = value
            .get("hidden")
            .map(|v| v.as_bool().ok_or(ValueError::WrongType("hidden")))
            .transpose()?
            .unwrap_or(false);
        Self::new(ssid, auth, password, hidden)
    }
    pub fn payload(&self) -> Result<Zeroizing<String>, Error> {
        fn escaped(out: &mut String, text: &str, literal: bool) {
            let quoted = literal && text.bytes().all(|b| b.is_ascii_hexdigit());
            if quoted {
                out.push('"');
            }
            for c in text.chars() {
                if matches!(c, '\\' | ';' | ',' | '"' | ':') {
                    out.push('\\');
                }
                out.push(c);
            }
            if quoted {
                out.push('"');
            }
        }
        let mut out = Zeroizing::new(String::new());
        out.try_reserve_exact(MAX_PAYLOAD)
            .map_err(|_| Error::Allocation)?;
        out.push_str(match self.auth {
            Auth::Open => "WIFI:T:nopass;S:",
            Auth::Wpa => "WIFI:T:WPA;S:",
            Auth::Wep => "WIFI:T:WEP;S:",
        });
        escaped(&mut out, self.ssid, true);
        if self.auth != Auth::Open {
            out.push_str(";P:");
            let raw_hex = match self.auth {
                Auth::Wpa => self.password.len() == 64,
                Auth::Wep => matches!(self.password.len(), 10 | 26),
                Auth::Open => false,
            };
            escaped(&mut out, self.password, !raw_hex);
        }
        out.push_str(if self.hidden {
            ";H:true;;"
        } else {
            ";H:false;;"
        });
        Ok(out)
    }
    pub fn qr(&self) -> Result<Qr, Error> {
        let payload = self.payload()?;
        let mut scratch = Zeroizing::new([0u8; BUFFER]);
        let mut output = Zeroizing::new([0u8; BUFFER]);
        let qr = QrCode::encode_text(
            &payload,
            &mut scratch[..],
            &mut output[..],
            QrCodeEcc::Medium,
            Version::MIN,
            Version::new(12),
            None,
            true,
        )
        .map_err(|_| Error::Encoding)?;
        let size = qr.size() as usize;
        let mut pixels = Zeroizing::new(Vec::new());
        pixels
            .try_reserve_exact(size * size)
            .map_err(|_| Error::Allocation)?;
        for y in 0..size {
            for x in 0..size {
                pixels.push(u8::from(qr.get_module(x as i32, y as i32)));
            }
        }
        Ok(Qr { size, pixels })
    }
}
