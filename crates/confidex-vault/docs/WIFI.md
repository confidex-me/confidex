# Wi-Fi values and QR codes

`wifi/v1` requires `ssid: str` and `auth: str` (`nopass`, `WPA`, or `WEP`).
Optional `password: str` and `hidden: bool` default to empty and false. Unknown
fields remain intact. `Entry::validate_value` and `wifi::Credentials::from_value`
explicitly check this profile. Ordinary Record reads do not validate or connect.

SSID is nonempty printable UTF-8, at most 32 bytes. The profile does not cover
arbitrary binary SSIDs. Open networks accept only an absent/empty password.
WPA/WPA2 personal accepts 8–63 printable ASCII passphrase bytes or 64 hex digits
for a raw PSK. Legacy WEP accepts 5/13 printable ASCII bytes or 10/26 hex digits.
Enterprise EAP and SAE-only provisioning are outside this profile and are never
silently exported as another authentication method. These are parameter checks,
not proof of network availability, password correctness, or scanner support.

`Credentials::new` borrows validated fields. `payload()` returns zeroizing text
following the [ZXing Wi-Fi format](https://github.com/zxing/zxing/wiki/Barcode-Contents#wi-fi-network-config-android-ios-11).
It escapes backslash, semicolon, comma, colon, and double quote, so values cannot
inject new fields. Hex-looking literal SSIDs/passphrases are quoted; raw hex keys
remain unquoted. No trimming, normalization, URI escaping, or Unicode conversion
changes the stored values. WPA passphrase rules match the
[wpa_supplicant profile](https://android.googlesource.com/platform/external/wpa_supplicant_8/+/refs/heads/main/wpa_supplicant/wpa_supplicant.conf).

`qr()` returns a zeroizing module matrix: `size()` is its width and height, and
`dark(x,y)` reports a black module (false outside the matrix). Render sharp square
modules with a white quiet zone of at least `QUIET_ZONE` (4) modules on all sides.
The pure Rust qrcodegen-no-heap 1.8.1 encoder uses medium error correction, boosts
it when space permits, and selects versions 1–12 (at most 65×65 modules).
Payload capacity is fixed at 256 bytes; validated inputs fit it. Caller-provided
QR work buffers are fixed 530-byte zeroizing arrays, and output reserves at most
4,225 bytes fallibly. Dependency stack temporaries/compiler copies retain the
platform cleanup limitations. Payloads, matrices, screenshots and exported images
contain the Wi-Fi password; their presentation/lifetime belongs to the application.
The core performs no file access, network configuration, UI drawing, or scanning.
