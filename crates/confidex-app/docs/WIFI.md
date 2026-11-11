# Wi-Fi QR fields

`wifi-qr/v1` is an independent entry. Its encrypted value contains `auth`
(`nopass`, `WEP`, or `WPA`) and optional `ssid` / `password` strings.
Each reference is a decimal, zero-based entry position in the same revision.
An absent or empty reference means no selection. These are not persistent IDs.

SSID resolves only to `text/v1`; password resolves only to `password/v1`.
The QR field stores no copy of either credential. The editor updates positions
after reorder or deletion. Deleting a target clears the reference rather than
binding it to the next entry. Names can be empty or repeated.

Legacy composite entries expand into separate draft fields. Their expansion
updates references on read; saving writes one entry per draft field. Invalid
or missing targets produce a field error, not a QR for another credential.
Unknown value keys remain intact when the field is edited.
