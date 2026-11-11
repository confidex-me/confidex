# Record attachments

Photo and file entries keep binary `data` in the encrypted Record. The draft
uses a shared buffer that is cleared when its last owner is dropped. Metadata
such as `filename` and `mime` stays in the value mapping. Unknown keys survive
editing and saving.

`CheckDraft` builds the complete candidate Record from its verified revision,
applies all fields, and measures the same zlib level-6 output used by sealing.
It writes nothing. The limit is **4,000,000 compressed bytes for the complete
Record**, including every attachment, field, tag and extra value. Saving checks
the limit again. Source and decompression limits still apply separately.

Native file pickers and image codecs run outside the UI thread. Browser image
work runs in a dedicated Worker, using the existing image pipeline. Images use
WebP storage, explicit quality/Lossless and EXIF choices, a bounded preview,
and WebP/PNG/JPEG exports. Cancel or a failed size check keeps the current draft
attachment. Session changes discard late picker and processing results.

The browser protocol removes draft binary values from JSON and sends length-
framed byte buffers in the existing bounded attachment channel. Empty files
have a zero-length frame. Malformed, missing or extra frames are rejected.
Returned drafts, history and comparison responses use the same framing.
