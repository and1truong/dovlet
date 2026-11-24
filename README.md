# dovlet (CLI)

Command-line port of [Dovlet](https://github.com/and1truong/dovlet): encrypts text
or a ZIP file into an AES-256 ZIP and hides it inside a PNG. Images are
byte-compatible with the web app in both directions.

## Build

```sh
go build -o dovlet .
# or
go install github.com/and1truong/dovlet@main-go
```

## Use

```sh
# Encode: message from stdin, -i FILE, or -m TEXT; -z embeds a ZIP file instead
dovlet encode -i secret.txt -o picture.png
dovlet encode -i secret.txt -c photo.jpg -o picture.png
dovlet encode -z photos.zip -o picture.png
echo "hello" | dovlet encode

# Decode: text to stdout, or -o FILE; a ZIP file is saved under its original
# filename unless -o is given; --zip saves the encrypted ZIP
dovlet decode picture.png
dovlet decode picture.png -o message.txt --zip message.zip
dovlet decode picture.png -o photos.zip
```

The password is read, in order, from `--password-file FILE` (first line),
`$DOVLET_PASSWORD`, or a hidden terminal prompt (asked twice when encoding).
It is never accepted as a command-line argument. Existing files are not
overwritten without `-f`. Decoded messages are written with mode 0600.

`-m TEXT` is convenient but puts the message in the process list and shell
history; prefer `-i` or stdin for anything secret.

## Format and limits

Same as the web app: UTF-8 text up to 500,000 bytes, ZIP files up to 1,400,000
bytes; passwords of at least 12 characters; input images up to 25 MiB and 16
million pixels. Covers (PNG, JPEG or WebP) are flattened onto white, scaled to
at most 2,000 px on the longest side, and rotated per JPEG EXIF orientation.
The default cover is the same 1200×1200 apple, and holds a ZIP file of about
539 KB. A ZIP file of 1,400,000 bytes needs a cover of at least 1933×1933 px
(`-c`). Payload: `APPLE001` + 4-byte big-endian length + ZIP, one LSB per RGB channel, row-major, MSB first. ZIP:
one entry, WinZip AE-2 AES-256. Text mode stores one `message.txt` entry
(DEFLATE); ZIP mode (`-z`) stores the original `.zip` file under its original
filename, stored uncompressed. Every exported PNG is decoded again before it
is written.

Keep the PNG unchanged: screenshots, resizing or recompression destroy the
payload. There is no password recovery.

## Tests

```sh
go test ./...
# Cross-check against the web app's own JavaScript (requires Node.js 22+):
DOVLET_WEB_HTML=/path/to/dovlet/index.html go test ./internal/dovlet -run WebInterop -v
```
