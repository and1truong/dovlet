# Dovlet

Private messages, carried inside pictures.

Dovlet is a self-contained HTML app that encrypts text into an AES-256 ZIP and hides that ZIP inside a PNG. Enter text and a password, then export a picture. A custom cover image is optional; a built-in apple illustration is used by default.

## Use

1. Download `index.html` and open it in a modern browser. No build, server, account, CDN, or internet connection is required.
2. In **Tạo ảnh**, enter your text and a password of at least 12 characters. Optionally choose a PNG, JPEG, or WebP cover.
3. Click **Export ảnh PNG**. Dovlet verifies the exported PNG can be decrypted before offering the download.
4. Send the PNG as an original **file/document attachment**, and share the password separately.
5. The recipient opens the same HTML file, chooses **Đọc ảnh**, uploads the PNG, and enters the password. They can copy the text, download `message.txt`, or save the encrypted ZIP.

The interface is in Vietnamese. All processing happens in browser memory. A restrictive Content Security Policy blocks network connections; no analytics or browser persistence is used. The HTML can also be served by any static host.

## Limits and format

- UTF-8 text: at most 500,000 bytes; input image: 25 MiB and 16 million pixels maximum.
- Custom covers are flattened onto white and scaled down to at most 2,000 pixels on their longest side before embedding. The default image is 1,200 × 1,200 pixels.
- Capacity: `floor(width × height × 3 / 8) - 12` bytes of encrypted ZIP. A cover that cannot hold the payload is rejected.
- ZIP: one `message.txt` entry, DEFLATE compression, WinZip AES-256 encryption, authenticated extraction, and a bounded decompression sink.
- Steganography: one least-significant bit per RGB channel, row-major, most-significant bit first within each payload byte. Alpha is unchanged.
- Header: eight ASCII bytes `APPLE001`, followed by a four-byte big-endian ZIP length, then the encrypted ZIP bytes. The original prototype marker is retained for compatibility.
- Embedded dependency: zip.js 2.7.57, BSD-3-Clause. Its copyright and license are included in `index.html`; workers are disabled for offline single-file operation.

**Keep the PNG unchanged.** Screenshots, resizing, JPEG conversion, or messaging-platform image processing can destroy the payload. Encryption protects the message; LSB embedding does not guarantee that hidden data is undetectable. Use a long, unique password: WinZip AES uses its standard legacy password derivation, so password strength matters. There is no password recovery.

## Development and validation

`index.html` is both source and deliverable. The first script is the vendored ZIP bundle; the second contains Dovlet's application code. Keep the embedded dependency's license when modifying it.

Run the dependency-free core checks with Node.js 22 or newer:

```sh
node tests/core.cjs
```

Optional browser checks:

```sh
npm install --no-save --package-lock=false playwright
npx playwright install chromium
node tests/browser.cjs
```

Set `CHROMIUM_PATH` to use an existing Chromium executable. Browser checks open the HTML via `file://` with the network disabled, test PNG export/import and password rejection, exercise a custom cover, and check mobile overflow and unexpected network requests.
