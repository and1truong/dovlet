// Runs the web app's own code (index.html) under Node to cross-check the Go
// implementation. Usage:
//   node interop.cjs INDEX.html embed   W H MSG_FILE OUT_RGBA   (password: $PW)
//   node interop.cjs INDEX.html extract W H IN_RGBA  OUT_TEXT   (password: $PW)
const fs = require('node:fs');
const vm = require('node:vm');
const [html, mode, w, h, a, b] = process.argv.slice(2);
const elements = {};
const drawing = new Proxy({}, {get: (_, k) => k === 'createLinearGradient' ? () => ({addColorStop() {}}) : () => {}});
global.document = {
  getElementById: id => elements[id] ??= {value: '', files: [], setAttribute() {}, getContext: () => drawing},
  querySelectorAll: () => [],
};
for (const m of fs.readFileSync(html, 'utf8').matchAll(/<script>([\s\S]*?)<\/script>/g)) vm.runInThisContext(m[1]);
const canvas = pixels => ({width: +w, height: +h, getContext: () => ({getImageData: () => ({data: pixels}), putImageData() {}})});
(async () => {
  const password = process.env.PW;
  if (mode === 'embed') {
    const writer = new zip.ZipWriter(new zip.Uint8ArrayWriter());
    await writer.add('message.txt', new zip.TextReader(fs.readFileSync(a, 'utf8')), {password, encryptionStrength: 3, level: 6});
    const pixels = new Uint8ClampedArray(w * h * 4).fill(255);
    embed(canvas(pixels), await writer.close());
    fs.writeFileSync(b, pixels);
  } else {
    const pixels = new Uint8ClampedArray(fs.readFileSync(a));
    fs.writeFileSync(b, await unzip(extract(canvas(pixels)), password));
  }
})().catch(e => { console.error(e); process.exit(1); });
