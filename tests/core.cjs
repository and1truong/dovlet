// Exercises the shipped single-file app, including its embedded ZIP dependency.
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const html = fs.readFileSync(path.join(__dirname, '../index.html'), 'utf8');
const elements = {};
const drawing = new Proxy({}, {get: (_, key) => key === 'createLinearGradient' ? () => ({addColorStop(){}}) : () => {}});
global.document = {
  getElementById: id => elements[id] ??= {value:'', files:[], setAttribute(){}, getContext:() => drawing},
  querySelectorAll: () => []
};
for (const match of html.matchAll(/<script>([\s\S]*?)<\/script>/g)) vm.runInThisContext(match[1]);
function canvas(width = 1200, height = 1200) {
  const pixels = new Uint8ClampedArray(width * height * 4).fill(255);
  return {width, height, pixels, getContext: () => ({getImageData: () => ({data:pixels}), putImageData(){}})};
}
(async () => {
  const password = 'test-only-password-123';
  const original = 'Xin chào Việt Nam! 🍎\n<script>alert(1)</script>\n' + 'hello'.repeat(10000);
  const writer = new zip.ZipWriter(new zip.Uint8ArrayWriter());
  await writer.add('message.txt', new zip.TextReader(original), {password, encryptionStrength:3, level:6});
  const archive = await writer.close();
  const image = canvas();
  embed(image, archive);
  const recovered = extract(image);
  assert.deepEqual(recovered, archive);
  assert.equal(await unzip(recovered, password), original);
  assert(image.pixels.every((value, index) => index % 4 !== 3 || value === 255), 'Alpha must remain opaque');
  await assert.rejects(() => unzip(recovered, 'wrong-password'));
  const tampered = recovered.slice();
  tampered[100] ^= 1;
  await assert.rejects(() => unzip(tampered, password));
  assert.throws(() => extract(canvas()));
  assert.throws(() => embed(canvas(1, 1), archive));
  // A forged length cannot cause an allocation outside the image capacity.
  for (let bit = 64; bit < 96; bit++) image.pixels[Math.floor(bit / 3) * 4 + bit % 3] |= 1;
  assert.throws(() => extract(image));
  // Changing inputs during decryption must never publish stale plaintext.
  document.createElement = () => ({getContext: () => ({drawImage(){}})});
  await vm.runInThisContext(`(async () => {
    const oldLoad=load, oldExtract=extract, oldUnzip=unzip;
    try {
      load=async () => ({naturalWidth:1,naturalHeight:1});
      extract=() => new Uint8Array();
      let release;
      unzip=() => new Promise(resolve => {release=resolve});
      $("secretImage").files=[{}]; $("readPassword").value="original-password";
      const pending=$("decode").onclick();
      await Promise.resolve();
      $("readPassword").value="changed-password";
      $("readPassword").oninput();
      release("stale plaintext");
      await pending;
      if ($("output").value || !$("decoded").hidden) throw Error("Stale decode exposed");
    } finally {load=oldLoad;extract=oldExtract;unzip=oldUnzip}
  })()`);
  console.log('PASS: Unicode, compression, AES ZIP, LSB, alpha preservation, wrong password, tampering, missing header, capacity, forged length');
})().catch(error => {console.error(error); process.exitCode = 1});
