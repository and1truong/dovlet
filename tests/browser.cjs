// Optional: npm install --no-save --package-lock=false playwright
// Then: npx playwright install chromium && node tests/browser.cjs
const {chromium} = require('playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {pathToFileURL} = require('node:url');
(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dovlet-test-'));
  const browser = await chromium.launch({headless:true, ...(process.env.CHROMIUM_PATH ? {executablePath:process.env.CHROMIUM_PATH} : {}), args:['--no-sandbox','--disable-gpu']});
  try {
    const page = await browser.newPage({acceptDownloads:true});
    const errors = [], requests = [];
    page.on('pageerror', error => errors.push(error.message));
    page.on('request', request => {if (/^https?:/.test(request.url())) requests.push(request.url())});
    await page.context().setOffline(true);
    await page.goto(pathToFileURL(path.join(__dirname, '../index.html')).href);
    const original = 'Xin chào Việt Nam! 🍎\n<script>alert(1)</script>';
    await page.fill('#message', original);
    await page.fill('#password', 'test-only-password-123');
    const nextDownload = page.waitForEvent('download');
    await page.click('#export');
    const png = path.join(dir, 'message.png');
    await (await nextDownload).saveAs(png);
    await page.click('#readTab');
    await page.setInputFiles('#secretImage', png);
    await page.fill('#readPassword', 'wrong-password');
    await page.click('#decode');
    await page.waitForFunction(() => !document.querySelector('#decode').disabled);
    assert.match(await page.locator('#status').innerText(), /Sai password/);
    assert.equal(await page.locator('#decoded').isVisible(), false);
    await page.fill('#readPassword', 'test-only-password-123');
    await page.click('#decode');
    await page.waitForFunction(() => !document.querySelector('#decode').disabled);
    assert.equal(await page.inputValue('#output'), original);
    await page.click('#createTab');
    await page.setInputFiles('#cover', png);
    await page.fill('#message', 'Custom cover test');
    const customDownload = page.waitForEvent('download');
    await page.click('#export');
    await customDownload; // Export includes an actual PNG decode + authenticated roundtrip.
    await page.setViewportSize({width:390, height:844});
    assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
    assert.deepEqual(errors, []);
    assert.deepEqual(requests, []);
    console.log('PASS: offline browser export/import, password rejection, optional image, mobile width, zero network requests');
  } finally {await browser.close(); fs.rmSync(dir, {recursive:true, force:true})}
})().catch(error => {console.error(error); process.exitCode = 1});
