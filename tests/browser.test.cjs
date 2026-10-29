const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const { createInterface } = require('node:readline');
const { once } = require('node:events');
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require('playwright');

const root = path.resolve(__dirname, '..');
const artifacts = path.join(root, 'artifacts');
let fixture, browser, urls;
const observations = [];
const payload = '<script>window.__xssProbe="executed"</script>';

before(async () => {
  fs.mkdirSync(artifacts, { recursive: true });
  fixture = spawn(process.env.PYTHON || path.join(root, '.venv/bin/python'), ['tools/browser_fixture.py'], { cwd: root, stdio: ['pipe', 'pipe', 'pipe'] });
  fixture.stderr.resume(); // Drain local access logs; evidence contains no session cookies.
  const lines = createInterface({ input: fixture.stdout });
  urls = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('Local fixture did not become ready')), 20000);
    fixture.once('error', reject);
    fixture.once('exit', code => { if (!urls) reject(new Error(`Fixture exited: ${code}`)); });
    lines.once('line', line => { clearTimeout(timer); lines.close(); resolve(JSON.parse(line)); });
  });
  browser = await chromium.launch({
    executablePath: process.env.CHROMIUM_PATH || (fs.existsSync('/usr/bin/chromium') ? '/usr/bin/chromium' : undefined),
    headless: true, args: ['--no-sandbox', '--disable-dev-shm-usage'],
  });
});

after(async () => {
  await browser?.close();
  if (fixture && fixture.exitCode === null) {
    const closed = once(fixture, 'close');
    fixture.stdin.end();
    await closed;
  }
  fs.writeFileSync(path.join(artifacts, 'browser-observations.json'), JSON.stringify(observations, null, 2) + '\n');
});

async function newPage(t, width = 1440) {
  const context = await browser.newContext({ viewport: { width, height: 1000 } });
  t.after(() => context.close());
  return context.newPage();
}

async function signIn(page, mode, username = 'alice') {
  await page.goto(urls[mode] + '/login');
  await page.getByLabel('Username', { exact: true }).fill(username);
  await page.getByLabel('Password', { exact: true }).fill('LabPassword!2026');
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await page.waitForURL('**/notes');
}

for (const mode of ['vulnerable', 'secure']) {
  test(`${mode}: verify stored-XSS behavior in a real browser`, async t => {
    const page = await newPage(t);
    await signIn(page, mode);
    const otherUserEdit = await page.goto(urls[mode] + '/notes/2/edit');
    assert.equal(otherUserEdit.status(), mode === 'vulnerable' ? 200 : 404);
    if (mode === 'secure') {
      await page.goto(urls.secure + '/notes/new');
      await page.getByLabel('Title', { exact: true }).fill('Local XSS evidence');
    }
    await page.getByLabel('Your note', { exact: true }).fill(payload);
    await page.getByRole('button', { name: 'Save note', exact: true }).click();
    if (mode === 'vulnerable') {
      await page.getByRole('button', { name: 'Sign out', exact: true }).click();
      await signIn(page, mode, 'bob');
      await page.goto(urls.vulnerable + '/notes/2');
    }
    await page.locator('.note-body').waitFor();
    const executed = await page.evaluate(() => window.__xssProbe === 'executed');
    assert.equal(executed, mode === 'vulnerable');
    if (mode === 'secure') assert.equal(await page.locator('.note-body').innerText(), payload);
    observations.push({ check: 'stored-xss', mode, script_executed: executed, cross_user_edit_status: otherUserEdit.status(), viewed_by: mode === 'vulnerable' ? 'bob' : 'alice', planted_by: 'alice', expected_result_verified: true });
  });
}

test('secure: registration, note lifecycle, and logout work in the browser', async t => {
  const page = await newPage(t);
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.goto(urls.secure + '/register');
  await page.getByLabel('Username', { exact: true }).fill('browser_learner');
  await page.getByLabel('Password', { exact: true }).fill('BrowserLabPass!2026');
  await page.getByRole('button', { name: 'Create account', exact: true }).click();
  await page.waitForURL('**/login');
  await page.getByLabel('Username', { exact: true }).fill('browser_learner');
  await page.getByLabel('Password', { exact: true }).fill('BrowserLabPass!2026');
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await page.getByRole('link', { name: '+ New note', exact: true }).click();
  await page.getByLabel('Title', { exact: true }).fill('Browser draft');
  await page.getByLabel('Your note', { exact: true }).fill('An ordinary note.');
  await page.getByRole('button', { name: 'Save note', exact: true }).click();
  await page.getByRole('heading', { name: 'Browser draft', exact: true }).waitFor();
  await page.getByRole('link', { name: 'Edit note', exact: true }).click();
  await page.getByLabel('Your note', { exact: true }).fill('An improved note.');
  await page.getByRole('button', { name: 'Save note', exact: true }).click();
  assert.equal(await page.locator('.note-body').innerText(), 'An improved note.');
  await page.getByRole('button', { name: 'Delete note', exact: true }).click();
  await page.getByRole('heading', { name: 'A fresh page awaits.', exact: true }).waitFor();
  await page.getByRole('button', { name: 'Sign out', exact: true }).click();
  await page.waitForURL('**/login');
  assert.deepEqual(errors, []);
  observations.push({ check: 'secure-browser-lifecycle', passed: true, script_errors: errors.length });
});

test('secure: keyboard access and layouts fit 320, 390, 768, and 1440 pixels', async t => {
  const page = await newPage(t);
  for (const width of [320, 390, 768, 1440]) {
    await page.setViewportSize({ width, height: 1000 });
    await page.goto(urls.secure + '/login');
    await page.keyboard.press('Tab');
    assert.equal(await page.evaluate(() => document.activeElement.textContent), 'Skip to content');
    await page.getByRole('heading', { name: 'Welcome back', exact: true }).click();
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
    if (width === 390 || width === 1440) await page.screenshot({ path: path.join(artifacts, `secure-login-${width}.png`), fullPage: true });
    await signIn(page, 'secure');
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
    if (width === 1440) await page.screenshot({ path: path.join(artifacts, 'secure-notes-desktop.png'), fullPage: true });
    await page.getByRole('link', { name: '+ New note', exact: true }).click();
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
    await page.getByRole('button', { name: 'Sign out', exact: true }).click();
  }
  observations.push({ check: 'responsive-and-keyboard', widths: [320, 390, 768, 1440], passed: true });
});
