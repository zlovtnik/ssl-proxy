const { readFileSync } = require('node:fs');
const { resolve } = require('node:path');
const { expect, test } = require('@playwright/test');

const themeRoot = resolve(__dirname, '../../../cyber-stack/base/schema-migrator/configmaps/keycloak-theme/login');
const customCss = readFileSync(resolve(themeRoot, 'resources/css/custom-login.css'), 'utf8');
const parentCss = readFileSync(resolve(__dirname, 'patternfly-form.css'), 'utf8');

// Match the DOM produced by keycloak.v2/login/field.ftl (Keycloak 26.2.5).
// A rejected combined login marks username invalid; password-only flows mark password.
function field(name, error) {
  const label = name === 'username' ? 'Username or email' : 'Password';
  const control = `<span class="pf-v5-c-form-control ${error ? 'pf-m-error' : ''}">
    <input id="${name}" name="${name}" type="${name === 'password' ? 'password' : 'text'}"
      autocomplete="${name === 'password' ? 'current-password' : 'username'}" aria-invalid="${!!error}">
    ${error ? `<span class="pf-v5-c-form-control__utilities">
      <span class="pf-v5-c-form-control__icon pf-m-status">
        <i class="fas fa-exclamation-circle" aria-hidden="true"></i>
      </span>
    </span>` : ''}
  </span>`;
  return `<div class="pf-v5-c-form__group" id="group-${name}">
    <div class="pf-v5-c-form__group-label">
      <label class="pf-v5-c-form__label" for="${name}">${label}</label>
    </div>
    ${name === 'password' ? `<div class="pf-v5-c-input-group">
      <div class="pf-v5-c-input-group__item pf-m-fill">${control}</div>
      <div class="pf-v5-c-input-group__item">
        <button class="pf-v5-c-button pf-m-control" type="button" aria-label="Show password" aria-controls="password">
          <i class="fas fa-eye" aria-hidden="true"></i>
        </button>
      </div>
    </div>
    <div class="pf-v5-c-form__helper-text" aria-live="polite">
      <div class="pf-v5-c-helper-text"><div class="pf-v5-c-helper-text__item">
        <span class="pf-v5-c-helper-text__item-text"><a href="#reset">Forgot Password?</a></span>
      </div></div>
    </div>` : control}
    <div id="input-error-container-${name}">
      ${error ? `<div class="pf-v5-c-form__helper-text" aria-live="polite">
        <div class="pf-v5-c-helper-text"><div class="pf-v5-c-helper-text__item pf-m-error" id="input-error-${name}">
          <span class="pf-v5-c-helper-text__item-text pf-m-error kc-feedback-text">${error}</span>
        </div></div>
      </div>` : ''}
    </div>
  </div>`;
}

async function render(page, invalidField, error = 'Invalid username or password.') {
  await page.setContent(`<!doctype html><html class="login-pf"><head>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>${parentCss}</style><style>${customCss}</style>
  </head><body id="keycloak-bg"><div class="auth-page"><div class="auth-split">
    <aside class="auth-brand">RCLabs Gateway</aside><div class="auth-shell">
      <main class="auth-card" aria-labelledby="kc-page-title">
        <header class="auth-card-header"><p class="auth-eyebrow">RCLabs account</p>
          <h1 id="kc-page-title">Sign in to your account</h1>
          <p class="auth-intro">Continue to your application.</p>
        </header>
        <div class="auth-card-body"><form id="kc-form-login" class="pf-v5-c-form">
          ${field('username', invalidField === 'username' ? error : '')}
          ${field('password', invalidField === 'password' ? error : '')}
          <div class="pf-v5-c-form__group"><div class="pf-v5-c-form__actions">
            <button class="pf-v5-c-button pf-m-primary" type="submit">Sign In</button>
          </div></div>
        </form></div>
      </main><p class="auth-footnote">rafael@rclabs.uk</p>
    </div>
  </div></div></body></html>`);
  // setContent can return while entry animations are still running. Measure
  // the completed layout, including when motion is enabled in the browser.
  await page.locator('.auth-card').evaluate(async (card) => {
    await Promise.all(card.getAnimations({ subtree: true }).map((animation) => animation.finished));
  });
}

async function box(locator) {
  const bounds = await locator.boundingBox();
  expect(bounds).not.toBeNull();
  return bounds;
}

for (const width of [360, 375, 768, 1024, 1440]) {
  for (const invalidField of ['username', 'password']) {
    test(`${invalidField} error stays beside the input at ${width}px`, async ({ page }) => {
      await page.setViewportSize({ width, height: 900 });
      await render(page);
      const input = page.locator(`#${invalidField}`);
      const normal = await box(input.locator('..'));

      await render(page, invalidField);
      await input.fill('long-credential-'.repeat(20));
      await expect(input).toBeFocused();
      await expect(input).toHaveAttribute('aria-invalid', 'true');

      const control = input.locator('..');
      const icon = control.locator('.pf-v5-c-form-control__icon');
      // Read related bounds in one browser frame, not separate protocol calls.
      const [controlBox, inputBox, iconBox, errorBox] = await control.evaluate((element, name) => {
        return [element, element.querySelector('input'),
          element.querySelector('.pf-v5-c-form-control__icon'),
          document.querySelector(`#input-error-${name}`)]
          .map((node) => node.getBoundingClientRect().toJSON());
      }, invalidField);
      // Catch both the extra error row and an icon painted over typed text.
      expect(Math.abs(controlBox.height - normal.height)).toBeLessThanOrEqual(1);
      expect(inputBox.x + inputBox.width).toBeLessThanOrEqual(iconBox.x);
      expect(Math.abs((inputBox.y + inputBox.height / 2) - (iconBox.y + iconBox.height / 2))).toBeLessThanOrEqual(1);
      expect(iconBox.x + iconBox.width).toBeLessThanOrEqual(controlBox.x + controlBox.width);
      expect(errorBox.y).toBeGreaterThanOrEqual(controlBox.y + controlBox.height);
      await expect(control).toHaveCSS('border-top-color', 'rgba(248, 113, 113, 0.65)');
      await expect(icon).toHaveCSS('color', 'rgb(252, 165, 165)');

      // Autofocus after failed login must preserve the error border and a focus ring.
      await expect(control).not.toHaveCSS('box-shadow', 'none');
      await page.getByRole('button', { name: 'Show password' }).focus();
      await expect(control).toHaveCSS('border-top-color', 'rgba(248, 113, 113, 0.65)');
      const passwordBox = await box(page.locator('#password').locator('..'));
      const toggleBox = await box(page.getByRole('button', { name: 'Show password' }));
      expect(passwordBox.x + passwordBox.width).toBeLessThanOrEqual(toggleBox.x);
      expect(Math.abs(passwordBox.height - toggleBox.height)).toBeLessThanOrEqual(1);

      if (invalidField === 'username') {
        const nextLabel = await box(page.getByText('Password', { exact: true }));
        expect(errorBox.y + errorBox.height).toBeLessThanOrEqual(nextLabel.y);
      }
      expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width);
    });
  }

  test(`long error wraps above the password at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await render(page, 'username', 'Invalid username or password. Check your credentials and try signing in again. '.repeat(4));
    const errorBox = await box(page.locator('#input-error-username'));
    const nextLabel = await box(page.getByText('Password', { exact: true }));
    expect(errorBox.height).toBeGreaterThan(36);
    expect(errorBox.y + errorBox.height).toBeLessThanOrEqual(nextLabel.y);
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width);
  });
}
