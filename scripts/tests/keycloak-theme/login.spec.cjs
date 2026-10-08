const { readFileSync } = require('node:fs');
const { resolve } = require('node:path');
const { expect, test } = require('@playwright/test');

const themeRoot = resolve(__dirname, '../../../cyber-stack/base/schema-migrator/configmaps/keycloak-theme/login');
const customCss = readFileSync(resolve(themeRoot, 'resources/css/custom-login.css'), 'utf8');
const parentCss = readFileSync(resolve(__dirname, 'patternfly-form.css'), 'utf8');
const template = readFileSync(resolve(themeRoot, 'template.ftl'), 'utf8');
const brand = template.match(/<aside class="auth-brand"[\s\S]*?<\/aside>/)[0];
const mobileBrand = template.match(/<div class="auth-mobile-brand"[\s\S]*?<\/div>/)[0];
const securityMark = template.match(/<div class="auth-security-mark"[\s\S]*?<\/div>/)[0];

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

async function render(page, invalidField, error = 'Invalid username or password.', options = {}) {
  await page.setContent(`<!doctype html><html class="login-pf" lang="en"><head>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="color-scheme" content="dark">
    <style>${parentCss}</style><style>${customCss}</style>
  </head><body id="keycloak-bg"><div class="auth-page">
    <div class="auth-grid" aria-hidden="true"></div>
    <div class="glow glow-1" aria-hidden="true"></div>
    <div class="glow glow-2" aria-hidden="true"></div>
    <div class="glow glow-3" aria-hidden="true"></div>
    <div class="auth-split">${brand}<div class="auth-shell">
      <main class="auth-card" aria-labelledby="kc-page-title">
        <header class="auth-card-header">${mobileBrand}${securityMark}<p class="auth-eyebrow">RCLabs account</p>
          <h1 id="kc-page-title">Sign in to your account</h1>
          <p class="auth-intro">Continue to your application.</p>
          ${options.extended ? `<label class="auth-language" for="login-select-toggle">
            <span class="sr-only">Languages</span>
            <select id="login-select-toggle" aria-label="Languages"><option>English</option></select>
          </label>` : ''}
        </header>
        <div class="auth-card-body">
          ${options.extended ? `<div class="auth-sso"><div id="kc-social-providers">
            <a href="#identity-provider">Continue with SSO</a>
          </div></div><div class="auth-divider" aria-hidden="true"><span>or</span></div>` : ''}
          ${options.alert ? `<div class="pf-v5-c-alert pf-m-${options.alert}" role="alert" aria-live="polite">
            <span class="pf-v5-c-alert__icon" aria-hidden="true">!</span>
            <span class="pf-v5-c-alert__title kc-feedback-text">${options.alert}: ${error}</span>
          </div>` : ''}
          <form id="kc-form-login" class="pf-v5-c-form">
          ${field('username', invalidField === 'username' ? error : '')}
          ${field('password', invalidField === 'password' ? error : '')}
          ${options.extended ? `<div id="kc-form-options"><div class="pf-v5-c-check">
            <input class="pf-v5-c-check__input" id="rememberMe" type="checkbox">
            <label class="pf-v5-c-check__label" for="rememberMe">Remember me</label>
          </div></div>` : ''}
          <div class="pf-v5-c-form__group"><div class="pf-v5-c-form__actions">
            <button class="pf-v5-c-button pf-m-primary" type="submit">Sign In</button>
          </div></div>
        </form>${options.extended ? `<a id="try-another-way" href="#another-way" class="pf-v5-c-button pf-m-secondary">Try Another Way</a>
          <div class="auth-info" id="kc-registration">New user? <a href="#register">Register</a></div>` : ''}</div>
      </main><p class="auth-footnote"><a href="mailto:rafael@rclabs.uk">rafael@rclabs.uk</a></p>
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

for (const width of [320, 360, 375, 768, 1024, 1440]) {
  for (const colorScheme of ['light', 'dark']) {
    test(`normal login stays dark under ${colorScheme} preference at ${width}px`, async ({ page }, testInfo) => {
      await page.emulateMedia({ colorScheme });
      await page.setViewportSize({ width, height: 900 });
      await render(page);
      await expect(page.locator('html')).toHaveCSS('color-scheme', 'dark');
      await expect(page.locator('body')).toHaveCSS('background-color', 'rgb(9, 9, 9)');
      await expect(page.locator('.auth-card')).toHaveCSS('background-color', 'rgb(20, 20, 20)');
      await expect(page.locator('#username').locator('..')).toHaveCSS('background-color', 'rgb(28, 28, 28)');
      await expect(page.getByRole('button', { name: 'Sign In' })).toHaveCSS('background-color', 'rgb(163, 230, 163)');
      await expect(page.getByRole('button', { name: 'Sign In' })).toHaveCSS('color', 'rgb(9, 9, 9)');
      expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width);
      if (colorScheme === 'light' && [375, 1440].includes(width)) {
        await page.screenshot({ path: testInfo.outputPath(`login-normal-${width}.png`), fullPage: true });
      }
    });
  }

  for (const invalidField of ['username', 'password']) {
    test(`${invalidField} error stays beside the input at ${width}px`, async ({ page }, testInfo) => {
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
      await expect(control).toHaveCSS('border-top-color', 'rgb(252, 165, 165)');
      await expect(icon).toHaveCSS('color', 'rgb(252, 165, 165)');

      // Autofocus after failed login must preserve the error border and a focus ring.
      await expect(control).not.toHaveCSS('box-shadow', 'none');
      await page.getByRole('button', { name: 'Show password' }).focus();
      await expect(control).toHaveCSS('border-top-color', 'rgb(252, 165, 165)');
      const passwordBox = await box(page.locator('#password').locator('..'));
      const toggleBox = await box(page.getByRole('button', { name: 'Show password' }));
      expect(passwordBox.x + passwordBox.width).toBeLessThanOrEqual(toggleBox.x);
      expect(Math.abs(passwordBox.height - toggleBox.height)).toBeLessThanOrEqual(1);

      if (invalidField === 'username') {
        const nextLabel = await box(page.getByText('Password', { exact: true }));
        expect(errorBox.y + errorBox.height).toBeLessThanOrEqual(nextLabel.y);
      }
      expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width);
      if (invalidField === 'username' && [375, 1440].includes(width)) {
        await page.screenshot({ path: testInfo.outputPath(`login-error-${width}.png`), fullPage: true });
      }
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

function contrast(foreground, background) {
  const luminance = (color) => {
    const channels = color.match(/[\d.]+/g).slice(0, 3).map(Number).map((value) => {
      const channel = value / 255;
      return channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4;
    });
    return channels[0] * 0.2126 + channels[1] * 0.7152 + channels[2] * 0.0722;
  };
  const values = [luminance(foreground), luminance(background)].sort((a, b) => b - a);
  return (values[0] + 0.05) / (values[1] + 0.05);
}

async function colors(locator) {
  return locator.evaluate((element) => {
    const style = getComputedStyle(element);
    let parent = element;
    let background;
    while (parent) {
      background = getComputedStyle(parent).backgroundColor;
      if (background !== 'rgba(0, 0, 0, 0)' && background !== 'transparent') break;
      parent = parent.parentElement;
    }
    return { foreground: style.color, background, border: style.borderTopColor, outline: style.outlineColor };
  });
}

for (const width of [320, 768, 1440]) {
  test(`text, controls and semantic alerts meet contrast targets at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await render(page, 'username', undefined, { extended: true });
    const text = page.locator(`.auth-brand-name, .auth-brand-eyebrow, .auth-brand-title, .auth-brand-lede,
      .auth-trust-label, .auth-trust-sub, .auth-brand-foot, .auth-eyebrow, #kc-page-title, .auth-intro,
      .pf-v5-c-form__label, input:not([type=checkbox]), .kc-feedback-text, a, button, select,
      .pf-v5-c-check__label, .auth-divider span, #kc-registration`);
    for (const element of await text.all()) {
      if (!await element.isVisible()) continue;
      const { foreground, background } = await colors(element);
      expect(contrast(foreground, background), await element.textContent()).toBeGreaterThanOrEqual(7);
    }
    for (const element of await page.locator('.pf-v5-c-form-control, .pf-m-control, .pf-m-secondary, select, #kc-social-providers a').all()) {
      const { background, border } = await colors(element);
      expect(contrast(border, background)).toBeGreaterThanOrEqual(3);
      expect(contrast(border, 'rgb(20, 20, 20)')).toBeGreaterThanOrEqual(3);
    }
    const alertColors = new Set();
    for (const alert of ['danger', 'warning', 'info', 'success']) {
      await render(page, undefined, 'Check your account to continue.', { alert });
      const { foreground, background, border } = await colors(page.getByRole('alert'));
      expect(contrast(foreground, background)).toBeGreaterThanOrEqual(7);
      expect(contrast(border, background)).toBeGreaterThanOrEqual(3);
      alertColors.add(foreground);
    }
    expect(alertColors.size).toBe(4);
  });

  for (const invalidField of [undefined, 'username']) {
    test(`${invalidField || 'normal'} login keeps targets and reflows with text spacing at ${width}px`, async ({ page }) => {
      await page.setViewportSize({ width, height: 900 });
      await render(page, invalidField, undefined, { extended: true });
      await page.addStyleTag({ content: `* { line-height: 1.5 !important; letter-spacing: 0.12em !important; word-spacing: 0.16em !important; }
        p { margin-bottom: 2em !important; }` });
      const controls = page.locator('a, button, select, label[for=rememberMe], .pf-v5-c-form-control');
      for (const control of await controls.all()) {
        const bounds = await box(control);
        expect(bounds.width).toBeGreaterThanOrEqual(44);
        expect(bounds.height).toBeGreaterThanOrEqual(44);
        expect(bounds.x).toBeGreaterThanOrEqual(0);
        expect(bounds.x + bounds.width).toBeLessThanOrEqual(width);
        expect(await control.evaluate((element) => element.scrollWidth <= element.clientWidth + 1)).toBe(true);
      }
      expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width);
      const username = await box(page.locator('#username').locator('..'));
      const password = await box(page.locator('#password').locator('..'));
      expect(username.y + username.height).toBeLessThan(password.y);
    });
  }
}

test('keyboard follows the form, shows focus and operates the remember control', async ({ page }) => {
  await render(page, 'username', undefined, { extended: true });
  const order = [
    page.getByRole('combobox', { name: 'Languages' }),
    page.getByRole('link', { name: 'Continue with SSO' }),
    page.getByRole('textbox', { name: 'Username or email' }),
    page.getByLabel('Password', { exact: true }),
    page.getByRole('button', { name: 'Show password' }),
    page.getByRole('link', { name: 'Forgot Password?' }),
    page.getByRole('checkbox', { name: 'Remember me' }),
    page.getByRole('button', { name: 'Sign In' }),
    page.getByRole('link', { name: 'Try Another Way' }),
    page.getByRole('link', { name: 'Register', exact: true }),
    page.getByRole('link', { name: 'rafael@rclabs.uk' }),
  ];
  for (const target of order) {
    await page.keyboard.press('Tab');
    await expect(target).toBeFocused();
    if (await target.evaluate((element) => element.matches('.pf-v5-c-form-control input'))) {
      await expect(target.locator('..')).toHaveCSS('box-shadow', 'rgb(20, 20, 20) 0px 0px 0px 2px, rgb(163, 230, 163) 0px 0px 0px 5px');
    } else {
      await expect(target).toHaveCSS('outline-width', '3px');
      const { outline } = await colors(target);
      expect(contrast(outline, 'rgb(20, 20, 20)')).toBeGreaterThanOrEqual(3);
    }
  }
  await page.getByRole('checkbox', { name: 'Remember me' }).focus();
  await page.keyboard.press('Space');
  await expect(page.getByRole('checkbox', { name: 'Remember me' })).toBeChecked();
  await page.getByText('Remember me', { exact: true }).click();
  await expect(page.getByRole('checkbox', { name: 'Remember me' })).not.toBeChecked();
});

test('reduced motion disables entry animations and transitions', async ({ page }) => {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await render(page, 'username', undefined, { alert: 'danger' });
  expect(await page.evaluate(() => document.getAnimations().length)).toBe(0);
  for (const target of await page.locator('input, button, a, .pf-v5-c-form-control').all()) {
    await expect(target).toHaveCSS('transition-duration', '0s');
  }
});

test('forced colors keeps control boundaries and focus visible', async ({ page }) => {
  await page.emulateMedia({ forcedColors: 'active' });
  await render(page, 'username', undefined, { extended: true, alert: 'danger' });
  await expect(page.locator('.auth-grid')).toBeHidden();
  await expect(page.locator('.glow-1')).toBeHidden();
  for (const target of await page.locator('input:not([type=checkbox]), button, select').all()) {
    await target.focus();
    await expect(target).toHaveCSS('outline-style', 'solid');
    await expect(target).toHaveCSS('outline-width', '3px');
  }
  for (const target of await page.locator('.pf-v5-c-form-control, button, select').all()) {
    await expect(target).toHaveCSS('border-top-style', 'solid');
    await expect(target).toHaveCSS('border-top-width', '1px');
  }
  await expect(page.getByRole('alert')).toBeVisible();
});
