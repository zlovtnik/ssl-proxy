import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

test('employers can review positioning, attributed experience and engineering evidence without JavaScript', async ({
  browser,
}) => {
  const context = await browser.newContext({ javaScriptEnabled: false });
  try {
    const page = await context.newPage();
    await page.goto('http://127.0.0.1:4323/');
    const sectionOrder = await page
      .locator('main > section')
      .evaluateAll((sections) =>
        sections
          .slice(0, 6)
          .map((section) =>
            section.classList.contains('playground-section')
              ? 'playground'
              : section.id,
          ),
      );
    expect(sectionOrder).toEqual([
      'top',
      'experience',
      'selected-work',
      'technical-evidence',
      'products',
      'playground',
    ]);

    const experience = page.locator('#experience');
    await expect(experience).toContainText('Synchro');
    await expect(experience).toContainText(/20 million|~20M/);
    await expect(experience).toContainText(/weekly|per week/);
    await expect(experience).not.toContainText(/2 million|~2M/);
    await expect(experience).toContainText(/historical|employer/i);

    const studies = page.locator('#selected-work .about-case-study');
    await expect(studies).toHaveCount(4);
    const fields = [
      'What I built',
      'Hardest failure mode',
      'How I addressed it',
      'Regression coverage',
      'Still unverified',
    ];
    for (const id of ['octopus', 'search', 'migrator', 'vpn']) {
      const study = page.locator(`#case-${id}`);
      if ((await study.getAttribute('open')) === null && id !== 'octopus')
        await study.locator('summary').click();
      await expect(study).toHaveAttribute('open', '');
      await expect(study).toContainText(/independent/i);
      await expect(study.locator('dt')).toHaveText(fields);
      for (const definition of await study.locator('dd').all())
        expect((await definition.innerText()).trim().length).toBeGreaterThan(
          30,
        );
      const sourceLinks = study.locator('a[href^="https://github.com/"]');
      expect(await sourceLinks.count()).toBeGreaterThan(0);
      const repositories: Record<string, string> = {
        octopus: 'octopus',
        search: 'integration-console',
        migrator: 'schema-migrator',
        vpn: 'ssl-proxy',
      };
      for (const link of await sourceLinks.all()) {
        // Each submodule has its own GitHub repository. A parent-repository
        // URL cannot open a source file below a gitlink.
        const destination = new URL((await link.getAttribute('href'))!);
        expect(destination.pathname).toMatch(
          new RegExp(`^/zlovtnik/${repositories[id]}/blob/main/`),
        );
      }
    }

    const octopus = page.locator('#case-octopus');
    for (const mechanism of [
      /persist|PostgreSQL/i,
      /replay/i,
      /dedup/i,
      /lease|fenc/i,
    ])
      await expect(octopus).toContainText(mechanism);
    await expect(page.locator('#technical-evidence')).toContainText(
      /synthetic/i,
    );
    await expect(page.locator('#technical-evidence')).toContainText(
      /benchmark/i,
    );
    await expect(page.locator('#top a[href="/resume/"]')).toBeVisible();
    await expect(page.locator('#top a[href^="mailto:"]')).toBeVisible();
  } finally {
    await context.close();
  }
});

test('full-time hiring has a direct contact path distinct from project inquiries', async ({
  page,
}) => {
  await page.goto('/');
  const navigation = page.getByRole('navigation', {
    name: 'Main navigation',
    exact: true,
  });
  await expect(
    navigation.getByRole('link', { name: /resume/i }),
  ).toHaveAttribute('href', '/resume/');
  await navigation
    .getByRole('link', { name: 'Contact for full-time roles', exact: true })
    .click();
  await expect(page).toHaveURL(/\/demo\/#employment$/);
  const employment = page.locator('#employment');
  const request = new URL(
    (await employment
      .locator('a[href^="mailto:"]')
      .first()
      .getAttribute('href'))!,
  );
  expect(request.pathname).toBe('rafael@rclabs.uk');
  expect(request.searchParams.get('subject')).toBe(
    'Full-time engineering role',
  );
  expect(request.searchParams.get('body')).toMatch(/role|position/i);

  for (const id of ['search', 'migrator', 'vpn', 'octopus', 'all']) {
    const href = await page.locator(`#${id} a`).getAttribute('href');
    expect(new URL(href!).searchParams.get('subject')).toMatch(
      /^Use-case discussion: /,
    );
  }
});

test('the public resume is readable without an account or JavaScript', async ({
  browser,
}) => {
  const context = await browser.newContext({ javaScriptEnabled: false });
  try {
    const page = await context.newPage();
    const response = await page.goto('http://127.0.0.1:4323/resume/');
    expect(response?.status()).toBe(200);
    await expect(page.getByRole('heading', { level: 1 })).toContainText(
      'Rafael Cardoso dos Santos',
    );
    const main = page.locator('main');
    await expect(main).toContainText(/professional experience/i);
    await expect(main).toContainText('Synchro');
    await expect(main).toContainText(/Senior Staff Software Engineer/);
    await expect(main).toContainText(
      'Staff Platform and Distributed Systems Engineer',
    );
    await expect(main).toContainText('No sponsorship required');
    await expect(main).toContainText('Open to Remote / Hybrid');
    await expect(main).toContainText('20 million fiscal transactions per week');
    await expect(main).toContainText('1-2 GB XML documents');
    await expect(main).toContainText(/2011/);
    await expect(main).toContainText(/independent projects/i);
    await expect(main).toContainText('Octopus');
    await expect(main.locator('a[href^="mailto:"]').first()).toHaveAttribute(
      'href',
      /^mailto:racasantos@icloud\.com/,
    );
    await expect(main.locator('a[href^="tel:"]')).toHaveAttribute(
      'href',
      'tel:+12078046704',
    );
    await expect(main.locator('a[href*="docs.google.com"]')).toHaveCount(0);
  } finally {
    await context.close();
  }
});

test('printing the resume hides navigation, print controls and production consent chrome', async ({
  page,
}) => {
  await page.goto('/resume/');
  // Local builds omit analytics markup. Reproduce the visible production banner
  // so print behavior is checked even when no measurement ID is configured.
  await page.evaluate(() => {
    const banner = document.createElement('section');
    banner.className = 'privacy-consent';
    banner.textContent = 'Your privacy choices';
    document.body.append(banner);
  });
  await expect(page.locator('.privacy-consent')).toBeVisible();
  await expect(page.locator('#print-resume')).toBeVisible();
  await page.emulateMedia({ media: 'print' });
  await expect(page.locator('.privacy-consent')).toBeHidden();
  await expect(page.locator('#print-resume')).toBeHidden();
  await expect(page.locator('.site-top')).toBeHidden();
  await expect(page.locator('.site-footer')).toBeHidden();
  await expect(page.locator('body')).toHaveCSS(
    'background-color',
    'rgb(255, 255, 255)',
  );
  await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
  await expect(page.locator('#resume-experience')).toBeVisible();
});

test('portfolio disclosures and the resume reflow at mobile, tablet and desktop widths', async ({
  page,
}) => {
  for (const route of ['/', '/resume/']) {
    await page.goto(route);
    await page.locator('#selected-work details').evaluateAll((details) =>
      details.forEach((detail) => {
        (detail as HTMLDetailsElement).open = true;
      }),
    );
    for (const width of [375, 768, 1024, 1440]) {
      await page.setViewportSize({ width, height: 1000 });
      expect(
        await page.evaluate(
          () => document.documentElement.scrollWidth <= innerWidth,
        ),
        `${route} at ${width}px`,
      ).toBe(true);
    }
  }
});

test('resume landmarks and controls have no automated accessibility violations', async ({
  page,
}) => {
  await page.goto('/resume/');
  expect(
    (
      await new AxeBuilder({ page })
        .withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa'])
        .analyze()
    ).violations,
  ).toEqual([]);
});
