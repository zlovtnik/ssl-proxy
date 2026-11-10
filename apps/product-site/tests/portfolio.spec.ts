import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { guides, guidePath } from '../src/data/products';

test('the homepage summaries and guide destinations work without JavaScript', async ({
  browser,
}) => {
  const context = await browser.newContext({ javaScriptEnabled: false });
  try {
    const page = await context.newPage();
    await page.goto('http://127.0.0.1:4323/');
    const sectionOrder = await page
      .locator('main > section')
      .evaluateAll((sections) => sections.map((section) => section.id));
    expect(sectionOrder).toEqual([
      'top',
      'experience',
      'selected-work',
      'technical-evidence',
      'delivery',
      'guides',
      'faq',
      'contact',
    ]);

    const experience = page.locator('#experience');
    await expect(experience).toContainText('Synchro');
    await expect(experience).toContainText(/historical|employer/i);
    await expect(experience).toContainText(
      '20 million fiscal transactions per week',
    );
    await expect(
      experience.getByRole('link', { name: 'Read about my work' }),
    ).toHaveAttribute('href', '/about/#experience');

    const projects = [
      ['octopus', '/octopus/', /delivery may repeat/i],
      [
        'search',
        '/atheros-search/',
        /does not confirm a current connection or device identity/i,
      ],
      ['migrator', '/schema-migrator/', /do not back up database data/i],
      ['vpn', '/vpn-proxy/', /traffic outside the configured path/i],
    ] as const;
    for (const [id, destination, caveat] of projects) {
      const card = page.locator(`#selected-work #case-${id}`);
      await expect(card).toBeVisible();
      await expect(card).toContainText(caveat);
      await expect(card.locator(`a[href="${destination}"]`)).toBeVisible();
    }
    await expect(page.locator('#selected-work details')).toHaveCount(0);
    await expect(
      page.locator('#technical-evidence a[href^="https://github.com/"]'),
    ).toBeVisible();
    await expect(page.locator('#top a[href="/resume/"]')).toBeVisible();
    await expect(
      page.locator('#contact a[href^="mailto:"]').first(),
    ).toBeVisible();
    for (const guide of guides) {
      const link = page.locator(`#guides a[href="${guidePath(guide.slug)}"]`);
      await expect(link).toBeVisible();
      await link.click();
      await expect(page.getByRole('heading', { level: 1 })).toHaveText(
        guide.title,
      );
      await page.goBack();
    }
  } finally {
    await context.close();
  }
});

test('the about page retains attributed experience and full engineering evidence without JavaScript', async ({
  browser,
}) => {
  const context = await browser.newContext({ javaScriptEnabled: false });
  try {
    const page = await context.newPage();
    await page.goto('http://127.0.0.1:4323/about/');
    const experience = page.locator('#experience');
    await expect(experience).toContainText('Synchro');
    await expect(experience).toContainText(/20 million|~20M/);
    await expect(experience).toContainText(/weekly|per week/);
    await expect(experience).not.toContainText(/2 million|~2M/);
    await expect(experience).toContainText(/historical|employer/i);
    const roles = [
      ['Senior Staff Software Engineer', 'May 2022 - September 2024'],
      ['Senior Software Engineer', 'September 2018 - May 2022'],
      ['Software Analyst', 'February 2011 - September 2018'],
    ];
    for (const [title, period] of roles) {
      await expect(
        experience.getByRole('region', { name: title, exact: true }),
      ).toContainText(period);
    }
    await expect(
      experience.getByRole('region', {
        name: 'Senior Staff Software Engineer',
      }),
    ).toContainText(/2024 customer project.*electronic invoice recognition/);

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
      await expect(study.locator('.about-case-detail > dl dt')).toHaveText(
        fields,
      );
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
  } finally {
    await context.close();
  }
});

test('general contact has a direct email path distinct from project inquiries', async ({
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
  await navigation.getByRole('link', { name: 'Contact', exact: true }).click();
  await expect(page).toHaveURL(/\/contact\/$/);
  const employment = page.locator('#employment');
  const request = new URL(
    (await employment
      .getByRole('link', { name: 'Contact', exact: true })
      .getAttribute('href'))!,
  );
  expect(request.pathname).toBe('rafael@rclabs.uk');
  expect(request.searchParams.get('subject')).toBe('General inquiry');
  expect(request.searchParams.get('body')).toBe(
    'Hello Rafael,\n\nI would like to get in touch about:\n\nThank you.',
  );

  await page.goto('/contact/');
  for (const id of ['search', 'migrator', 'vpn', 'octopus', 'all']) {
    const href = await page.locator(`#${id} a`).getAttribute('href');
    expect(new URL(href!).searchParams.get('subject')).toMatch(
      /^Engineering discussion: /,
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
      'Rafael Cardoso',
    );
    const main = page.locator('main');
    await expect(main).toContainText(/professional experience/i);
    await expect(main).toContainText('Synchro');
    await expect(main).toContainText(/Senior Staff Software Engineer/);
    await expect(main.locator('header .lead')).toHaveText(
      'Senior Software Engineer | Backend Systems & Enterprise Integration',
    );
    await expect(
      main.getByRole('link', { name: 'rclabs.uk', exact: true }),
    ).toHaveAttribute('href', 'https://rclabs.uk/');
    await expect(main).toContainText('No sponsorship required');
    await expect(main).toContainText('Open to Remote / Hybrid');
    await expect(main).toContainText('20 million fiscal transactions per week');
    await expect(main).toContainText('1-2 GB XML documents');
    await expect(main).toContainText(/2011/);
    await expect(main).toContainText(/independent projects/i);
    await expect(main).toContainText('Octopus');
    await expect(main.locator('a[href^="mailto:"]').first()).toHaveAttribute(
      'href',
      /^mailto:rafael@rclabs\.uk/,
    );
    await expect(main.locator('a[href^="tel:"]')).toHaveCount(0);
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
