export {};

type ConsentRecord = {
  version: 1;
  analytics: boolean;
  savedAt: number;
};

declare global {
  interface Window {
    dataLayer?: IArguments[];
    gtag?: (...args: unknown[]) => void;
    [key: `ga-disable-${string}`]: boolean | undefined;
  }
}

const consentKey = 'rclabs-analytics-consent';
const consentVersion = 1 as const;
const consentLifetimeMs = 180 * 24 * 60 * 60 * 1000;
const analyticsCookieLifetimeSeconds = 60 * 24 * 60 * 60;
const trackedPaths = new Set([
  '/',
  '/products/',
  '/vpn-proxy/',
  '/atheros-search/',
  '/schema-migrator/',
  '/octopus/',
  '/demo/',
  '/accessibility/',
  '/privacy/',
]);
const documentRoot = document.documentElement;
const configuredMeasurementId = documentRoot.dataset.ga4Id;
const consentPanel = document.getElementById('privacy-consent');

if (configuredMeasurementId && consentPanel) {
  const measurementId = configuredMeasurementId;
  const title = document.getElementById('privacy-consent-title');
  const settings = document.getElementById('privacy-consent-settings');
  const settingsButton = consentPanel.querySelector<HTMLButtonElement>(
    '[data-consent="settings"]',
  );
  const analyticsToggle = consentPanel.querySelector<HTMLInputElement>(
    '[data-consent="analytics-toggle"]',
  );
  let acceptedForThisPage = false;

  const readConsent = (): ConsentRecord | null => {
    try {
      const parsed = JSON.parse(
        localStorage.getItem(consentKey) || 'null',
      ) as ConsentRecord | null;
      if (
        !parsed ||
        parsed.version !== consentVersion ||
        typeof parsed.analytics !== 'boolean' ||
        !Number.isFinite(parsed.savedAt) ||
        parsed.savedAt > Date.now() ||
        Date.now() - parsed.savedAt > consentLifetimeMs
      ) {
        localStorage.removeItem(consentKey);
        return null;
      }
      return parsed;
    } catch {
      return null;
    }
  };

  const writeConsent = (analytics: boolean) => {
    const consent: ConsentRecord = {
      version: consentVersion,
      analytics,
      savedAt: Date.now(),
    };
    try {
      localStorage.setItem(consentKey, JSON.stringify(consent));
    } catch {
      // An explicit choice still applies to this page if browser storage is off.
    }
    consentPanel.hidden = true;
    if (analytics) enableAnalytics();
    else disableAnalytics();
  };

  const clearAnalyticsCookies = () => {
    const names = document.cookie
      .split(';')
      .map((entry) => entry.trim().split('=')[0])
      .filter(
        (name) => name === '_ga' || name === '_gid' || name.startsWith('_ga_'),
      );
    const domains = new Set<string | undefined>([
      undefined,
      location.hostname,
      '.rclabs.uk',
    ]);
    for (const name of names) {
      for (const domain of domains) {
        const domainPart = domain ? `; Domain=${domain}` : '';
        document.cookie = `${name}=; Max-Age=0; Path=/${domainPart}; SameSite=Lax; Secure`;
      }
    }
  };

  const disableAnalytics = () => {
    acceptedForThisPage = false;
    window[`ga-disable-${measurementId}`] = true;
    document
      .querySelector<HTMLScriptElement>(
        `script[data-rclabs-ga="${measurementId}"]`,
      )
      ?.remove();
    clearAnalyticsCookies();
  };

  const safeCampaignValue = (value: string | null) => {
    if (!value || value.length > 80 || /[@\s]/.test(value)) return undefined;
    if (/\d{7,}/.test(value)) return undefined;
    return /^[a-zA-Z0-9._-]+$/.test(value) ? value : undefined;
  };

  const pageLocation = () => {
    const url = new URL(location.href);
    const safePath = trackedPaths.has(url.pathname) ? url.pathname : '/other/';
    const safe = new URL(safePath, location.origin);
    for (const key of [
      'utm_source',
      'utm_medium',
      'utm_campaign',
      'utm_content',
      'utm_term',
    ]) {
      const value = safeCampaignValue(url.searchParams.get(key));
      if (value) safe.searchParams.set(key, value);
    }
    return safe.toString();
  };

  const pageReferrer = () => {
    try {
      return document.referrer ? new URL(document.referrer).origin : '';
    } catch {
      return '';
    }
  };

  const send = (eventName: string, parameters: Record<string, string>) => {
    if (!acceptedForThisPage || !window.gtag) return;
    window.gtag('event', eventName, {
      ...parameters,
      page_location: pageLocation(),
      page_referrer: pageReferrer(),
    });
  };

  function enableAnalytics() {
    if (acceptedForThisPage) return;
    acceptedForThisPage = true;
    window[`ga-disable-${measurementId}`] = false;
    window.dataLayer = window.dataLayer || [];
    window.gtag = function () {
      window.dataLayer!.push(arguments);
    };
    window.gtag('js', new Date());
    window.gtag('config', measurementId, {
      send_page_view: false,
      allow_google_signals: false,
      allow_ad_personalization_signals: false,
      cookie_domain: 'rclabs.uk',
      cookie_expires: analyticsCookieLifetimeSeconds,
      cookie_update: false,
      page_location: pageLocation(),
      page_referrer: pageReferrer(),
    });
    const script = document.createElement('script');
    script.async = true;
    script.dataset.rclabsGa = measurementId;
    script.src = `https://www.googletagmanager.com/gtag/js?id=${encodeURIComponent(measurementId)}`;
    document.head.append(script);
    send('page_view', { page_title: document.title });
  }

  const openPanel = (focus = false) => {
    consentPanel.hidden = false;
    if (focus) title?.focus();
  };

  const initialConsent = readConsent();
  if (initialConsent?.analytics) enableAnalytics();
  else if (initialConsent) consentPanel.hidden = true;
  else openPanel();

  consentPanel.addEventListener('click', (event) => {
    const button = (event.target as HTMLElement).closest<HTMLButtonElement>(
      'button[data-consent]',
    );
    if (!button) return;
    switch (button.dataset.consent) {
      case 'accept':
        writeConsent(true);
        break;
      case 'reject':
        writeConsent(false);
        break;
      case 'settings': {
        const isExpanded = button.getAttribute('aria-expanded') === 'true';
        button.setAttribute('aria-expanded', String(!isExpanded));
        if (settings) settings.hidden = isExpanded;
        break;
      }
      case 'save':
        writeConsent(analyticsToggle?.checked === true);
        break;
    }
  });

  document
    .getElementById('privacy-settings-link')
    ?.addEventListener('click', () => {
      if (analyticsToggle)
        analyticsToggle.checked = readConsent()?.analytics ?? false;
      if (settings) settings.hidden = true;
      settingsButton?.setAttribute('aria-expanded', 'false');
      openPanel(true);
    });

  document.addEventListener(
    'click',
    (event) => {
      if (!acceptedForThisPage) return;
      const target = event.target;
      if (!(target instanceof Element)) return;

      const link = target.closest<HTMLAnchorElement>('a[href]');
      const isEmail = link?.protocol === 'mailto:';
      if (
        link &&
        (isEmail ||
          link.classList.contains('button') ||
          link.classList.contains('text-link') ||
          link.hasAttribute('data-preview'))
      ) {
        send(isEmail ? 'mailto_click' : 'cta_click', {
          cta_type: isEmail ? 'email' : 'site_link',
          cta_placement: link.closest('header')
            ? 'header'
            : link.closest('footer')
              ? 'footer'
              : link.closest('section')?.id || 'content',
          destination: isEmail
            ? 'email'
            : new URL(link.href).origin === location.origin
              ? new URL(link.href).pathname
              : 'external',
        });
      }

      const control = target.closest<HTMLElement>(
        '[data-analytics-product][data-analytics-action]',
      );
      if (control) {
        send('sample_interaction', {
          product: control.dataset.analyticsProduct || 'sample',
          action: control.dataset.analyticsAction || 'interaction',
        });
      }
    },
    true,
  );

  document.addEventListener(
    'change',
    (event) => {
      if (!acceptedForThisPage) return;
      const target = event.target;
      if (!(target instanceof HTMLElement)) return;
      const control = target.closest<HTMLElement>(
        '[data-analytics-product][data-analytics-action]',
      );
      if (!control) return;
      send('sample_interaction', {
        product: control.dataset.analyticsProduct || 'sample',
        action: control.dataset.analyticsAction || 'interaction',
      });
    },
    true,
  );
}
