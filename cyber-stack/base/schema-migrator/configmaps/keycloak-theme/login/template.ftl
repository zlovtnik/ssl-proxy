<#import "field.ftl" as field>
<#import "footer.ftl" as loginFooter>
<#macro username>
<#assign label>
<#if !realm.loginWithEmailAllowed>
  ${msg("username")}
<#elseif !realm.registrationEmailAsUsername>
  ${msg("usernameOrEmail")}
<#else>
  ${msg("email")}
</#if>
</#assign>
<@field.group name="username" label=label>
<div class="${properties.kcInputGroup}">
  <div class="${properties.kcInputGroupItemClass} ${properties.kcFill}">
    <span class="${properties.kcInputClass} ${properties.kcFormReadOnlyClass}">
      <input id="kc-attempted-username" value="${auth.attemptedUsername}" readonly>
    </span>
  </div>
  <div class="${properties.kcInputGroupItemClass}">
    <button id="reset-login" class="${properties.kcFormPasswordVisibilityButtonClass} kc-login-tooltip" type="button"
              aria-label="${msg('restartLoginTooltip')}" onclick="location.href='${url.loginRestartFlowUrl}'">
      <i class="fa-sync-alt fas" aria-hidden="true">
      </i>
      <span class="kc-tooltip-text">
        ${msg("restartLoginTooltip")}
      </span>
    </button>
  </div>
</div>
</@field.group>
</#macro>
<#macro registrationLayout bodyClass="" displayInfo=false displayMessage=true displayRequiredFields=false>
<!DOCTYPE html>
<html class="${properties.kcHtmlClass!}" lang="${lang}"<#if realm.internationalizationEnabled>
  dir="${(locale.rtl)?then('rtl','ltr')}"
</#if>
>
<head>
  <meta charset="utf-8">
  <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
  <meta name="robots" content="noindex, nofollow">
  <meta name="color-scheme" content="dark">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <#if properties.meta?has_content>
    <#list properties.meta?split(' ') as meta>
      <meta name="${meta?split('==')[0]}" content="${meta?split('==')[1]}"/>
    </#list>
  </#if>
  <title>
    ${msg("loginTitle",(realm.displayName!''))}
  </title>
  <link rel="icon" href="${url.resourcesPath}/img/favicon.ico" />
  <#if properties.stylesCommon?has_content>
    <#list properties.stylesCommon?split(' ') as style>
      <link href="${url.resourcesCommonPath}/${style}" rel="stylesheet" />
    </#list>
  </#if>
  <#if properties.styles?has_content>
    <#list properties.styles?split(' ') as style>
      <link href="${url.resourcesPath}/${style}" rel="stylesheet" />
    </#list>
  </#if>
  <script type="importmap">
    {
    "imports": {
    "rfc4648": "${url.resourcesCommonPath}/vendor/rfc4648/rfc4648.js"
    }
    }
  </script>
  <#if properties.scripts?has_content>
    <#list properties.scripts?split(' ') as script>
      <script src="${url.resourcesPath}/${script}" type="text/javascript">
      </script>
    </#list>
  </#if>
  <#if scripts??>
    <#list scripts as script>
      <script src="${script}" type="text/javascript">
      </script>
    </#list>
  </#if>
  <script type="module" src="${url.resourcesPath}/js/passwordVisibility.js">
  </script>
  <script type="module">
    import { startSessionPolling } from "${url.resourcesPath}/js/authChecker.js";
    startSessionPolling("${url.ssoLoginInOtherTabsUrl?no_esc}");
  </script>
  <script type="module">
    document.addEventListener("click", (event) => {
    const link = event.target.closest("a[data-once-link]");
    if (!link) return;
    if (link.getAttribute("aria-disabled") === "true") {
    event.preventDefault();
    return;
    }
    const { disabledClass } = link.dataset;
    if (disabledClass) link.classList.add(...disabledClass.trim().split(/\s+/));
    link.setAttribute("role", "link");
    link.setAttribute("aria-disabled", "true");
    });
  </script>
  <#if authenticationSession??>
    <script type="module">
      import { checkAuthSession } from "${url.resourcesPath}/js/authChecker.js";
      checkAuthSession("${authenticationSession.authSessionIdHash}");
    </script>
  </#if>
</head>
<body id="keycloak-bg" class="${bodyClass!}" data-page-id="login-${pageId}">
  <div class="auth-page">
    <div class="auth-grid" aria-hidden="true">
    </div>
    <div class="glow glow-1" aria-hidden="true">
    </div>
    <div class="glow glow-2" aria-hidden="true">
    </div>
    <div class="glow glow-3" aria-hidden="true">
    </div>
    <div class="auth-split">
      <aside class="auth-brand" aria-label="RCLabs applications">
        <div class="auth-brand-top">
          <span class="auth-brand-logo" aria-hidden="true">
            <svg viewBox="0 0 24 24">
              <path d="M12 2.5 4.5 5.6v6.1c0 4.6 3.1 8.4 7.5 9.8 4.4-1.4 7.5-5.2 7.5-9.8V5.6L12 2.5Z" />
              <path d="M12 7.2c-1.8.3-3.2 1.8-3.4 3.7l-.1 1.1h2.1l.1-.9c.2-1 1-1.7 2-1.9-.4.6-.5 1.3-.3 2l.4 1.3 1.1 2.5.4 2.4" />
            </svg>
          </span>
          <span class="auth-brand-name">
            RCLabs Gateway
          </span>
        </div>
        <div class="auth-brand-main">
          <p class="auth-brand-eyebrow">
            Operations
          </p>
          <p class="auth-brand-title">
            RCLabs applications
          </p>
          <p class="auth-brand-lede">
            Use your RCLabs account to continue to the application you opened.
          </p>
          <ul class="auth-trust">
            <li>
              <span class="auth-trust-icon" aria-hidden="true">
                <svg viewBox="0 0 24 24">
                  <path d="M12 2.5 4.5 5.6v6.1c0 4.6 3.1 8.4 7.5 9.8 4.4-1.4 7.5-5.2 7.5-9.8V5.6L12 2.5Z" />
                  <path d="m9.2 11.8 1.8 1.8 3.9-4" />
                </svg>
              </span>
              <span class="auth-trust-text">
                <span class="auth-trust-label">
                  Wireless audits
                </span>
                <span class="auth-trust-sub">
                  Captured wireless activity
                </span>
              </span>
            </li>
            <li>
              <span class="auth-trust-icon" aria-hidden="true">
                <svg viewBox="0 0 24 24">
                  <rect x="5.5" y="10" width="13" height="9.5" rx="2" />
                  <path d="M8.5 10V7.8a3.5 3.5 0 0 1 7 0V10" />
                </svg>
              </span>
              <span class="auth-trust-text">
                <span class="auth-trust-label">
                  Device search
                </span>
                <span class="auth-trust-sub">
                  Devices and audit records
                </span>
              </span>
            </li>
            <li>
              <span class="auth-trust-icon" aria-hidden="true">
                <svg viewBox="0 0 24 24">
                  <circle cx="12" cy="12" r="8.5" />
                  <path d="M3.5 12h17M12 3.5c2.3 2.4 3.4 5.3 3.4 8.5s-1.1 6.1-3.4 8.5c-2.3-2.4-3.4-5.3-3.4-8.5s1.1-6.1 3.4-8.5Z" />
                </svg>
              </span>
              <span class="auth-trust-text">
                <span class="auth-trust-label">
                  Ingestion monitoring
                </span>
                <span class="auth-trust-sub">
                  Processing jobs and service health
                </span>
              </span>
            </li>
            <li>
              <span class="auth-trust-icon" aria-hidden="true">
                <svg viewBox="0 0 24 24">
                  <path d="M13 2.5 4.5 13.5H11l-1 8 8.5-11H12l1-8Z" />
                </svg>
              </span>
              <span class="auth-trust-text">
                <span class="auth-trust-label">
                  Schema migrations
                </span>
                <span class="auth-trust-sub">
                  Database schema changes
                </span>
              </span>
            </li>
          </ul>
        </div>
        <p class="auth-brand-foot">
          <svg viewBox="0 0 24 24" aria-hidden="true">
            <circle cx="12" cy="12" r="9" />
            <path d="m8.5 12.2 2.4 2.4 4.6-5" />
          </svg>
          <span>
            For authorized users.
          </span>
        </p>
      </aside>
      <div class="auth-shell">
        <main class="auth-card" aria-labelledby="kc-page-title">
          <header id="kc-header" class="auth-card-header">
            <div class="auth-mobile-brand" aria-hidden="true">
              <span class="auth-brand-logo auth-brand-logo-sm">
                <svg viewBox="0 0 24 24">
                  <path d="M12 2.5 4.5 5.6v6.1c0 4.6 3.1 8.4 7.5 9.8 4.4-1.4 7.5-5.2 7.5-9.8V5.6L12 2.5Z" />
                  <path d="M12 7.2c-1.8.3-3.2 1.8-3.4 3.7l-.1 1.1h2.1l.1-.9c.2-1 1-1.7 2-1.9-.4.6-.5 1.3-.3 2l.4 1.3 1.1 2.5.4 2.4" />
                </svg>
              </span>
              <span class="auth-brand-name">
                RCLabs Gateway
              </span>
            </div>
            <div class="auth-security-mark" aria-hidden="true">
              <svg viewBox="0 0 24 24" role="img">
                <path d="M12 3 5.5 5.8v5.5c0 4.2 2.7 7.9 6.5 9.2 3.8-1.3 6.5-5 6.5-9.2V5.8L12 3Z" />
                <path d="m9.2 11.8 1.8 1.8 3.9-4" />
              </svg>
            </div>
            <div id="kc-header-wrapper">
              <p class="auth-eyebrow">
                RCLabs account
              </p>
              <h1 id="kc-page-title">
                <#nested "header">
              </h1>
              <p class="auth-intro">
                Continue to your application.
              </p>
            </div>
            <#if realm.internationalizationEnabled && locale.supported?size gt 1>
              <label class="auth-language" for="login-select-toggle">
                <span class="sr-only">
                  ${msg("languages")}
                </span>
                <select aria-label="${msg("languages")}" id="login-select-toggle" onchange="if (this.value) window.location.href=this.value">
                  <#list locale.supported?sort_by("label") as l>
                    <option value="${l.url}" <#if l.languageTag == locale.currentLanguageTag>
                      selected
                    </#if>
                    >${l.label}
                  </option>
                </#list>
              </select>
            </label>
          </#if>
        </header>
        <div class="auth-card-body">
          <#if social?? && social.providers?? && social.providers?has_content>
            <div class="auth-sso">
              <#nested "socialProviders">
            </div>
            <div class="auth-divider" aria-hidden="true">
              <span>
                or
              </span>
            </div>
          </#if>
          <#if auth?has_content && auth.showUsername() && !auth.showResetCredentials()>
            <div class="${properties.kcFormClass} auth-attempted-user">
              <#nested "show-username">
              <@username />
            </div>
          <#elseif displayRequiredFields>
            <p class="auth-required">
              <span aria-hidden="true">
                *
              </span>
              ${msg("requiredFields")}
            </p>
          </#if>
          <#if displayMessage && message?has_content && (message.type != 'warning' || !isAppInitiatedAction??)>
            <div class="${properties.kcAlertClass!} pf-m-${(message.type = 'error')?then('danger', message.type)}" role="alert" aria-live="polite">
              <div class="${properties.kcAlertIconClass!}" aria-hidden="true">
                <#if message.type = 'success'>
                  <span class="${properties.kcFeedbackSuccessIcon!}">
                  </span>
                </#if>
                <#if message.type = 'warning'>
                  <span class="${properties.kcFeedbackWarningIcon!}">
                  </span>
                </#if>
                <#if message.type = 'error'>
                  <span class="${properties.kcFeedbackErrorIcon!}">
                  </span>
                </#if>
                <#if message.type = 'info'>
                  <span class="${properties.kcFeedbackInfoIcon!}">
                  </span>
                </#if>
              </div>
              <span class="${properties.kcAlertTitleClass!} kc-feedback-text">
                ${kcSanitize(message.summary)?no_esc}
              </span>
            </div>
          </#if>
          <#nested "form">
          <#if auth?has_content && auth.showTryAnotherWayLink()>
            <form id="kc-select-try-another-way-form" action="${url.loginAction}" method="post" novalidate="novalidate">
              <input type="hidden" name="tryAnotherWay" value="on"/>
              <a id="try-another-way" href="javascript:document.forms['kc-select-try-another-way-form'].requestSubmit()"
               class="${properties.kcButtonSecondaryClass} ${properties.kcButtonBlockClass} ${properties.kcMarginTopClass}">
                ${kcSanitize(msg("doTryAnotherWay"))?no_esc}
              </a>
            </form>
          </#if>
          <div class="auth-card-footer">
            <#if displayInfo>
              <div id="kc-info" class="auth-info ${properties.kcFormClass}">
                <div id="kc-info-wrapper">
                  <#nested "info">
                </div>
              </div>
            </#if>
            <@loginFooter.content/>
          </div>
        </div>
      </main>
      <p class="auth-footnote">
        <svg viewBox="0 0 20 20" aria-hidden="true">
          <path d="M6.8 8V6.2a3.2 3.2 0 0 1 6.4 0V8m-7.4 0h8.4v7.2H5.8V8Z" />
        </svg>
        <a href="mailto:rafael@rclabs.uk">
          rafael@rclabs.uk
        </a>
      </p>
    </div>
  </div>
</div>
</body>
</html>
</#macro>
