<#import "field.ftl" as field>
<#import "footer.ftl" as loginFooter>
<#macro username>
  <#assign label>
    <#if !realm.loginWithEmailAllowed>${msg("username")}<#elseif !realm.registrationEmailAsUsername>${msg("usernameOrEmail")}<#else>${msg("email")}</#if>
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
            <i class="fa-sync-alt fas" aria-hidden="true"></i>
            <span class="kc-tooltip-text">${msg("restartLoginTooltip")}</span>
        </button>
      </div>
    </div>
  </@field.group>
</#macro>

<#macro registrationLayout bodyClass="" displayInfo=false displayMessage=true displayRequiredFields=false>
<!DOCTYPE html>
<html class="${properties.kcHtmlClass!}" lang="${lang}"<#if realm.internationalizationEnabled> dir="${(locale.rtl)?then('rtl','ltr')}"</#if>>
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
    <title>${msg("loginTitle",(realm.displayName!''))}</title>
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
            <script src="${url.resourcesPath}/${script}" type="text/javascript"></script>
        </#list>
    </#if>
    <#if scripts??>
        <#list scripts as script>
            <script src="${script}" type="text/javascript"></script>
        </#list>
    </#if>
    <script type="module" src="${url.resourcesPath}/js/passwordVisibility.js"></script>
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
  <div class="auth-grid" aria-hidden="true"></div>
  <div class="glow glow-1" aria-hidden="true"></div>
  <div class="glow glow-2" aria-hidden="true"></div>

  <div class="auth-shell">
    <header id="kc-header" class="auth-brand">
      <div class="auth-brand-mark" aria-hidden="true">
        <svg viewBox="0 0 24 24" role="img">
          <path d="M12 3a9 9 0 1 0 9 9" />
          <path d="M12 7a5 5 0 1 0 5 5" />
          <path d="M12 11a1 1 0 1 0 1 1" />
          <path d="m13 11 7-7" />
        </svg>
      </div>
      <div id="kc-header-wrapper" class="auth-brand-copy">
        <span class="auth-brand-name">${kcSanitize(msg("loginTitleHtml",(realm.displayNameHtml!'')))?no_esc}</span>
        <span class="auth-brand-status"><i aria-hidden="true"></i> Identity gateway</span>
      </div>
    </header>

    <main class="auth-card" aria-labelledby="kc-page-title">
      <div class="auth-card-header">
        <div>
          <p class="auth-eyebrow">Protected access</p>
          <h1 id="kc-page-title"><#nested "header"></h1>
        </div>
        <#if realm.internationalizationEnabled && locale.supported?size gt 1>
          <label class="auth-language" for="login-select-toggle">
            <span class="sr-only">${msg("languages")}</span>
            <select aria-label="${msg("languages")}" id="login-select-toggle" onchange="if (this.value) window.location.href=this.value">
              <#list locale.supported?sort_by("label") as l>
                <option value="${l.url}" ${(l.languageTag == locale.currentLanguageTag)?then('selected','')}>${l.label}</option>
              </#list>
            </select>
          </label>
        </#if>
      </div>

      <div class="auth-card-body">
        <#if auth?has_content && auth.showUsername() && !auth.showResetCredentials()>
          <div class="${properties.kcFormClass} auth-attempted-user">
            <#nested "show-username">
            <@username />
          </div>
        <#elseif displayRequiredFields>
          <p class="auth-required"><span aria-hidden="true">*</span> ${msg("requiredFields")}</p>
        </#if>

        <#if displayMessage && message?has_content && (message.type != 'warning' || !isAppInitiatedAction??)>
          <div class="${properties.kcAlertClass!} pf-m-${(message.type = 'error')?then('danger', message.type)}" role="alert" aria-live="polite">
            <div class="${properties.kcAlertIconClass!}" aria-hidden="true">
              <#if message.type = 'success'><span class="${properties.kcFeedbackSuccessIcon!}"></span></#if>
              <#if message.type = 'warning'><span class="${properties.kcFeedbackWarningIcon!}"></span></#if>
              <#if message.type = 'error'><span class="${properties.kcFeedbackErrorIcon!}"></span></#if>
              <#if message.type = 'info'><span class="${properties.kcFeedbackInfoIcon!}"></span></#if>
            </div>
            <span class="${properties.kcAlertTitleClass!} kc-feedback-text">${kcSanitize(message.summary)?no_esc}</span>
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
          <#nested "socialProviders">
          <#if displayInfo>
            <div id="kc-info" class="auth-info ${properties.kcFormClass}">
              <div id="kc-info-wrapper"><#nested "info"></div>
            </div>
          </#if>
          <@loginFooter.content/>
        </div>
      </div>
    </main>

    <p class="auth-footnote"><span aria-hidden="true"></span> Encrypted session · Authorized users only</p>
  </div>
</div>
</body>
</html>
</#macro>
