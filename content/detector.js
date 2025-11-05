(() => {
  const TERMS_STORAGE_KEY = "sbde_terms_acceptance";
  const TERMS_VERSION = "1.0";
  let initialized = false;

  if (!chrome?.storage?.local) {
    return;
  }

  const isTermsAccepted = (record) => Boolean(record && record.version === TERMS_VERSION);

  const start = () => {
    if (initialized) {
      return;
    }
    initialized = true;
    try {
      if (window.__sbdeDetectorInjected) {
        return;
      }
      window.__sbdeDetectorInjected = true;
    } catch (error) {
      // Ignore flag errors and continue.
    }

    const inject = () => {
      const script = document.createElement("script");
      script.src = chrome.runtime.getURL("content/detector_inject.js");
      script.type = "text/javascript";
      script.async = false;
      script.onload = () => {
        try {
          script.remove();
        } catch (error) {
          // Ignore removal errors.
        }
      };
      (document.documentElement || document.head || document.body)?.prepend(script);
    };

    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", inject, { once: true });
    } else {
      inject();
    }
  };

  chrome.storage.local.get([TERMS_STORAGE_KEY], (result) => {
    if (isTermsAccepted(result?.[TERMS_STORAGE_KEY])) {
      start();
    }
  });

  chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== "local" || !changes[TERMS_STORAGE_KEY]) {
      return;
    }
    if (isTermsAccepted(changes[TERMS_STORAGE_KEY].newValue)) {
      start();
    }
  });
})();
