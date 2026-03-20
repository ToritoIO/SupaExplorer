;(function () {
  var TERMS_STORAGE_KEY = "sbde_terms_acceptance";
  var TERMS_VERSION = "1.0";
  var initialized = false;

  if (!chrome?.storage?.local) {
    return;
  }

  function isTermsAccepted(record) {
    return Boolean(record && record.version === TERMS_VERSION);
  }

  function start() {
    if (initialized) {
      if (window.__sbdeOverlayBridge) {
        window.__sbdeOverlayBridge.open();
      }
      return;
    }
    initialized = true;

    if (window.__sbdeOverlayBridge) {
      window.__sbdeOverlayBridge.open();
      return;
    }

    var OVERLAY_ID = "sbde-explorer-overlay";
  var REFRESH_EVENT = "SBDE_REFRESH_TABLE";
  var overlayFrame = null;

  function postRefresh() {
    if (overlayFrame && overlayFrame.contentWindow) {
      overlayFrame.contentWindow.postMessage({ type: REFRESH_EVENT }, "*");
      return true;
    }
    var frame = document.querySelector("#" + OVERLAY_ID + " iframe");
    if (frame && frame.contentWindow) {
      overlayFrame = frame;
      overlayFrame.contentWindow.postMessage({ type: REFRESH_EVENT }, "*");
      return true;
    }
    return false;
  }

  function createOverlay() {
    if (postRefresh()) {
      return;
    }

    var overlay = document.getElementById(OVERLAY_ID);
    if (!overlay) {
      overlay = document.createElement("div");
      overlay.id = OVERLAY_ID;
      overlay.style.position = "fixed";
      overlay.style.inset = "0";
      overlay.style.zIndex = "2147483646";
      overlay.style.display = "flex";
      overlay.style.alignItems = "center";
      overlay.style.justifyContent = "center";
      overlay.style.pointerEvents = "none";

      var backdrop = document.createElement("div");
      backdrop.className = "sbde-overlay-backdrop";
      backdrop.style.position = "absolute";
      backdrop.style.inset = "0";
      backdrop.style.background = "rgba(0, 0, 0, 0.5)";
      backdrop.style.backdropFilter = "blur(4px)";
      backdrop.style.webkitBackdropFilter = "blur(4px)";
      backdrop.style.pointerEvents = "auto";

      var frameWrapper = document.createElement("div");
      frameWrapper.style.position = "relative";
      frameWrapper.style.width = "90vw";
      frameWrapper.style.height = "90vh";
      frameWrapper.style.maxWidth = "1280px";
      frameWrapper.style.maxHeight = "900px";
      frameWrapper.style.borderRadius = "12px";
      frameWrapper.style.overflow = "hidden";
      frameWrapper.style.boxShadow = "0 16px 40px rgba(0, 0, 0, 0.5)";
      frameWrapper.style.border = "1px solid rgba(255, 255, 255, 0.06)";
      frameWrapper.style.pointerEvents = "auto";

      overlayFrame = document.createElement("iframe");
      overlayFrame.src = chrome.runtime.getURL("explorer/explorer.html");
      overlayFrame.style.border = "none";
      overlayFrame.style.width = "100%";
      overlayFrame.style.height = "100%";
      overlayFrame.style.background = "#09090b";

      frameWrapper.appendChild(overlayFrame);
      overlay.appendChild(backdrop);
      overlay.appendChild(frameWrapper);
      document.documentElement.appendChild(overlay);

      var closeOnBackdrop = function () {
        removeOverlay();
      };
      backdrop.addEventListener("click", closeOnBackdrop);

      var onKeyDown = function (event) {
        if (event.key === "Escape") {
          removeOverlay();
        }
      };
      document.addEventListener("keydown", onKeyDown, { once: true });
    } else if (!postRefresh()) {
      overlayFrame = overlay.querySelector("iframe");
      postRefresh();
    }
  }

  function removeOverlay() {
    var overlay = document.getElementById(OVERLAY_ID);
    if (overlay && overlay.parentNode) {
      overlay.parentNode.removeChild(overlay);
    }
    overlayFrame = null;
  }

  function openOverlay() {
    createOverlay();
  }

  chrome.runtime.onMessage.addListener(function (message) {
    if (message && message.type === "SBDE_OPEN_OVERLAY") {
      openOverlay();
    }
    if (message && message.type === "SBDE_CLOSE_OVERLAY") {
      removeOverlay();
    }
  });

  window.addEventListener("message", function (event) {
    if (!event?.data || typeof event.data.type !== "string") {
      return;
    }
    if (event.data.type === "SBDE_CLOSE_OVERLAY") {
      removeOverlay();
    }
    if (event.data.type === "SBDE_OPEN_OVERLAY") {
      openOverlay();
    }
  });

  window.__sbdeOverlayBridge = {
    open: openOverlay,
    close: removeOverlay,
    refresh: postRefresh,
  };
  }

  chrome.storage.local.get([TERMS_STORAGE_KEY], function (result) {
    if (isTermsAccepted(result && result[TERMS_STORAGE_KEY])) {
      start();
    }
  });

  chrome.storage.onChanged.addListener(function (changes, area) {
    if (area !== "local" || !changes[TERMS_STORAGE_KEY]) {
      return;
    }
    if (isTermsAccepted(changes[TERMS_STORAGE_KEY].newValue)) {
      start();
    }
  });
})();
