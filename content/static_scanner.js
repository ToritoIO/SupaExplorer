// Static scanner for detecting hardcoded Supabase credentials in page source and external JS files
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

    if (window.__sbdeStaticScannerInjected) {
      return;
    }
    window.__sbdeStaticScannerInjected = true;

    const SUPABASE_URL_PATTERN = /https?:\/\/([a-z0-9-]+)\.supabase\.co/gi;
  const JWT_TOKEN_PATTERN = /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g;
  const ANON_KEY_PATTERN = /"(eyJ[A-Za-z0-9_-]+\.eyJ[^"]+?role["']?\s*:\s*["']?anon[^"]+)"/g;
  const SERVICE_ROLE_KEY_PATTERN = /"(eyJ[A-Za-z0-9_-]+\.eyJ[^"]+?role["']?\s*:\s*["']?service_role[^"]+)"/g;
  
  const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB limit
  const SCAN_TIMEOUT = 5000; // 5 second timeout per file
  const scannedUrls = new Set();

  // Check if a JWT is a Supabase key by decoding the payload
  const isSupabaseJWT = (token) => {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) return false;
      
      let payload = parts[1].replace(/-/g, '+').replace(/_/g, '/');
      const pad = payload.length % 4;
      if (pad) payload += '='.repeat(4 - pad);
      
      const decoded = JSON.parse(atob(payload));
      
      // Check for Supabase-specific JWT fields
      return decoded.iss?.includes('supabase') || 
             decoded.ref || 
             decoded.role === 'anon' || 
             decoded.role === 'service_role';
    } catch (e) {
      return false;
    }
  };

  // Extract project ID from Supabase URL
  const extractProjectId = (url) => {
    const match = url.match(/https?:\/\/([a-z0-9-]+)\.supabase\.co/i);
    return match ? match[1] : null;
  };

  // Extract project ref from JWT
  const extractProjectRef = (jwt) => {
    try {
      const parts = jwt.split('.');
      if (parts.length !== 3) return null;
      
      let payload = parts[1].replace(/-/g, '+').replace(/_/g, '/');
      const pad = payload.length % 4;
      if (pad) payload += '='.repeat(4 - pad);
      
      const decoded = JSON.parse(atob(payload));
      return decoded.ref || null;
    } catch (e) {
      return null;
    }
  };

  // Determine key type from JWT
  const getKeyType = (jwt) => {
    try {
      const parts = jwt.split('.');
      if (parts.length !== 3) return 'unknown';
      
      let payload = parts[1].replace(/-/g, '+').replace(/_/g, '/');
      const pad = payload.length % 4;
      if (pad) payload += '='.repeat(4 - pad);
      
      const decoded = JSON.parse(atob(payload));
      
      if (decoded.role === 'anon') return 'anon';
      if (decoded.role === 'service_role') return 'service_role';
      return decoded.role || 'unknown';
    } catch (e) {
      return 'unknown';
    }
  };

  // Create snippet from match
  const createSnippet = (match) => {
    if (!match || match.length <= 20) return match;
    return `${match.slice(0, 12)}...${match.slice(-8)}`;
  };

  // Report detection to background script
  const reportDetection = (detection) => {
    try {
      chrome.runtime.sendMessage({
        type: 'SBDE_REGISTER_ASSET_DETECTION',
        payload: detection
      });
      
      // Also send as a Supabase request for immediate connection
      if (detection.supabaseUrl && detection.apiKey) {
        chrome.runtime.sendMessage({
          type: 'SBDE_SUPABASE_REQUEST',
          url: detection.supabaseUrl,
          apiKey: detection.apiKey,
          schema: 'public'
        });
      }
    } catch (error) {
      console.debug('[SBDE] Failed to report detection:', error);
    }
  };

  // Scan text content for Supabase credentials
  const scanText = (text, sourceUrl) => {
    if (!text || typeof text !== 'string' || text.length === 0) {
      return;
    }

    const findings = {
      urls: [],
      keys: []
    };

    // Find Supabase URLs
    let urlMatch;
    SUPABASE_URL_PATTERN.lastIndex = 0;
    while ((urlMatch = SUPABASE_URL_PATTERN.exec(text)) !== null) {
      findings.urls.push(urlMatch[0]);
    }

    // Find JWT tokens
    let jwtMatch;
    JWT_TOKEN_PATTERN.lastIndex = 0;
    while ((jwtMatch = JWT_TOKEN_PATTERN.exec(text)) !== null) {
      const token = jwtMatch[0];
      if (isSupabaseJWT(token)) {
        findings.keys.push(token);
      }
    }

    // If we found both URLs and keys in proximity, report them
    if (findings.urls.length > 0 && findings.keys.length > 0) {
      findings.urls.forEach(url => {
        findings.keys.forEach(key => {
          const projectId = extractProjectId(url);
          const keyProjectRef = extractProjectRef(key);
          
          // Only match if project IDs align or we can't determine
          if (projectId && keyProjectRef && projectId !== keyProjectRef) {
            return;
          }

          const detection = {
            projectId: projectId || keyProjectRef || 'unknown',
            supabaseUrl: url,
            assetUrl: sourceUrl || window.location.href,
            keyType: getKeyType(key),
            keyLabel: `${getKeyType(key)} key`,
            apiKeySnippet: createSnippet(key),
            apiKey: key, // Include full key for connection
            detectedAt: new Date().toISOString()
          };

          console.debug(`[SBDE] Detected ${getKeyType(key)} in ${sourceUrl}`);
          reportDetection(detection);
        });
      });
    }
  };

  // Check if URL is same-origin
  const isSameOrigin = (url) => {
    try {
      const urlObj = new URL(url, window.location.href);
      const currentOrigin = new URL(window.location.href);
      
      // Check if protocol, hostname, and port match
      return urlObj.protocol === currentOrigin.protocol &&
             urlObj.hostname === currentOrigin.hostname &&
             urlObj.port === currentOrigin.port;
    } catch (error) {
      return false;
    }
  };

  // Fetch and scan external JavaScript file (same-origin only)
  const scanExternalScript = async (scriptUrl) => {
    if (scannedUrls.has(scriptUrl)) {
      return;
    }
    scannedUrls.add(scriptUrl);

    // Only scan same-origin scripts
    if (!isSameOrigin(scriptUrl)) {
      return;
    }

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), SCAN_TIMEOUT);

      const response = await fetch(scriptUrl, {
        signal: controller.signal,
        credentials: 'same-origin'
      });
      clearTimeout(timeoutId);

      if (!response.ok) {
        return;
      }

      const contentLength = response.headers.get('content-length');
      if (contentLength && parseInt(contentLength) > MAX_FILE_SIZE) {
        console.debug(`[SBDE] Skipping large file: ${scriptUrl}`);
        return;
      }

      const text = await response.text();
      scanText(text, scriptUrl);
    } catch (error) {
      // Silently fail for CORS errors, timeouts, etc.
      if (error.name !== 'AbortError') {
        console.debug(`[SBDE] Failed to scan ${scriptUrl}:`, error.message);
      }
    }
  };

  // Scan inline scripts
  const scanInlineScripts = () => {
    const scripts = document.querySelectorAll('script:not([src])');
    scripts.forEach(script => {
      if (script.textContent) {
        scanText(script.textContent, window.location.href);
      }
    });
  };

  // Scan external scripts
  const scanExternalScripts = () => {
    const scripts = document.querySelectorAll('script[src]');
    
    scripts.forEach(script => {
      const src = script.src;
      if (!src) return;

      // Skip browser extension scripts and data URIs
      if (src.startsWith('chrome-extension://') || 
          src.startsWith('moz-extension://') || 
          src.startsWith('data:')) {
        return;
      }

      // Convert relative URLs to absolute
      try {
        const absoluteUrl = new URL(src, window.location.href).href;
        scanExternalScript(absoluteUrl);
      } catch (error) {
        // Invalid URL, skip
      }
    });
  };

  // Also scan the main HTML document
  const scanDocument = () => {
    const htmlContent = document.documentElement.outerHTML;
    scanText(htmlContent, window.location.href);
  };

  // Run scans
  const runScans = () => {
    try {
      scanInlineScripts();
      scanExternalScripts();
      // scanDocument(); // This might be redundant with inline scripts
    } catch (error) {
      console.error('[SBDE] Static scan error:', error);
    }
  };

  // Start scanning after page load
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', runScans, { once: true });
  } else {
    // Page already loaded, scan immediately
    runScans();
  }

  // Also observe for dynamically added scripts
  const observer = new MutationObserver((mutations) => {
    mutations.forEach((mutation) => {
      mutation.addedNodes.forEach((node) => {
        if (node.nodeName === 'SCRIPT') {
          if (node.src) {
            const src = node.src;
            if (!src.startsWith('chrome-extension://') && 
                !src.startsWith('moz-extension://') && 
                !src.startsWith('data:')) {
              try {
                const absoluteUrl = new URL(src, window.location.href).href;
                scanExternalScript(absoluteUrl);
              } catch (error) {
                // Invalid URL
              }
            }
          } else if (node.textContent) {
            scanText(node.textContent, window.location.href);
          }
        }
      });
    });
  });

  observer.observe(document.documentElement, {
    childList: true,
    subtree: true
  });
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
