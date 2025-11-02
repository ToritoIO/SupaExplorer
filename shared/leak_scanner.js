import { DEFAULT_DENY_LIST, DEFAULT_PATTERN_GROUPS } from "./leak_patterns.js";

const DEFAULT_CONTEXT_CHARS = 80;
const BASE64_CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
const BASE64_MIN_THRESHOLD = 20;
const BASE64_MAX_LENGTH = 4096;

const noop = () => {};

function ensureGlobalRegex(pattern) {
  if (pattern instanceof RegExp) {
    const flags = pattern.flags.includes("g") ? pattern.flags : `${pattern.flags}g`;
    return new RegExp(pattern.source, flags);
  }
  return new RegExp(pattern, "g");
}

function flattenPatternGroups(patternGroups) {
  const combined = {};
  Object.values(patternGroups || {}).forEach((group) => {
    if (!group || typeof group !== "object") {
      return;
    }
    Object.entries(group).forEach(([key, pattern]) => {
      if (key && pattern) {
        combined[key] = pattern;
      }
    });
  });
  return combined;
}

function extractContext(text, index, matchLength, radius = DEFAULT_CONTEXT_CHARS) {
  if (!text || typeof text !== "string") {
    return "";
  }
  const start = Math.max(0, index - radius);
  const end = Math.min(text.length, index + matchLength + radius);
  return text.slice(start, end);
}

function getStringsOfSet(word, charSet, threshold = BASE64_MIN_THRESHOLD) {
  if (!word) {
    return [];
  }
  let count = 0;
  let letters = "";
  const strings = [];
  for (const char of word) {
    if (charSet.indexOf(char) > -1) {
      letters += char;
      count += 1;
    } else {
      if (count > threshold) {
        strings.push(letters);
      }
      letters = "";
      count = 0;
    }
  }
  if (count > threshold) {
    strings.push(letters);
  }
  return strings;
}

function getDecodedBase64Strings(inputString) {
  const encodeds = getStringsOfSet(inputString, BASE64_CHARSET);
  const decodeds = [];
  encodeds.forEach((encoded) => {
    if (!encoded || encoded.length > BASE64_MAX_LENGTH) {
      return;
    }
    try {
      const decoded = atob(encoded);
      if (decoded) {
        decodeds.push({ encoded, decoded });
      }
    } catch (error) {
      noop(error);
    }
  });
  return decodeds;
}

export function summarizeLeakMatch(match) {
  if (!match || typeof match !== "string") {
    return "";
  }
  const trimmed = match.trim();
  if (trimmed.length <= 16) {
    return trimmed;
  }
  const prefix = trimmed.slice(0, 8);
  const suffix = trimmed.slice(-6);
  return `${prefix}...${suffix}`;
}

export function createLeakScanner(options = {}) {
  const patternGroups = options.patternGroups || DEFAULT_PATTERN_GROUPS;
  const denyList = Array.isArray(options.denyList) ? options.denyList : DEFAULT_DENY_LIST;
  const denySet = new Set(denyList);
  const compiledPatterns = Object.entries(flattenPatternGroups(patternGroups)).map(([key, pattern]) => ({
    key,
    regex: ensureGlobalRegex(pattern),
  }));

  const includeEncoded = options.includeEncoded !== undefined ? Boolean(options.includeEncoded) : true;
  const contextRadius = Number.isFinite(options.contextRadius) ? options.contextRadius : DEFAULT_CONTEXT_CHARS;

  const scanPlainText = (text, encodedFrom, results, seen) => {
    if (!text || typeof text !== "string") {
      return;
    }
    compiledPatterns.forEach(({ key, regex }) => {
      regex.lastIndex = 0;
      let exec;
      while ((exec = regex.exec(text))) {
        const rawMatch = exec.groups?.token || exec[1] || exec[0];
        if (typeof rawMatch !== "string" || !rawMatch.length) {
          if (!regex.global) {
            break;
          }
          if (exec.index === regex.lastIndex) {
            regex.lastIndex += 1;
          }
          continue;
        }
        if (denySet.has(rawMatch)) {
          continue;
        }
        const dedupeKey = `${key}|${rawMatch}|${encodedFrom || ""}`;
        if (seen.has(dedupeKey)) {
          continue;
        }
        seen.add(dedupeKey);

        const index = typeof exec.index === "number" ? exec.index : text.indexOf(rawMatch);
        const context = extractContext(text, index, rawMatch.length, contextRadius);
        results.push({
          key,
          match: rawMatch,
          context,
          encodedFrom: encodedFrom || null,
          index,
        });

        if (!regex.global) {
          break;
        }
        if (exec.index === regex.lastIndex) {
          regex.lastIndex += 1;
        }
      }
    });
  };

  return {
    scan(source) {
      if (!source || typeof source !== "string") {
        return [];
      }
      const results = [];
      const seen = new Set();

      scanPlainText(source, null, results, seen);

      if (includeEncoded) {
        const decodeds = getDecodedBase64Strings(source);
        decodeds.forEach(({ encoded, decoded }) => {
          scanPlainText(decoded, encoded, results, seen);
        });
      }

      return results;
    },
  };
}

export function combinePatterns(customGroups) {
  return flattenPatternGroups(customGroups || DEFAULT_PATTERN_GROUPS);
}
