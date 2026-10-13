"use strict";

// How a search box entry is interpreted:
//
//   report          the name contains "report"
//   logs/report     the path below the searched folder contains "logs/report"
//   /var/log/rep    the whole remote path contains "/var/log/rep"
//   *.log           the name is anything ending in ".log"
//   logs/*.log      the path below the searched folder matches that pattern
//
// A query is a wildcard pattern when it contains "*" or "?", and a pattern has to
// match the whole value rather than part of it, so "*.log" does not match
// "app.log.1". "*" spans "/" so a pattern need not describe every level of a tree.
// A pattern for a path below the searched folder may begin at any folder boundary,
// which is what makes "alice/*.txt" find "home/alice/notes.txt"; one written from
// the root is matched from the root. Matching is always case-insensitive.

// The pattern is walked against the value rather than compiled to a regular
// expression. Turning "*" into ".*" reads well and is a trap: "*a*a*a*a" against a
// name that does not match makes a backtracking engine try every way of dividing
// the name between the stars, and the cost of that grows with a power of the number
// of stars. Search runs in the main process, so the one window that would pay for a
// pattern like that is every window.
//
// This walk cannot behave that way. On a mismatch it goes back to the last "*" and
// gives it exactly one more character — never less than it had before — so the
// value is scanned forwards once per "*" and no more.
function globMatch(pattern, value) {
  let patternIndex = 0;
  let valueIndex = 0;
  let star = -1;
  let resume = 0;
  while (valueIndex < value.length) {
    const character = patternIndex < pattern.length ? pattern[patternIndex] : null;
    // "*" is asked about before the plain comparison, or a "*" in the name would
    // satisfy a "*" in the pattern as an ordinary character and swallow it.
    if (character === "*") {
      star = patternIndex;
      patternIndex += 1;
      resume = valueIndex;
    } else if (character === "?" || (character !== null && character === value[valueIndex])) {
      patternIndex += 1;
      valueIndex += 1;
    } else if (star >= 0) {
      // The last "*" swallows one more character than it did last time.
      resume += 1;
      valueIndex = resume;
      patternIndex = star + 1;
    } else {
      return false;
    }
  }
  // Trailing stars have nothing left to match, which is allowed; anything else is
  // pattern the value ran out before satisfying.
  while (pattern[patternIndex] === "*") patternIndex += 1;
  return patternIndex === pattern.length;
}

// A pattern written for a path below the searched folder may begin at any folder
// boundary, which is what makes "alice/*.txt" find "home/alice/notes.txt".
//
// Asking the question once per boundary is the obvious way and the wrong one: each
// ask rescans the rest of the path, so the cost climbs with the square of the depth
// and a deep tree can hold up the main process for every window. "*" already spans
// "/", so "anything ending in a slash, then the pattern" is just the pattern with
// "*/" in front of it -- and the walk tries every place that slash could be in one
// pass, because that is what its one step back does.
function matchesAtAnyBoundary(pattern, value) {
  return globMatch(pattern, value) || globMatch(`*/${pattern}`, value);
}

function buildMatcher(query) {
  const text = String(query ?? "");
  const absolute = text.startsWith("/");
  const relative = !absolute && text.includes("/");
  const wildcard = /[*?]/.test(text);
  const needle = text.toLocaleLowerCase();
  const scope = absolute ? "full path" : relative ? "relative path" : "name";

  return {
    absolute,
    relative,
    wildcard,
    scope,
    test(name, relativePath, fullPath) {
      const value = String(absolute ? fullPath : relative ? relativePath : name).toLocaleLowerCase();
      if (!wildcard) return value.includes(needle);
      return relative ? matchesAtAnyBoundary(needle, value) : globMatch(needle, value);
    },
  };
}

module.exports = { buildMatcher };
