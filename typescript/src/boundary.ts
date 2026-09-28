/**
 * The lexical boundary policy, stated once. Mirror of src/aletheia/boundary.py.
 *
 * `\b` is not a security boundary. It means "a transition between `\w` and
 * `\W`", and the two runtimes disagree about what `\w` is: Python's is
 * Unicode-aware for str patterns, JavaScript's is ASCII-only. Security
 * semantics were therefore resting on a regex dialect default (issue #3).
 *
 * The policy, stated explicitly rather than inherited from a default:
 *
 *     Match a security keyword unless it is embedded inside a larger ASCII
 *     identifier. Unicode letters adjacent to it do not suppress a detection.
 *
 * So `criticalé` matches; `hypercritical` and `critical_path` do not.
 *
 * Where this policy does not apply: identifiers whose canonical grammar is
 * itself Unicode-aware — usernames, internationalized hostnames,
 * registry-specific package names — must be parsed with the target grammar and
 * compared as canonical fields, not matched with keyword regexes.
 */

/** The alphabet of an ASCII identifier. Deliberately not `\w`. */
export const ASCII_IDENTIFIER_CHAR = "[A-Za-z0-9_]";

/** Left edge — not preceded by an ASCII identifier character. */
export const LEFT = `(?<!${ASCII_IDENTIFIER_CHAR})`;

/** Right edge — not followed by an ASCII identifier character. */
export const RIGHT = `(?!${ASCII_IDENTIFIER_CHAR})`;

/** Wrap a pattern in the boundary policy on both sides. */
export function bounded(pattern: string): string {
  return `${LEFT}(?:${pattern})${RIGHT}`;
}

/*
 * Case-insensitivity, stated as policy rather than inherited from a flag.
 * Mirror of the block in boundary.py — read that one for the full reasoning.
 *
 * Under the `i` flag the boundary class folds too: `iu` lets U+017F (ſ) and
 * U+212A (Kelvin sign) satisfy [A-Za-z0-9_], so `criticalK` read as one longer
 * identifier and was suppressed. No phrasing of the class survives a global
 * `i` — the engine cannot tell K from k at all — and Node 20 has no scoped
 * `(?i:...)`. So the pattern is rewritten instead, and compiled without `i`:
 *
 *     A keyword matches in either ASCII case, and also where Unicode case
 *     folding maps a letter onto one of its ASCII letters (ſ for s, K for k,
 *     ı and İ for i). The boundary class is never folded.
 *
 * The fold set is Python's (all four), not ECMAScript's (two): the port gains
 * ı/İ inside keywords so that both runtimes state one policy.
 */
export const CASE_FOLD_EXTRAS: Readonly<Record<string, string>> = {
  i: 'İı', // İ ı
  k: 'K',       // K Kelvin sign
  s: 'ſ',       // ſ long s
};

/** Rewrite `pattern` so its ASCII letters match case-insensitively. */
export function caseless(pattern: string): string {
  const out: string[] = [];
  let i = 0;
  while (i < pattern.length) {
    const ch = pattern[i];
    if (ch === '\\') {
      const end = escapeEnd(pattern, i);
      out.push(pattern.slice(i, end));
      i = end;
    } else if (ch === '[') {
      const end = classEnd(pattern, i);
      out.push(foldClass(pattern.slice(i, end)));
      i = end;
    } else if (ch === '{') {
      const end = pattern.indexOf('}', i) + 1;
      out.push(pattern.slice(i, end));
      i = end;
    } else if (pattern.startsWith('(?', i)) {
      const prefix = groupPrefix(pattern, i);
      out.push(prefix);
      i += prefix.length;
    } else if (/^[A-Za-z]$/.test(ch)) {
      const low = ch.toLowerCase();
      out.push(`[${low}${low.toUpperCase()}${CASE_FOLD_EXTRAS[low] ?? ''}]`);
      i += 1;
    } else {
      out.push(ch);
      i += 1;
    }
  }
  return out.join('');
}

/**
 * Index just past the escape opening at `start`. Hex digits and property or
 * character names are copied whole — rewriting `\x4B` to `\x4[bB]` would
 * silently change the pattern. Named backreferences are refused. Mirrors
 * `_escape_end` in boundary.py.
 */
function escapeEnd(pattern: string, start: number): number {
  const kind = pattern[start + 1];
  if (kind === 'x') return start + 4;
  if (kind === 'u') {
    return pattern.startsWith('{', start + 2) ? pattern.indexOf('}', start) + 1 : start + 6;
  }
  if (kind === 'U') return start + 10;
  if ((kind === 'N' || kind === 'p' || kind === 'P') && pattern.startsWith('{', start + 2)) {
    return pattern.indexOf('}', start) + 1;
  }
  if (kind === 'c') return start + 3;
  if (kind === 'k') throw new Error(`named backreference at ${start} in ${JSON.stringify(pattern)}`);
  return start + 2;
}

function classEnd(pattern: string, start: number): number {
  let i = start + 1;
  if (pattern[i] === '^') i += 1;
  if (pattern[i] === ']') i += 1; // a leading `]` is a literal
  while (i < pattern.length) {
    if (pattern[i] === '\\') {
      i += 2;
      continue;
    }
    if (pattern[i] === ']') return i + 1;
    i += 1;
  }
  throw new Error(`unterminated character class in ${JSON.stringify(pattern)}`);
}

/** Add the fold letters for every i/k/s the class admits, right after `[`/`[^`. */
function foldClass(cls: string): string {
  const head = cls.startsWith('[^') ? 2 : 1;
  const admitted = asciiLettersIn(cls.slice(head, -1));
  const extras = Object.keys(CASE_FOLD_EXTRAS)
    .sort()
    .filter((c) => admitted.has(c))
    .map((c) => CASE_FOLD_EXTRAS[c])
    .join('');
  return cls.slice(0, head) + extras + cls.slice(head);
}

function asciiLettersIn(body: string): Set<string> {
  const letters = new Set<string>();
  let i = 0;
  while (i < body.length) {
    if (body[i] === '\\') {
      i += 2;
      continue;
    }
    if (i + 2 < body.length && body[i + 1] === '-' && body[i + 2] !== '\\') {
      for (let code = body.charCodeAt(i); code <= body.charCodeAt(i + 2); code++) {
        const c = String.fromCharCode(code);
        if (/^[A-Za-z]$/.test(c)) letters.add(c.toLowerCase());
      }
      i += 3;
      continue;
    }
    if (/^[A-Za-z]$/.test(body[i])) letters.add(body[i].toLowerCase());
    i += 1;
  }
  return letters;
}

function groupPrefix(pattern: string, start: number): string {
  for (const prefix of ['(?<=', '(?<!', '(?:', '(?=', '(?!']) {
    if (pattern.startsWith(prefix, start)) return prefix;
  }
  throw new Error(`unsupported group syntax at ${start} in ${JSON.stringify(pattern)}`);
}

/**
 * `bounded()`, with the keyword case-insensitive and the edges not. Compile
 * the result WITHOUT the `i` flag — it would fold the boundary class too.
 */
export function boundedCaseless(pattern: string): string {
  return bounded(caseless(pattern));
}

/**
 * Left edge only — for patterns ending in an open-ended run (`\S+`), where a
 * right edge is meaningless because the match already runs to whitespace.
 */
export function boundedLeft(pattern: string): string {
  return `${LEFT}(?:${pattern})`;
}
