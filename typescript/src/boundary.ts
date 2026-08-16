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

/**
 * Left edge only — for patterns ending in an open-ended run (`\S+`), where a
 * right edge is meaningless because the match already runs to whitespace.
 */
export function boundedLeft(pattern: string): string {
  return `${LEFT}(?:${pattern})`;
}
