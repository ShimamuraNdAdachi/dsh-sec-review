/**
 * Extract every prompt out of VulnHuntr's `vulnhuntr/prompts.py` into
 * `src/prompts.json`, without executing Python and without hand-copying text.
 *
 * The source file uses only a tiny subset of Python: module-level
 * triple-quoted string assignments plus one dict of references to them. This
 * module implements exactly that subset (including Python's implicit
 * concatenation of adjacent string literals, which the upstream file relies on
 * by accident) so the extraction is reproducible and reviewable.
 *
 * Usage:
 *   node scripts/extract-prompts.mjs [--source <path/to/prompts.py>] [--out <file>]
 *
 * Default source: ../vulnhuntr/prompts.py relative to the project root, i.e. the
 * VulnHuntr checkout this project lives beside.
 */

import { createHash } from 'node:crypto'
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const HERE = dirname(fileURLToPath(import.meta.url))
const PROJECT = resolve(HERE, '..')

/** The seven vulnerability classes VulnHuntr supports, in its own order. */
const CLASSES = ['LFI', 'RCE', 'XSS', 'AFO', 'SSRF', 'SQLI', 'IDOR']

/** Which module-level template each class's dict entry points at. */
const CLASS_TEMPLATES = {
  LFI: 'LFI_TEMPLATE',
  RCE: 'RCE_TEMPLATE',
  XSS: 'XSS_TEMPLATE',
  AFO: 'AFO_TEMPLATE',
  SSRF: 'SSRF_TEMPLATE',
  SQLI: 'SQLI_TEMPLATE',
  IDOR: 'IDOR_TEMPLATE',
}

/** The class-independent prompts, keyed by their upstream variable name. */
const SHARED_TEMPLATES = [
  'INITIAL_ANALYSIS_PROMPT_TEMPLATE',
  'README_SUMMARY_PROMPT_TEMPLATE',
  'GUIDELINES_TEMPLATE',
  'ANALYSIS_APPROACH_TEMPLATE',
  'SYS_PROMPT_TEMPLATE',
]

/**
 * Read one Python string literal starting at `start` (the opening quote).
 * @param {string} text - the source text.
 * @param {number} start - index of the opening quote.
 * @returns {{ value: string, end: number }} the decoded value and the index just past the closing quote.
 */
function readStringLiteral(text, start) {
  const quote = text[start]
  const escapes = {
    n: '\n', t: '\t', r: '\r', '\\': '\\', "'": "'", '"': '"',
    0: '\0', a: '\x07', b: '\b', f: '\f', v: '\v',
  }
  let out = ''
  let i = start + 1
  while (i < text.length) {
    const ch = text[i]
    if (ch === '\\') {
      const next = text[i + 1]
      if (!Object.hasOwn(escapes, next)) {
        throw new Error(`unsupported escape sequence \\${next} at offset ${i}`)
      }
      out += escapes[next]
      i += 2
      continue
    }
    if (ch === quote) return { value: out, end: i + 1 }
    out += ch
    i += 1
  }
  throw new Error(`unterminated string literal at offset ${start}`)
}

/**
 * Tokenize the Python subset used by the dict literal (strings, identifiers,
 * brackets, colons, commas, `#` comments, whitespace).
 * @param {string} text - the dict literal's source text.
 * @returns {Array<{ type: string, value?: string }>} the token stream.
 */
function tokenize(text) {
  const tokens = []
  let i = 0
  while (i < text.length) {
    const ch = text[i]
    if (/\s/.test(ch)) { i += 1; continue }
    if (ch === '#') {
      while (i < text.length && text[i] !== '\n') i += 1
      continue
    }
    if (ch === '"' || ch === "'") {
      const { value, end } = readStringLiteral(text, i)
      tokens.push({ type: 'string', value })
      i = end
      continue
    }
    if ('{}[]:,'.includes(ch)) {
      tokens.push({ type: ch })
      i += 1
      continue
    }
    if (/[A-Za-z_]/.test(ch)) {
      let j = i
      while (j < text.length && /[A-Za-z0-9_]/.test(text[j])) j += 1
      tokens.push({ type: 'ident', value: text.slice(i, j) })
      i = j
      continue
    }
    throw new Error(`unexpected character ${JSON.stringify(ch)} at offset ${i}`)
  }
  return tokens
}

/**
 * Parse a value from the token stream: a (possibly implicitly concatenated)
 * string, an identifier resolved through `names`, a list, or an object.
 * @param {Array<{ type: string, value?: string }>} tokens - the token stream.
 * @param {{ index: number }} cursor - mutable read position.
 * @param {Record<string, unknown>} names - already-parsed module-level names.
 * @returns {unknown} the parsed value.
 */
function parseValue(tokens, cursor, names) {
  const token = tokens[cursor.index]
  if (token === undefined) throw new Error('unexpected end of input')

  if (token.type === 'string') {
    // Python concatenates adjacent string literals into one value.
    let out = ''
    while (tokens[cursor.index]?.type === 'string') {
      out += tokens[cursor.index].value
      cursor.index += 1
    }
    return out
  }

  if (token.type === 'ident') {
    cursor.index += 1
    if (!Object.hasOwn(names, token.value)) throw new Error(`unknown name ${token.value}`)
    return names[token.value]
  }

  if (token.type === '[') {
    cursor.index += 1
    const list = []
    while (tokens[cursor.index]?.type !== ']') {
      list.push(parseValue(tokens, cursor, names))
      if (tokens[cursor.index]?.type === ',') cursor.index += 1
      else if (tokens[cursor.index]?.type !== ']') throw new Error('expected `,` or `]` in list')
    }
    cursor.index += 1
    return list
  }

  if (token.type === '{') {
    cursor.index += 1
    const object = {}
    while (tokens[cursor.index]?.type !== '}') {
      const key = tokens[cursor.index]
      if (key?.type !== 'string') throw new Error('object keys must be string literals')
      cursor.index += 1
      if (tokens[cursor.index]?.type !== ':') throw new Error('expected `:` after object key')
      cursor.index += 1
      object[key.value] = parseValue(tokens, cursor, names)
      if (tokens[cursor.index]?.type === ',') cursor.index += 1
      else if (tokens[cursor.index]?.type !== '}') throw new Error('expected `,` or `}` in object')
    }
    cursor.index += 1
    return object
  }

  throw new Error(`unexpected token ${JSON.stringify(token)}`)
}

/**
 * Parse every module-level assignment in the Python subset.
 * @param {string} source - the full `prompts.py` text.
 * @returns {{ templates: Record<string, string>, bypasses: Record<string, string[]> }} the parsed tables.
 */
function parseModule(source) {
  const names = {}
  // `NAME = """…"""` — the triple-quoted form used by every template. Upstream
  // is inconsistent about the delimiters: some literals open on the same line as
  // the assignment and some close on the last content line. No template contains
  // `"""` internally, so the next occurrence closes the literal.
  const tripleQuoted = /^([A-Z][A-Z0-9_]*) = """([\s\S]*?)"""/gm
  for (const match of source.matchAll(tripleQuoted)) {
    const [, name, body] = match
    if (body.includes('\\')) {
      throw new Error(`${name}: triple-quoted template contains a backslash; this extractor treats it as literal text`)
    }
    // Python's value is exactly the text between the delimiters.
    names[name] = body
  }

  const dictStart = source.indexOf('VULN_SPECIFIC_BYPASSES_AND_PROMPTS = {')
  if (dictStart === -1) throw new Error('VULN_SPECIFIC_BYPASSES_AND_PROMPTS not found')
  const open = source.indexOf('{', dictStart)
  // The dict closes at the first `}` in column 0.
  const close = source.indexOf('\n}\n', open)
  if (close === -1) throw new Error('unterminated VULN_SPECIFIC_BYPASSES_AND_PROMPTS literal')
  const literal = source.slice(open, close + 2)

  const cursor = { index: 0 }
  const table = parseValue(tokenize(literal), cursor, names)

  const templates = {}
  const bypasses = {}
  for (const vulnClass of CLASSES) {
    const entry = table[vulnClass]
    if (entry === undefined) throw new Error(`class ${vulnClass} missing from the bypass table`)
    templates[vulnClass] = entry.prompt
    bypasses[vulnClass] = entry.bypasses
    const expected = names[CLASS_TEMPLATES[vulnClass]]
    if (templates[vulnClass] !== expected) {
      throw new Error(`class ${vulnClass}: dict prompt does not resolve to ${CLASS_TEMPLATES[vulnClass]}`)
    }
  }
  for (const key of Object.keys(table)) {
    if (!CLASSES.includes(key)) throw new Error(`unexpected class ${key} in the bypass table`)
  }

  return { templates, bypasses, shared: names }
}

/**
 * Parse CLI flags of the form `--name value`.
 * @param {string[]} argv - `process.argv.slice(2)`.
 * @returns {Record<string, string>} the parsed flags.
 */
function parseFlags(argv) {
  const flags = {}
  for (let i = 0; i < argv.length; i += 2) {
    const key = argv[i]
    if (!key?.startsWith('--')) throw new Error(`unexpected argument ${key}`)
    flags[key.slice(2)] = argv[i + 1]
  }
  return flags
}

const flags = parseFlags(process.argv.slice(2))
const sourcePath = resolve(PROJECT, flags.source ?? '../vulnhuntr/prompts.py')
const outPath = resolve(PROJECT, flags.out ?? 'src/prompts.json')

const source = readFileSync(sourcePath, 'utf8')
const parsed = parseModule(source)

const shared = {}
for (const name of SHARED_TEMPLATES) {
  const text = parsed.shared[name]
  if (typeof text !== 'string') throw new Error(`shared template ${name} not found`)
  shared[name] = text
}

const document = {
  $comment: 'Generated by scripts/extract-prompts.mjs from VulnHuntr vulnhuntr/prompts.py. Do not edit by hand.',
  source: 'vulnhuntr/prompts.py',
  sourceSha256: createHash('sha256').update(source).digest('hex'),
  license: 'AGPL-3.0-or-later (upstream: protectai/vulnhuntr)',
  vulnerabilityClasses: CLASSES,
  classTemplates: parsed.templates,
  classBypasses: parsed.bypasses,
  sharedPrompts: shared,
  notes: [
    'Text is byte-identical to the upstream Python string values, including their leading and trailing newline.',
    'The upstream LFI bypass list relies on Python implicit string concatenation: "C:\\\\win.ini" is directly followed by "/?../../../etc/passwd" with no comma, so the two literals became one entry. This extractor reproduces Python semantics and keeps the merged entry.',
  ],
}

mkdirSync(dirname(outPath), { recursive: true })
writeFileSync(outPath, `${JSON.stringify(document, null, 2)}\n`, 'utf8')

const bytes = Object.values(parsed.templates).reduce((n, t) => n + t.length, 0)
  + Object.values(shared).reduce((n, t) => n + t.length, 0)
console.log(`extracted ${CLASSES.length} class templates + ${SHARED_TEMPLATES.length} shared prompts (${bytes} chars)`)
for (const vulnClass of CLASSES) {
  console.log(`  ${vulnClass.padEnd(5)} template ${String(parsed.templates[vulnClass].length).padStart(5)} chars, ${parsed.bypasses[vulnClass].length} bypass example(s)`)
}
console.log(`  LFI merged entry: ${JSON.stringify(parsed.bypasses.LFI.at(-1))}`)
console.log(`wrote ${outPath}`)
