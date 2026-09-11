/**
 * `security-review` — a DSH Cordis plugin that turns VulnHuntr's extracted
 * prompts into a per-session code-security-review capability.
 *
 * It contributes two things to the scope it is mounted in:
 *
 *   - one prompt section (`security-review:guidance`) that states the review
 *     workflow and the evidential rules upstream enforces; and
 *   - four host tools — `sec_review_playbook`, `sec_review_methodology`,
 *     `sec_review_finding`, `sec_review_findings`.
 *
 * The plugin is deliberately **dependency-free**: a locally authored agent
 * preset lives outside the installed harness, so Node's `node_modules` walk
 * cannot reach `@deepseek-ai/dsh-*` from here and a bare import would fail at
 * mount. Everything therefore arrives through `ctx.get(...)`/`ctx.<service>`,
 * and tool schemas are written as raw JSON Schema rather than through the
 * `defineTool` authoring DSL that first-party packages import.
 *
 * It publishes no service, so a preset may mount it as a loose row — no
 * `isolate` realm is needed.
 */

import { PROMPTS } from './prompts.mjs'

/** Cordis plugin name (metadata for the loader's row display). */
export const name = 'security-review'

/** Both registries this row contributes to are host-plane and always present. */
export const inject = ['tools', 'systemPrompt']

/** The vulnerability classes VulnHuntr covers, in its own order. */
const VULN_TYPES = PROMPTS.vulnerabilityClasses

/**
 * Section placement. `TOOL_REPORT` is 2900 in the system-prompt registry's own
 * table; a literal keeps this module import-free, and the registry tolerates
 * any finite order as long as the section name is unique.
 */
const SECTION_ORDER = 2900

/** How many findings one session may retain before the oldest are dropped. */
const MAX_FINDINGS = 200

/** The prompt section this plugin contributes to every agent on its preset. */
const GUIDANCE = `## Security review mode

This session performs static security review of a remote attack surface. The \`sec_review_*\` tools carry the full upstream (VulnHuntr) instruction set — use them instead of improvising the review method.

Workflow:
1. Inventory remote user-input entry points before analysing sinks: HTTP routes, RPC/API handlers, webhooks, form and query parameters, request bodies, headers, cookies, uploaded file names, and anything else a remote peer controls. Call \`sec_review_playbook\` with no argument for the upstream entry-point and sink inventory instructions.
2. For each vulnerability class that the code can plausibly reach, call \`sec_review_playbook\` with that class to get its analysis template and bypass examples. Call \`sec_review_methodology\` when you need the shared analysis approach, reporting guidelines, README-summary prompt, or the upstream reviewer persona.
3. Trace the complete path from remote input to the sink, including every validation, sanitisation, encoding, and authorisation step in between, and say explicitly which control you bypass and how.
4. Prove exploitability with a concrete proof of concept for the code actually under review — not a generic payload. If the chain is incomplete because context is missing, read the missing code first; do not guess.
5. Record each candidate with \`sec_review_finding\`.
6. Finish with \`sec_review_findings\` to produce the consolidated report.

Evidential rules (upstream, non-negotiable):
- Report only remotely exploitable vulnerabilities. Local-only access, CLI arguments, and environment-only inputs do not qualify.
- A proof of concept that does not begin with remote network input (HTTP, API, RPC) caps the confidence score at 6.
- Every finding needs a confidence score from 0 to 10 with a detailed justification. 7 means "investigate", 8 or more means "very likely valid".
- One vulnerability class per finding is the norm; list several only when one code path genuinely reaches several classes.
- Use \`None\` for any report field you lack the information for rather than inventing a value.`

/**
 * Quote one upstream prompt verbatim under a heading.
 * @param {string} title - heading text.
 * @param {string} text - the upstream prompt, newlines and all.
 * @returns {string} a markdown block whose body is untouched upstream text.
 */
function section(title, text) {
  return `### ${title}\n\n\`\`\`text\n${text.replace(/\n+$/, '')}\n\`\`\`\n`
}

/**
 * The severity band VulnHuntr's own guidance implies for a confidence score.
 * @param {number} confidence - 0-10 confidence score.
 * @returns {string} the band label.
 */
function severityOf(confidence) {
  if (confidence >= 8) return 'high'
  if (confidence >= 7) return 'medium'
  if (confidence >= 5) return 'low'
  return 'informational'
}

/**
 * One-line description of what each shared prompt is for, used by
 * `sec_review_methodology`'s index.
 */
const METHODOLOGY_INDEX = [
  ['initial', 'INITIAL_ANALYSIS_PROMPT_TEMPLATE', 'Step 1 of the upstream flow: inventory remote entry points and candidate sinks for all seven classes, and note the controls a PoC must defeat.'],
  ['approach', 'ANALYSIS_APPROACH_TEMPLATE', 'The shared analysis instructions: comprehensive review, code-path tracing, security-control analysis, context requests, and final review.'],
  ['guidelines', 'GUIDELINES_TEMPLATE', 'The reporting contract: JSON/scratchpad layout, how to request more context, which vulnerabilities count as remote, and PoC requirements.'],
  ['readme', 'README_SUMMARY_PROMPT_TEMPLATE', 'Summarise the target project README from an attack-surface perspective before analysing code.'],
  ['system', 'SYS_PROMPT_TEMPLATE', 'The upstream reviewer persona and task framing, including its context-completion loop.'],
]

/** The method names whose upstream prompt `sec_review_methodology` can return. */
const METHODOLOGY_PARTS = ['index', 'initial', 'approach', 'guidelines', 'readme', 'system', 'all', 'report']

/**
 * Keep the tool catalog's own schema declarations honest: raw JSON Schema for
 * models, plus the declared output contract the registry enforces.
 * @param {string} text - the model-facing text a tool produced.
 * @returns {Array<{ type: string, text: string }>} the result content blocks.
 */
function renderText(_args, value) {
  return [{ type: 'text', text: String(value) }]
}

/** Shared output declaration: every tool answers with one markdown string. */
const OUTPUT = { schema: { type: 'string' }, render: renderText }

/**
 * Register the prompt section and the four review tools on the mounting scope.
 * @param {import('@deepseek-ai/cordis').Context} ctx - the preset's scope context.
 */
export function apply(ctx) {
  ctx.effect(() => ctx.systemPrompt.section({
    name: 'security-review:guidance',
    order: SECTION_ORDER,
    text: GUIDANCE,
  }), 'security-review.section()')

  /** Per-session finding store: the preset's plugin instance is process-wide, so
   * state is keyed by owning agent instead of living in the closure alone. */
  const findings = new Map()

  /**
   * Resolve the finding list for the calling agent, creating it on first use.
   * @param {{ agent?: { id: string } }} exec - the tool run context.
   * @returns {Array<object>} the mutable list owned by that agent.
   */
  const bucketFor = exec => {
    const key = exec.agent ? String(exec.agent.id) : '_anonymous'
    let list = findings.get(key)
    if (list === undefined) {
      list = []
      findings.set(key, list)
    }
    return list
  }

  for (const tool of defineTools(bucketFor)) {
    ctx.effect(() => ctx.tools.register(tool), `security-review.tool(${tool.name})`)
  }
}

/**
 * Build the four tool definitions.
 * @param {(exec: object) => Array<object>} bucketFor - per-agent finding store.
 * @returns {object[]} registry-ready tool definitions.
 */
function defineTools(bucketFor) {
  return [
    {
      name: 'sec_review_playbook',
      description:
        'Return the extracted VulnHuntr playbook. Without `vulnerability_type` it returns the '
        + 'cross-class entry-point/sink inventory instructions (step 1 of the upstream flow). With a '
        + 'class it returns that class\'s verbatim analysis template plus its bypass examples. Call it '
        + 'once per class you intend to pursue, before tracing code for that class.',
      parameters: {
        type: 'object',
        properties: {
          vulnerability_type: {
            type: 'string',
            enum: VULN_TYPES,
            description: 'Vulnerability class to load the playbook for. Omit for the cross-class inventory instructions.',
          },
          include_bypasses: {
            type: 'boolean',
            description: 'Include the class\'s example bypass techniques. Defaults to true.',
          },
          include_methodology: {
            type: 'boolean',
            description: 'Also append the shared analysis approach and reporting guidelines. Defaults to false; prefer sec_review_methodology.',
          },
        },
      },
      output: OUTPUT,
      async execute(args) {
        const parts = []
        const wanted = args.vulnerability_type
        if (wanted === undefined) {
          parts.push('# VulnHuntr playbook — cross-class inventory\n')
          parts.push('Supported classes: ' + VULN_TYPES.join(', ') + '. Call this tool again with '
            + '`vulnerability_type` set to load a class template.\n')
          parts.push(section('Initial analysis prompt (INITIAL_ANALYSIS_PROMPT_TEMPLATE)',
            PROMPTS.sharedPrompts.INITIAL_ANALYSIS_PROMPT_TEMPLATE))
        } else {
          if (!VULN_TYPES.includes(wanted)) {
            throw new Error(`unknown vulnerability_type ${JSON.stringify(wanted)}; expected one of ${VULN_TYPES.join(', ')}`)
          }
          parts.push(`# VulnHuntr playbook — ${wanted}\n`)
          parts.push(section(`${wanted} analysis template`, PROMPTS.classTemplates[wanted]))
          if (args.include_bypasses !== false) {
            const bypasses = PROMPTS.classBypasses[wanted] ?? []
            if (bypasses.length === 0) {
              parts.push(`### ${wanted} bypass examples\n\nUpstream ships none for this class.\n`)
            } else {
              parts.push(`### ${wanted} bypass examples (upstream)\n\n`
                + bypasses.map(item => `- \`${item.replace(/`/g, '\\`')}\``).join('\n') + '\n')
            }
          }
        }
        if (args.include_methodology === true) {
          parts.push(section('Analysis approach (ANALYSIS_APPROACH_TEMPLATE)',
            PROMPTS.sharedPrompts.ANALYSIS_APPROACH_TEMPLATE))
          parts.push(section('Reporting guidelines (GUIDELINES_TEMPLATE)',
            PROMPTS.sharedPrompts.GUIDELINES_TEMPLATE))
        }
        return parts.join('\n')
      },
      presentCall: args => ({
        card: 'generic',
        title: `Security playbook: ${args.vulnerability_type ?? 'inventory'}`,
        kind: 'other',
      }),
    },

    {
      name: 'sec_review_methodology',
      description:
        'Return a shared (class-independent) VulnHuntr prompt verbatim: the upstream reviewer persona, '
        + 'the analysis approach, the reporting guidelines, the README attack-surface summary prompt, or '
        + 'the initial analysis prompt. Call it with no argument for the index of available parts.',
      parameters: {
        type: 'object',
        properties: {
          part: {
            type: 'string',
            enum: METHODOLOGY_PARTS,
            description: 'Which shared prompt to return. `index` (default) lists them; `all` returns every one.',
          },
        },
      },
      output: OUTPUT,
      async execute(args) {
        const part = args.part ?? 'index'
        if (part === 'index') {
          return '# VulnHuntr shared prompts\n\n'
            + METHODOLOGY_INDEX.map(([key, variable, purpose]) => `- \`${key}\` (${variable}) — ${purpose}`).join('\n')
            + '\n- `report` — the consolidated report shape a `sec_review_finding` record maps onto.\n'
            + '\nCall `sec_review_methodology` with one part, or with `part: "all"` for everything.\n'
        }
        if (part === 'report') {
          return section('Upstream report shape', REPORT_SHAPE)
        }
        if (part === 'all') {
          const blocks = METHODOLOGY_INDEX.map(([, variable]) => section(`${variable}`, PROMPTS.sharedPrompts[variable]))
          blocks.push(section('Upstream report shape', REPORT_SHAPE))
          return blocks.join('\n')
        }
        const entry = METHODOLOGY_INDEX.find(([key]) => key === part)
        if (entry === undefined) {
          throw new Error(`unknown part ${JSON.stringify(part)}; expected one of ${METHODOLOGY_PARTS.join(', ')}`)
        }
        return section(`${entry[1]}`, PROMPTS.sharedPrompts[entry[1]])
      },
      presentCall: args => ({
        card: 'generic',
        title: `Security methodology: ${args.part ?? 'index'}`,
        kind: 'other',
      }),
    },

    {
      name: 'sec_review_finding',
      description:
        'Record one security-review finding for the current session. Call it once per candidate '
        + 'vulnerability, after the code path and its controls have been traced and a concrete proof of '
        + 'concept exists. The reply lists the stored finding plus a running count; use '
        + 'sec_review_findings to read the consolidated report.',
      parameters: {
        type: 'object',
        properties: {
          vulnerability_types: {
            type: 'array',
            items: { type: 'string', enum: VULN_TYPES },
            description: 'One or more classes this code path reaches (LFI, RCE, XSS, AFO, SSRF, SQLI, IDOR).',
          },
          file_path: {
            type: 'string',
            description: 'File containing the vulnerable sink, as a path relative to the reviewed repository.',
          },
          confidence_score: {
            type: 'integer',
            description: 'Confidence 0-10 that a remote attacker can exploit this. Cap at 6 when the PoC does not start from remote network input.',
          },
          analysis: {
            type: 'string',
            description: 'Final analysis: the user-input-to-sink chain, how each security control is bypassed, and the impact.',
          },
          poc: {
            type: 'string',
            description: 'Concrete proof of concept for this code: the remote request or payload plus the code path it follows.',
          },
          scratchpad: {
            type: 'string',
            description: 'Optional step-by-step reasoning that led to the finding.',
          },
          entry_point: {
            type: 'string',
            description: 'Optional remote entry point the chain starts at, e.g. `POST /add_llm (JSON body)`.',
          },
          security_controls_bypassed: {
            type: 'string',
            description: 'Optional list of the validation, sanitisation, or authorisation controls the PoC defeats.',
          },
        },
        required: ['vulnerability_types', 'file_path', 'confidence_score', 'analysis', 'poc'],
      },
      output: OUTPUT,
      async execute(args, exec) {
        const classes = args.vulnerability_types ?? []
        if (!Array.isArray(classes) || classes.length === 0) {
          throw new Error('vulnerability_types must list at least one class')
        }
        for (const item of classes) {
          if (!VULN_TYPES.includes(item)) {
            throw new Error(`unknown vulnerability type ${JSON.stringify(item)}; expected one of ${VULN_TYPES.join(', ')}`)
          }
        }
        const confidence = args.confidence_score
        if (!Number.isInteger(confidence) || confidence < 0 || confidence > 10) {
          throw new Error(`confidence_score must be an integer from 0 to 10 (got ${JSON.stringify(confidence)})`)
        }
        if (typeof args.analysis !== 'string' || args.analysis.trim() === '') {
          throw new Error('analysis must be a non-empty description of the exploit chain')
        }
        if (typeof args.poc !== 'string' || args.poc.trim() === '') {
          throw new Error('poc must be a non-empty proof of concept for the reviewed code')
        }
        const record = {
          vulnerability_types: classes,
          file_path: args.file_path,
          confidence_score: confidence,
          severity: severityOf(confidence),
          analysis: args.analysis,
          poc: args.poc,
          scratchpad: args.scratchpad ?? 'None',
          entry_point: args.entry_point ?? 'None',
          security_controls_bypassed: args.security_controls_bypassed ?? 'None',
        }
        const list = bucketFor(exec)
        list.push(record)
        while (list.length > MAX_FINDINGS) list.shift()
        return `Recorded finding #${list.length} (${list.length} in this session).\n\n${formatFinding(record, list.length - 1)}`
      },
      presentCall: args => ({
        card: 'generic',
        title: `Security finding: ${(args.vulnerability_types ?? []).join('/') || 'unclassified'} in ${args.file_path ?? '?'}`,
        kind: 'other',
      }),
    },

    {
      name: 'sec_review_findings',
      description:
        'Read the consolidated security-review report for the current session: every finding recorded with '
        + 'sec_review_finding, ordered by confidence. Use `format: "json"` for the machine-checkable export, '
        + 'or `clear: true` to start a fresh report.',
      parameters: {
        type: 'object',
        properties: {
          format: {
            type: 'string',
            enum: ['markdown', 'json'],
            description: 'Report shape. Defaults to `markdown`.',
          },
          clear: {
            type: 'boolean',
            description: 'Discard every recorded finding after producing the report. Defaults to false.',
          },
          min_confidence: {
            type: 'integer',
            description: 'Only include findings at or above this confidence score. Defaults to 0.',
          },
        },
      },
      output: OUTPUT,
      async execute(args, exec) {
        const list = bucketFor(exec)
        const threshold = args.min_confidence ?? 0
        if (!Number.isInteger(threshold) || threshold < 0 || threshold > 10) {
          throw new Error(`min_confidence must be an integer from 0 to 10 (got ${JSON.stringify(threshold)})`)
        }
        const selected = list.filter(item => item.confidence_score >= threshold)
        const ordered = [...selected].sort((a, b) => b.confidence_score - a.confidence_score)
        if (args.clear === true) list.length = 0
        if (args.format === 'json') {
          return JSON.stringify({
            summary: summarise(selected),
            findings: ordered,
          }, null, 2)
        }
        return formatReport(ordered, selected.length === 0
          ? 'No findings recorded for this session yet.'
          : undefined)
      },
      presentCall: args => ({
        card: 'generic',
        title: args.clear === true ? 'Security report (and clear)' : 'Security report',
        kind: 'other',
      }),
    },
  ]
}

/** The upstream report layout, quoted so the model can mirror it when reporting. */
const REPORT_SHAPE = `scratchpad:
  <step-by-step analysis>
----------------------------------------

analysis:
  <final analysis of the vulnerability>
----------------------------------------

poc:
  <proof of concept exploit or detailed exploitation steps>
----------------------------------------

confidence_score:
  <0-10>
----------------------------------------

vulnerability_types:
  - <one or more of LFI, RCE, XSS, AFO, SSRF, SQLI, IDOR>
----------------------------------------
`

/**
 * Count findings per class and band.
 * @param {object[]} findings - the findings to summarise.
 * @returns {object} per-severity and per-class counts.
 */
function summarise(findings) {
  const bySeverity = {}
  const byClass = {}
  for (const item of findings) {
    bySeverity[item.severity] = (bySeverity[item.severity] ?? 0) + 1
    for (const vulnClass of item.vulnerability_types) {
      byClass[vulnClass] = (byClass[vulnClass] ?? 0) + 1
    }
  }
  return { total: findings.length, bySeverity, byClass }
}

/**
 * Render one finding as markdown.
 * @param {object} record - a stored finding.
 * @param {number} index - its position in the report.
 * @returns {string} the markdown block.
 */
function formatFinding(record, index) {
  return [
    `#### ${index + 1}. [${record.severity}] ${record.vulnerability_types.join('/')} — ${record.file_path}`,
    '',
    `- confidence_score: ${record.confidence_score}/10`,
    `- entry_point: ${record.entry_point}`,
    `- security_controls_bypassed: ${record.security_controls_bypassed}`,
    '',
    '**analysis**',
    '',
    record.analysis,
    '',
    '**poc**',
    '',
    '```',
    record.poc,
    '```',
    '',
    '**scratchpad**',
    '',
    record.scratchpad,
  ].join('\n')
}

/**
 * Render the consolidated report.
 * @param {object[]} ordered - findings ordered by descending confidence.
 * @param {string} [empty] - message to use when there is nothing to report.
 * @returns {string} the markdown report.
 */
function formatReport(ordered, empty) {
  if (ordered.length === 0) return empty ?? 'No findings recorded for this session yet.'
  const counts = summarise(ordered)
  const header = [
    '# Security review report',
    '',
    `${counts.total} finding(s): `
      + Object.entries(counts.bySeverity).map(([band, n]) => `${n} ${band}`).join(', '),
    '',
    Object.entries(counts.byClass).map(([vulnClass, n]) => `${vulnClass}: ${n}`).join(' · '),
    '',
  ].join('\n')
  return `${header}\n${ordered.map((item, i) => formatFinding(item, i)).join('\n\n')}\n`
}
