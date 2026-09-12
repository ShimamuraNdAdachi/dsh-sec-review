# Third-party notices

This project contains material copied verbatim from **two** upstream projects.
Each section below states exactly what was taken, from where, and under which
terms.

| Upstream | What was taken | Its license | Lands in |
| --- | --- | --- | --- |
| [VulnHuntr](https://github.com/protectai/vulnhuntr) | the text of 12 prompt string literals (14,364 characters) plus 32 example payload strings | AGPL-3.0 | `src/prompts.json`, `preset/plugin/prompts.mjs`, `dynamic/host.js`, and a few short quoted phrases in `tests/plugin.spec.mjs` |
| [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) | one preset composition file, copied verbatim | MIT | `preset/agent.cordis.yml` |

The repository as a whole is distributed under **AGPL-3.0-only** (see
`LICENSE`). The MIT-licensed file keeps its MIT terms for every recipient.

---

## 1. VulnHuntr (AGPL-3.0)

This project is a derivative work of **VulnHuntr**. It contains no VulnHuntr
source code, but it reproduces, verbatim, the text of several prompt string
literals that VulnHuntr defines.

### Upstream project

| | |
| --- | --- |
| Project | VulnHuntr |
| Repository | https://github.com/protectai/vulnhuntr |
| Owner | Protect AI (`protectai`) |
| Authors | Dan McInerney `<dan@protectai.com>` ([@DanHMcinerney](https://x.com/DanHMcinerney)), Marcello Salvati `<marcello@protectai.com>` ([@byt3bl33d3r](https://x.com/byt3bl33d3r)) |
| License | GNU Affero General Public License v3.0 (AGPL-3.0) |
| License text | https://github.com/protectai/vulnhuntr/blob/main/LICENSE |

### What was copied

Source file: `vulnhuntr/prompts.py` at upstream commit state whose SHA-256 is

```
101c6d48fb787cd684a3fa1e8bc94e0ec584b08aff38a217d87f0a188fb55374
```

Reproduced verbatim — the **values** of these string literals, byte for byte,
including leading and trailing newlines:

| Kind | Upstream names | Count |
| --- | --- | --- |
| Per-class analysis templates | `LFI_TEMPLATE`, `RCE_TEMPLATE`, `XSS_TEMPLATE`, `AFO_TEMPLATE`, `SSRF_TEMPLATE`, `SQLI_TEMPLATE`, `IDOR_TEMPLATE` | 7 (8,390 chars together) |
| Shared prompts | `INITIAL_ANALYSIS_PROMPT_TEMPLATE`, `README_SUMMARY_PROMPT_TEMPLATE`, `GUIDELINES_TEMPLATE`, `ANALYSIS_APPROACH_TEMPLATE`, `SYS_PROMPT_TEMPLATE` | 5 (5,974 chars together) |
| Example bypass payload strings | the `bypasses` lists inside `VULN_SPECIFIC_BYPASSES_AND_PROMPTS` | 32 strings |

Total reproduced prompt text: **14,364 characters**.

Where that text now lives in this repository:

- `src/prompts.json` — the extracted dataset, with the upstream source name and
  the SHA-256 above recorded inside it;
- `preset/plugin/prompts.mjs` — generated from that dataset;
- `dynamic/host.js` — generated from the same module, with the dataset inlined;
- `tests/plugin.spec.mjs` — quotes a few **short phrases** from the prompts as
  regression assertions (e.g. to prove extraction did not mangle a template).

### What was not copied

- No VulnHuntr source file is copied, vendored, or modified. The extraction is
  performed by `scripts/extract-prompts.mjs`, which parses the Python string
  literals in `vulnhuntr/prompts.py` without executing Python; upstream is read
  only at extraction time and is not redistributed here.
- No VulnHuntr code (its analyzers, `symbol_finder.py`, `LLMs.py`, CLI, or
  prompts-assembly logic) is present in this project. The Cordis plugin, the
  build and install scripts, the tests, and the documentation are original work.

### Why this project is AGPL-3.0-only

VulnHuntr is distributed under the AGPL-3.0 license text and states no "or any
later version" grant, so the derivative as a whole is licensed under
**AGPL-3.0-only** — the version VulnHuntr grants, and no later one. The full
license text is in `LICENSE`.

---

## 2. DeepSeek Harness (MIT)

`preset/agent.cordis.yml` is a verbatim copy of the shipped composition
`packages/preset/agent-presets/presets/standard/agent.cordis.yml` from DeepSeek
Harness, with one row appended at the end (the `security-review` row) and a
header comment describing that derivation.
`scripts/sync-preset.mjs` regenerates the file from that source.

| | |
| --- | --- |
| Project | DeepSeek Harness (`@deepseek-ai/dsh-root`) |
| Repository | https://github.com/deepseek-ai/deepseek-harness |
| Copyright | Copyright (c) 2026 DeepSeek |
| License | MIT |
| Copied file | `preset/agent.cordis.yml`, from `packages/preset/agent-presets/presets/standard/agent.cordis.yml` |
| Local change | one `security-review` row appended, plus a header comment |

The copied composition is what makes this preset a full agent: it carries the
shell, filesystem, search, skills, plan, goal, and delegation rows rather than a
hand-written subset. Copying it is permitted by MIT, which also permits
sublicensing, so including it in an AGPL-3.0-only distribution is allowed. The
notice below is reproduced to satisfy MIT's condition that the copyright notice
and this permission notice accompany copies and substantial portions of the
software; that file itself remains available to recipients under MIT.

```
MIT License

Copyright (c) 2026 DeepSeek

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## Redistribution obligations, in one place

- **AGPL-3.0 (the whole work):** ship `LICENSE`, keep these notices, mark your
  changes, and provide the corresponding source. Section 13 additionally
  requires offering source to the users of a *modified* version you run as a
  network service.
- **MIT (the copied composition file):** keep the notice above with any copy of
  `preset/agent.cordis.yml`, or of a substantial portion of it.
- Nothing else is redistributed: no VulnHuntr code, and no DeepSeek Harness
  code beyond that single composition file.

## Disclaimer

This project is an independent work. It is **not affiliated with, sponsored by,
or endorsed by Protect AI**, the VulnHuntr authors, or DeepSeek. "VulnHuntr" is
used only to identify the origin of the prompt text and the methodology it
implements; "DeepSeek Harness" only to identify the source of the copied
composition.
