# dsh-sec-review

把 [VulnHuntr](https://github.com/protectai/vulnhuntr)（`protectai/vulnhuntr`）里的**提示词**提取出来，封装成 **DeepSeek Harness（DSH）可直接使用的代码安全审查插件**。

VulnHuntr 本体是一个 Python 工具：它自己驱动 LLM 循环，反复向模型索要上下文代码，直到走完「远程用户输入 → 危险函数 sink」的完整调用链。这套提示词才是它真正的价值，而这个仓库把它原样搬进 DSH —— 让**当前这个 Agent 自己**按 VulnHuntr 的方法论做静态审计，不再需要额外的 Python 运行时、API Key 和独立的 LLM 循环。

## 交付内容

| 形态 | 位置 | 说明 |
| --- | --- | --- |
| **Agent 预设**（推荐，长期可用） | `preset/` | 一个完整的 DSH Agent 预设（= 官方 `standard` 预设 + 1 行插件），已可直接挂载 |
| **Cordis 插件模块** | `preset/plugin/security-review.mjs` | 零依赖 ES 模块，随预设目录一起分发，注册 1 个提示词段落 + 4 个工具 |
| **动态插件 Host 半体** | `dynamic/host.js` | 由插件模块**生成**的 plain-JS 函数体，可直接贴进 `cordis_define`，会话内即用、无需安装 |
| **提示词数据** | `src/prompts.json` | 从上游 `vulnhuntr/prompts.py` 逐字提取，附来源 sha256 |
| **提取/构建/测试脚本** | `scripts/`、`tests/` | 可复现，无第三方依赖 |

## 提取出来的提示词

提取器 `scripts/extract-prompts.mjs` 不执行 Python，而是实现 `prompts.py` 用到的那一小撮 Python 语法（三引号字符串、字典、字符串隐式拼接、转义），因此提取过程**可复现、可核对**，文本与上游逐字节一致（含首尾换行）。

**7 类漏洞的分析模板 + 绕过示例**（`VULN_SPECIFIC_BYPASSES_AND_PROMPTS`）：

| 类别 | 模板要点 | 上游绕过示例数 |
| --- | --- | --- |
| `LFI` | `open()` / `os.path.join()` / 路径穿越 / 模板包含 | 5 |
| `RCE` | `eval`/`exec`/`subprocess`/反序列化 / 动态导入 / SSTI | 7 |
| `XSS` | HTML·属性·JS 三种输出上下文 / 存储型 / 头部注入 | 5 |
| `AFO` | 写模式 `open()` / `os.rename` / 日志与配置写入 | 5 |
| `SSRF` | `requests`/`urlopen` / URL 校验绕过 / 云元数据 | 5 |
| `SQLI` | 7 步法：入口 → 数据流 → SQL 构造 → 参数化 → 控制 → 绕过 → 影响 | 5 |
| `IDOR` | 对象引用 / 授权检查缺失 / `has_permission()` 之类 | 0 |

**5 个与类别无关的共享提示词**：

| 变量 | 用途 |
| --- | --- |
| `INITIAL_ANALYSIS_PROMPT_TEMPLATE` | 第一步：清点远程入口点与候选 sink |
| `ANALYSIS_APPROACH_TEMPLATE` | 通用分析方法：代码路径追踪、安全控制评估、上下文补齐 |
| `GUIDELINES_TEMPLATE` | 报告规范：JSON 结构、如何索要上下文、什么算「远程可利用」、PoC 要求 |
| `README_SUMMARY_PROMPT_TEMPLATE` | 先以攻击面视角总结目标项目 README |
| `SYS_PROMPT_TEMPLATE` | 上游「Python 安全分析权威」人格与上下文补齐循环 |

> 上游 LFI 绕过列表里 `"C:\\win.ini"` 后面**漏了逗号**，紧跟 `"/?../../../../etc/passwd"`，Python 把两个字面量隐式拼成了一条。提取器按 Python 语义保留了这个合并结果，并在 `src/prompts.json` 的 `notes` 中记录（这是上游的笔误，值得回报）。

## 插件做了什么

挂载后，它向**当前会话作用域**贡献：

**1 个提示词段落** `security-review:guidance`（order 2900）——把 VulnHuntr 的工作流和举证规则固化成系统提示：先清点远程入口 → 逐类加载 playbook → 追踪「入口到 sink」的完整路径并说明绕过了哪个控制 → 用贴合被测代码的 PoC 证明可利用性 → 记录 → 导出报告；同时明确「只报远程可利用」「PoC 不始于远程网络输入则置信度 ≤ 6」「每个发现都要 0–10 置信度与理由」。

**4 个工具**：

| 工具 | 作用 | 何时调用 |
| --- | --- | --- |
| `sec_review_playbook` | 无参数 → 跨类别入口/sink 清点指令；带 `vulnerability_type` → 该类模板原文 + 绕过示例（`include_bypasses`、`include_methodology` 可选） | 每追一类漏洞前调用一次 |
| `sec_review_methodology` | 按 `part` 返回共享提示词原文：`index`(默认) / `initial` / `approach` / `guidelines` / `readme` / `system` / `all` / `report` | 需要通用方法或报告规范时 |
| `sec_review_finding` | 记录一条发现：`vulnerability_types`、`file_path`、`confidence_score`(0–10)、`analysis`、`poc`，可选 `scratchpad`/`entry_point`/`security_controls_bypassed`；越界或空 PoC 直接报错 | 追踪完一条链之后 |
| `sec_review_findings` | 汇总报告：`format`(markdown/json)、`min_confidence`、`clear` | 收尾时导出 |

发现按 **Session 隔离**保存（预设实例是进程级的，所以状态按 `agent.id` 分桶），每会话上限 200 条；`sec_review_methodology` 的 `report` 部件会给出上游那份 `scratchpad / analysis / poc / confidence_score / vulnerability_types` 报告格式。

## 使用方式

### A. 作为 Agent 预设（推荐）

已经安装到 `%DSH_HOME%\.agent-presets\security-review\`。**重启 host 或新开一个会话**，在预设选择器里选「**代码安全审计 (VulnHuntr)**」即可。该预设 = 官方 `standard` 预设的全部能力（Shell、文件读写与检索、Skills、计划、目标、子代理、工作流）+ 本插件，所以审计时该有的读文件、grep、子代理能力都在。

重新安装（改了插件代码之后）：

```powershell
npm run build                       # 重新生成 preset/plugin/prompts.mjs 与 dynamic/host.js
npm run install-preset              # 复制 preset/ 到 %DSH_HOME%\.agent-presets\security-review\
node scripts/install-preset.mjs --force --id security-review --dry-run
```

### B. 作为动态插件（会话内即用，无需安装）

把 `dynamic/host.js` 的**全部内容**作为 `code.host` 传进 `cordis_define`，再 `cordis_run` 激活。四个工具与提示词段落只存在于当前进程，重启即消失。

### C. 只取提示词

`src/prompts.json` 是纯数据，任何工具都能直接读。

## 开发

```powershell
node scripts/extract-prompts.mjs    # ../vulnhuntr/prompts.py -> src/prompts.json
node scripts/build.mjs              # -> preset/plugin/prompts.mjs, dynamic/host.js
npm test                            # 24 项断言，覆盖预设模块与生成的动态半体
node scripts/sync-preset.mjs <path-to-standard/agent.cordis.yml>   # 重新同步预设组合
```

无需 `npm install`：全部脚本只用 Node 内置模块，测试用内置 `node:test`。

## DSH 升级 / 删除根目录重新构建之后

先分清三个东西各自放在哪里：

| 东西 | 位置 | 重建 DSH 根目录之后 |
| --- | --- | --- |
| 本项目（**唯一真源**） | 工作区里的 `dsh-sec-review/`，独立 git 仓库 | **不受影响**（不在 DSH 目录内） |
| 已安装的 Agent 预设 | `%DSH_HOME%\.agent-presets\security-review\`（默认 `C:\Users\<你>\.dsh`，**不在** DSH 根目录内） | 只要升级没有连 `%DSH_HOME%` 一起清掉，就**保留** |
| 动态插件（`cordis_define` 激活的那份） | 只存在于当前进程内存 | **任何一次重启都会消失**，与升级无关 |

所以：**插件不会因为重建 DSH 根目录而丢失** —— 它的本体（`preset/`、`src/`、脚本）在 DSH 目录之外，安装位置在 `%DSH_HOME%` 下；而 DSH 根目录里**没有本项目的任何文件**（我全程只读取过它）。真正要留意的是两点：

1. **`preset/agent.cordis.yml` 是官方 `standard` 组合的版本快照。** 升级后 `standard` 可能新增、改名或删除行，旧快照会出现「Cannot find package …」「invalid config …」或某行不激活。重新同步即可：

   ```powershell
   node scripts/sync-preset.mjs <新 DSH 根>\packages\preset\agent-presets\presets\standard\agent.cordis.yml
   npm run build
   npm run install-preset -- --force
   ```

   同步脚本会校验目标确实是 `standard` 组合、且尚未包含本插件的行，所以重复执行是安全的。

2. **如果升级流程连 `%DSH_HOME%` 一起清掉**（那会同时丢掉会话、凭据、设置），预设也没了，从仓库重装即可：

   ```powershell
   npm run build            # 需要时；只影响生成物
   npm run install-preset   # 把 preset/ 复制到 %DSH_HOME%\.agent-presets\security-review\
   ```

   `src/prompts.json` 是**已提交的提示词数据**，所以即使上游 `../vulnhuntr/`（Python 源码）被删除，`build` / `test` / `install-preset` 依旧可用；只有 `npm run extract` 需要那份上游源码。预设只对新会话生效，重装后新开一个会话确认「代码安全审计 (VulnHuntr)」出现在选择器里即可。

> 建议把本仓库推到远端（或至少备份）：它才是真源，`%DSH_HOME%` 里那份只是安装产物；更新流程也无法在 DSH 根目录内放任何属于本项目的东西（那会被下一次重建覆盖）。

## 设计说明

- **为什么插件模块零依赖？** 用户自建预设位于 `~/.dsh/.agent-presets/`，Node 的 `node_modules` 向上查找到不了已安装的 harness，任何 `@deepseek-ai/dsh-*` 裸导入在挂载时都会失败。因此插件只通过 `ctx.get()` / `ctx.<service>` 拿能力，工具 schema 直接写成**原始 JSON Schema**，而不是第一方包使用的 `defineTool` 授权 DSL。
- **为什么是「standard + 1 行」而不是从零写组合？** 预设决定 Agent 的全部工具面：从零写会悄悄丢掉 Shell、文件系统、检索、Skills 等审计必需的行。上游 `standard` 组合是已知可挂载的，本地差异只有最后一行。该行不 publish 任何 service，所以**不需要 `isolate` realm**，可以直接松散地放在组合里。
- **为什么动态半体是生成的？** 动态沙箱禁止 `import`，注册工具必须走 `harness.defineTool` + `harness.registerTool`。`scripts/build.mjs` 从同一个插件模块**派生**出动态半体（换掉模块包装、改走 dynamic harness），并在每个预期模式上断言，源码改动破坏派生时直接构建失败——两份实现不会漂移。
- **验证情况**：`standingKeyFor('security-review')` 挂载成功（行解析、`inject` 解析、`apply` 真实执行、schema 通过注册校验、未向 root realm 发布服务）；生成的动态半体已在沙箱语义下验证过参数方言与 `ctx.effect(...systemPrompt.section...)`。

## 限制

- 上游模板以 **Python** 为对象（`open()`、`pickle.loads`、`os.system` 等），分析其他语言时模板里的高危函数清单需要自行替换；但「入口点 → 数据流 → sink → 绕过控制 → PoC」的方法论是通用的。
- 插件只提供**方法论与结构化报告**，不做代码索引：读文件、grep、追调用链由 Agent 用预设里的常规工具完成。
- 提示词段落是英文（与上游原文一致，模型可靠性更好），工具描述同样是英文。
- 置信度只是模型自评：上游经验是 `<7` 基本可忽略、`7` 需要人工复核、`≥8` 很可能成立。

## 许可与来源

提示词逐字提取自 [protectai/vulnhuntr](https://github.com/protectai/vulnhuntr)（**AGPL-3.0**，作者 Dan McInerney、Marcello Salvati），因此本项目同样以 **AGPL-3.0-or-later** 发布，见 `LICENSE`。`src/prompts.json` 记录来源文件的 sha256，便于核对。
