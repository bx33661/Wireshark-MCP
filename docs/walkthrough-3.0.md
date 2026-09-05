# Wireshark MCP 3.0 正式版实施走查与验收报告

> **发布版本**：3.0.0<br>
> **发布主题**：可信分析与稳定接口 (Trustworthy Analysis and Stable Interfaces)<br>
> **核心承诺**：同一份抓包，结果可复现；分析不完整时明确说明；每个重要结论都能回到数据包证据。<br>
> **分发产物**：`dist/wireshark_mcp-3.0.0-py3-none-any.whl` 与 `dist/wireshark_mcp-3.0.0.tar.gz`<br>
> **Wheel SHA256**：`ea35aed97970595ae67026681a226934711c3e7aec97fdff5605e82acd29fe65`

---

## 1. 核心改进与收尾验收清单

本轮 3.0 正式版发布聚焦所有核心工作项与发布前缺陷的彻底修复，所有能力均通过真实验证并纳入自动化测试矩阵：

### 1.1 结果契约与错误边界 (P0)
- **统一信封契约**：在 `envelope.py` 中新增 `envelope_response`，规范统一输出结构，覆盖统计聚合、明文凭据提取和威胁检测套件，规范字段包括 `success`、`scope`、`coverage`、`pagination`、`warnings`、`truncated` 与 `stderr`。
- **类型不变截断机制**：彻底重写 `mcp_app.py:cap_result_text`，当响应超出字符上限（默认 25,000 字符）时：
  - `dict` 结构保持为合法字典对象，截断内部列表并注入 `truncated: true`；
  - 针对超长错误响应，按优先级逐步剥离 `scope`、`details`、`warnings`、`stderr`，最终仍兜底生成合法的 JSON 错误信封（`{"success": false, "error": {"message": "..."}, "truncated": true}`），绝不破坏 JSON 结构。
- **协议级 `is_error` 双重保障**：
  - 在 `mcp_app.py:call_tool` 中，在内容截断前率先检查原始返回的 `success: false`，严格同步设置 MCP 协议规范的 `CallToolResult.is_error = True`，即使错误文本发生严重截断也绝不丢失协议级错误标记。
- **分页元数据完整性保障**：
  - 当结果列表因字符上限被二次截断时，严格保留全局总量 `pagination["total"]`，并将 `next_offset` 修正为当前已返回的累加位移（`offset + returned`），同时标记 `has_more: true`，确保客户端分页重试或后续拉取绝不漏包。

### 1.2 修正检测语义与 Finding 证据模型 (P0)
- **子查询失败与局部覆盖感知**：
  - 在 `threat.py` 的 `wireshark_detect_port_scan` 与 `wireshark_detect_dos_attack` 中引入 `failed_checks` 跟踪；
  - 子查询执行失败绝不被解释为“零流量”，更不会输出“未发现攻击”的确定结论；当部分子查询失败时，响应被显式标记为 `coverage.status = "partial"`，置信度降为候选级别（`candidate`），并在摘要中警告未执行或失败的检查项。
- **DoS 失败处理与比例校验旁路**：
  - 当 SYN-ACK 响应查询失败时，将 SYN-ACK 数量严格置为未知（`None`），跳过依赖它的比例计算（`ratio = syn_count / synack_count`）与误报断言，彻底杜绝输出如 `100 SYNs vs 0 SYN-ACKs, Ratio 100.0` 的虚假证据；
  - 独立观测到的 SYN 速率仍正常在摘要中报告；
  - SYN 主查询及所有 DoS 子查询的截断状态完整记录至 `warnings`、`constraints` 与 `coverage`。
- **结构化 Finding 证据模型**：新增 `findings.py`，统一定义 `Finding`、`FindingEvidence`、`FindingConstraints` 及安全脱敏工具 `mask_secret`。
- **明文凭据提取修复**：
  - 移除了 `security.py` 中武断的 `len(...) > 20` 强行过滤限制，现已能准确捕获 `admin`、`123456`、`password` 等高频真实口令。
  - 口令输出自动做掩码脱敏（如 `p****d`），并返回帧号及 TCP 流序号证据锚点。
- **DNS 隧道研判去主观化**：
  - 在 `threat.py` 中限制仅过滤查询流量（`dns.flags.response == 0`），排除响应流量污染。
  - 移除了未经标定的“HIGH probability / VERY HIGH probability”断言，改用客观信号指标（高熵子域名数量、每秒查询率、采样域名）并标记为候选异常（`candidate_signal`）。
- **DoS 检测时间归一化**：
  - 依据匹配候选数据包的最早与最晚时间跨度计算时间归一化包速率（`pps`，窗口下限 1.0s），提示亚秒级微突发局限，并针对单向流量抓包给出明确偏差警示（`single-sided capture bias`）。
- **端口扫描帧号锚定**：
  - 记录代表性扫描帧序号列表与扫描限制范围。

### 1.3 聚合资源边界与全路径进程回收 (P1)
- **单行解析逐项受限与全局去重总预算**：
  - 在 `stats.py` 中不仅限制单组 5,000 去重上限，还在多值解析循环内部对单行内展开的每一项都进行上限核验（单行包含 6,000 个逗号分隔值会被严格截断在 5,000 项并追加警告）；
  - 引入全局跨组去重总预算 `MAX_TOTAL_DISTINCT_ITEMS = 50_000`，彻底阻断利用巨量小分组撑爆内存的攻击面。
- **全路径子进程终止与清理回收**：
  - 在 `tshark/client.py` 中，对流式读取循环（`_read_streaming_output`）和普通读取路径（`_read_process_output`、`_run_command`），均在捕获 `asyncio.CancelledError` 或任何异常时，主动执行 `proc.kill()` 并 `await proc.wait()`，彻底杜绝僵尸进程残留。
- **字面量字符串字段保护**：
  - 在 `stats.py` 中加入 `LITERAL_STRING_FIELDS`（如 `http.user_agent`、文件名等），防止普通文本中的逗号被误拆分成多个去重值。

### 1.4 真实抓包回归与传输验收 (P0)
- **确定性合成 PCAP 生成器**：
  - 创建 `tests/fixtures/generate_pcaps.py`，使用纯 Python `struct` 模块生成 5 种二进制 pcap 文件（`empty.pcap`、`plaintext_credentials.pcap`、`syn_scan_burst.pcap`、`dns_tunnel_candidate.pcap`、`multivalue_fields.pcap`）。
- **端到端测试驱动真实 tshark**：
  - 编写 `tests/test_real_pcap.py`，在本地与 CI 中直接调用操作系统安装的 `tshark` 二进制完成全链路检测。
- **真实 Streamable HTTP 协议握手与真实子进程测试**：
  - 在 `tests/test_server.py` 中，涵盖：
    1. 真实 stdio 子进程握手测试；
    2. 旧协议（2024-11-05）HTTP 兼容测试；
    3. 新协议（2026-07-28）使用无 `initialize`、无 Session ID 的逐请求 envelope，严格断言 `server/discover` 只返回 `2026-07-28`，并覆盖工具列表、成功调用与失败调用；
    4. 真实监听独立子进程通过同一新版无状态请求链完成网络套接字端到端测试。
- **Skill 跨端分发一致性与只读检查**：
  - 为 `scripts/sync_skills.py` 补充 `--check` 参数支持，在不修改任何文件的安全模式下递归比对镜像目录一致性与 manifest 校验；
  - 编写 `tests/test_skill_distribution.py` 验证 `--check` 在镜像完全一致时返回 0、在发生篡改或缺失时准确返回 1。
- **兼容性矩阵分级标定与记录校准**：
  - 校准 `docs/compatibility-matrix.md`，明确区分“CI/Locally Verified”（实测通过）、“Config Supported”（官方配置生成）与“Expected Compatible”（理论兼容）三级支持状态；
  - 将 Windows CI 的 Wireshark 版本准确记录为 Chocolatey 安装的 4.6.8。

---

## 2. 自动化验证结果

### 2.1 单元与集成测试套件 (439 项全部通过)
```bash
$ pytest -v
======================= 461 passed, 1 warning in 9.85s ========================
```
- **契约与截断测试** (`tests/test_result_contract.py`): 9/9 全部通过。
- **真实 PCAP 回归测试** (`tests/test_real_pcap.py`): 6/6 全部通过（驱动真实系统 `tshark`）。
- **安全与凭据提取测试** (`tests/test_security.py`): 5/5 全部通过。
- **威胁研判与语义测试** (`tests/test_threat.py`): 17/17 全部通过（含 DoS SYN-ACK 失败比例旁路与 SYN 截断传播测试）。
- **统计聚合与去重预算测试** (`tests/test_stats.py`): 24/24 全部通过（含数值归约、单行 6000 去重上限截断、跨组 50,000 全局预算测试）。
- **进程生命周期测试** (`tests/test_client.py`): 62/62 全部通过（含逐行字段消费、字节/行数熔断，以及取消操作主动 `kill` 与 `wait` 验证）。
- **服务端传输测试** (`tests/test_server.py`): 23/23 全部通过（含真实 stdio 握手、新版 HTTP 协议发现/列表/成功调用/失败调用、真实 HTTP 监听子进程测试）。
- **Skill 跨端分发一致性测试** (`tests/test_skill_distribution.py`): 4/4 全部通过（含 `--check` 成功与篡改报警测试）。

### 2.2 静态代码质量与类型检查 (100% 通过)
- **代码格式化 (`ruff format --check`)**：
  ```bash
  $ ruff format --check src/ tests/ scripts/
  94 files already formatted
  ```
- **代码检查 (`ruff check`)**：
  ```bash
  $ ruff check src/ tests/ scripts/
  All checks passed!
  ```
- **类型检查 (`mypy`)**：
  ```bash
  $ mypy src/
  Success: no issues found in 54 source files
  $ mypy --package wireshark_mcp --ignore-missing-imports --no-namespace-packages
  Success: no issues found in 54 source files
  ```
- **字节码编译检查 (`compileall`)**：
  ```bash
  $ python -m compileall src/
  Listing 'src/'...
  ```
- **Skill 文档镜像同步检查 (`sync_skills.py --check`)**：
  ```bash
  $ python scripts/sync_skills.py --check
  All skills and manifests are in sync.
  ```

---

## 3. 打包与全新环境安装验收

使用 `uv build` 构建正式 wheel 与源码分发包，并在独立的干净虚拟环境中安装验收：

1. **构建输出**：`dist/wireshark_mcp-3.0.0-py3-none-any.whl`、`dist/wireshark_mcp-3.0.0.tar.gz`
2. **SHA256 校验和**：
   ```text
   ea35aed97970595ae67026681a226934711c3e7aec97fdff5605e82acd29fe65  dist/wireshark_mcp-3.0.0-py3-none-any.whl
   ```
3. **独立环境安装**：
   ```bash
   uv venv .venv_test
   uv pip install --python .venv_test/bin/python dist/wireshark_mcp-3.0.0-py3-none-any.whl
   # Installed 30 packages successfully
   ```
4. **入口验证**：
   - CLI 二进制：`.venv_test/bin/wireshark-mcp --version` 输出 `wireshark-mcp 3.0.0`
   - Python 模块化入口：`.venv_test/bin/python -m wireshark_mcp --version` 输出 `wireshark-mcp 3.0.0`
   - 诊断模式：`.venv_test/bin/wireshark-mcp doctor --format json` 成功输出有效 JSON，正确检测所有 Wireshark 工具与客户端配置。
   - 新版 HTTP：从安装后的 wheel 发起 `server/discover`、`tools/list` 与 `tools/call` 无状态请求，严格返回 `2026-07-28`，且不生成 Session ID。
   - 源码一致性：wheel 内 54 个 Python 源文件与最终工作区逐文件 SHA256 一致，并包含 `wireshark-traffic-analysis` Skill。
5. **环境清理**：测试临时虚拟环境已安全移除。

---

## 4. 验收对照矩阵

| 目标分类 | 历史问题 / 痛点 | 3.0 正式版最终交付 | 验证方式 |
|---|---|---|---|
| **契约** | 超长错误响应降级破坏 JSON，丢失 MCP 协议级 `is_error` | 优雅收缩字段生成合规 JSON 错误信封，截断前锁定 `is_error = True` | `test_result_contract.py` |
| **契约** | 输出截断时分页覆盖全局 `total` 且 `next_offset` 漂移 | 保留原全局 `total`，递增更新 `next_offset = offset + returned` | `test_result_contract.py` |
| **语义** | 子查询失败仍输出正常结论，零数据误当无攻击 | 显式跟踪 `failed_checks`，标记 `partial` 覆盖并降为 `candidate` | `test_threat.py` |
| **语义** | SYN-ACK 查询失败仍被置 0 参与比例计算，输出错误证据 | 将失败置为未知，跳过比例计算与断言，仅报告独立 SYN 速率并传播截断状态 | `test_threat.py` |
| **资源** | 单行多值绕过去重上限，小分组撑爆内存 | 逐项插入核验上限（5,000）+ 全局去重总预算（50,000） | `test_stats.py` |
| **安全** | 取消或异常时非流式读取路径残留僵尸子进程 | 流式与普通路径全面执行 `proc.kill()` 与 `await proc.wait()` | `test_client.py` |
| **传输** | HTTP 验收缺少新协议工具执行与真实监听进程测试 | 覆盖新版协议发现/列表/执行成功与失败，并运行真实监听子进程套接字测试 | `test_server.py` |
| **生态** | `sync_skills.py` 缺少 `--check` 参数，无法提供只读检查证据 | 补充 `--check` 支持与自动化单元测试，通过 CI 门禁核验 | `test_skill_distribution.py` |
| **文档** | 兼容性文档记录版本与 CI 实际安装版本不一致 | 将 Windows 记录精确对齐为 Chocolatey 4.6.8 | `docs/compatibility-matrix.md` |
| **发布** | Wheel 包缺少确定校验和与干净安装验证 | 构建 Wheel 并记录 SHA256，在隔离环境验证 `--version`、`-m` 和 `doctor` | 真实构建与运行 |
