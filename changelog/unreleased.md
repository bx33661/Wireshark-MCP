# Unreleased

## English

### Fixed

- Line-oriented tool results (packet lists, field extraction, stream follows) are now capped by dropping the tail instead of removing a block from the middle. `WIRESHARK_MCP_MAX_RESULT_CHARS` used to cut these strings head-plus-tail, so the rows in between were unreachable by any later page while the tool's own footer still advertised the requested page size (a `limit=500` page reported `Showing 500/5131 lines` while delivering 143 rows with frames 496–499 appended). A capped page is now a contiguous prefix and ends with an explicit `[... N more withheld ...]` marker, so `offset + returned` is the correct next offset.
- `wireshark_decrypt_wpa` built its `80211_keys` UAT entry as a single field (`uat:80211_keys:"wpa-pwd:<pass>:<ssid>",1`), which every tested tshark rejects with `80211_keys:1: invalid value` before any dissection happens, so the tool failed for every passphrase and SSID. It now emits the two columns tshark expects: `uat:80211_keys:"wpa-pwd","<pass>:<ssid>"`. Verified on Wireshark/TShark 4.6.10 (Windows): the old form exits 1, the new form exits 0.
- `wireshark_case` stores cases under the first *writable* allowed directory, so a read-only evidence mount listed first (the container's `/captures,/results` layout) no longer receives case writes.

### Distribution

- The container image and the Codex / Claude Code plugin launchers now include the `[index]` extra. The image keeps indexes in `/index` (`WIRESHARK_MCP_INDEX_DIR`).

### Documentation

- New [DeepSeek Harness integration](../docs/deepseek-harness.md) page recording how DSH mounts this server, the settings that actually matter there, and which MCP features its bridge does not forward. It is explicitly scoped to DSH 0.2.2-rc.5, the only version tested.
- New [configuration reference](../docs/configuration.md) listing every optional extra, server flag, environment variable (including the previously undocumented binary overrides and `GEOIP_DB_PATH`) and limit, and which install routes include extras.
- README: a "New in 4.0" section with upgrade notes, extras in the install section, a large-capture quick-start prompt, and links to the capture index, findings and installation guides.
- Architecture, contributing and security docs describe the capture index, findings and case files; the deployment guide shows the container's index volume and where case files go there.
- Prompt examples for capture-set diffs and case-file investigations; release checklist updated for the 4.x line and the PyPI/GHCR/Homebrew publish flow.
- Compatibility matrix, roadmap and benchmark pages updated for the 4.0.0 release. The 1.0 release announcement and the 3.0 walkthrough moved to `docs/archive/`.

## 中文

### 修复

- 面向行的工具输出（报文列表、字段提取、跟随流）改为丢弃尾部而不是从中间挖掉一段。`WIRESHARK_MCP_MAX_RESULT_CHARS` 过去按"头部+尾部"裁剪这类字符串，被挖掉的行无法通过任何后续分页取回，而工具自身的 footer 仍然宣称已达到请求的页大小（`limit=500` 的页面报 `Showing 500/5131 lines`，实际只给出 143 行并附带第 496–499 帧）。现在被裁剪的页面保持连续前缀，并在末尾给出明确的 `[... N more withheld ...]` 标记，`offset + returned` 即为正确的下一页偏移。
- `wireshark_decrypt_wpa` 把 `80211_keys` UAT 条目拼成单一字段（`uat:80211_keys:"wpa-pwd:<pass>:<ssid>",1`），实测的 tshark 版本都会在解析阶段以 `80211_keys:1: invalid value` 拒绝，任何口令与 SSID 都无法使用。现改为 tshark 期望的两列形式：`uat:80211_keys:"wpa-pwd","<pass>:<ssid>"`。已在 Wireshark/TShark 4.6.10（Windows）验证：旧形式退出码 1，新形式退出码 0。
- `wireshark_case` 把案卷存到第一个*可写*的允许目录，排在前面的只读证据挂载（容器中的 `/captures,/results` 布局）不再被用来写案卷。

### 分发

- 容器镜像和 Codex / Claude Code 插件启动器现已包含 `[index]` 扩展。镜像把索引存放在 `/index`（`WIRESHARK_MCP_INDEX_DIR`）。

### 文档

- 新增 [DeepSeek Harness 集成](../docs/deepseek-harness_zh.md) 页面，记录 DSH 如何挂载本服务器、哪些设置在那里真正重要、以及它的桥接不转发哪些 MCP 能力。页面明确限定在 DSH 0.2.2-rc.5——唯一测过的版本。
- 新增[配置参考](../docs/configuration_zh.md)，列出所有可选扩展、服务器参数、环境变量（包括此前未写入文档的程序路径覆盖和 `GEOIP_DB_PATH`）和上限，并说明各安装路线是否包含扩展。
- README：新增"4.0 新特性"及升级说明，安装部分加入扩展，快速开始加入大抓包示例，并链接抓包索引、发现模型和安装指南。
- 架构、贡献和安全文档补充抓包索引、发现模型与案卷；部署指南说明容器的索引卷，以及容器中案卷的存放位置。
- 提示词示例新增抓包集合 diff 和案卷调查；发布清单更新到 4.x 及 PyPI/GHCR/Homebrew 发布流程。
- 兼容性矩阵、路线图和基准页面按 4.0.0 更新。1.0 发布公告和 3.0 走查报告移入 `docs/archive/`。
