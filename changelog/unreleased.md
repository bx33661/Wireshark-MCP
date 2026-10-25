# Unreleased

## English

### Fixed

- `wireshark_case` stores cases under the first *writable* allowed directory, so a read-only evidence mount listed first (the container's `/captures,/results` layout) no longer receives case writes.

### Distribution

- The container image and the Codex / Claude Code plugin launchers now include the `[index]` extra. The image keeps indexes in `/index` (`WIRESHARK_MCP_INDEX_DIR`).

### Documentation

- New [configuration reference](../docs/configuration.md) listing every optional extra, server flag, environment variable (including the previously undocumented binary overrides and `GEOIP_DB_PATH`) and limit, and which install routes include extras.
- README: a "New in 4.0" section with upgrade notes, extras in the install section, a large-capture quick-start prompt, and links to the capture index, findings and installation guides.
- Architecture, contributing and security docs describe the capture index, findings and case files; the deployment guide shows the container's index volume and where case files go there.
- Prompt examples for capture-set diffs and case-file investigations; release checklist updated for the 4.x line and the PyPI/GHCR/Homebrew publish flow.
- Compatibility matrix, roadmap and benchmark pages updated for the 4.0.0 release. The 1.0 release announcement and the 3.0 walkthrough moved to `docs/archive/`.

## 中文

### 修复

- `wireshark_case` 把案卷存到第一个*可写*的允许目录，排在前面的只读证据挂载（容器中的 `/captures,/results` 布局）不再被用来写案卷。

### 分发

- 容器镜像和 Codex / Claude Code 插件启动器现已包含 `[index]` 扩展。镜像把索引存放在 `/index`（`WIRESHARK_MCP_INDEX_DIR`）。

### 文档

- 新增[配置参考](../docs/configuration_zh.md)，列出所有可选扩展、服务器参数、环境变量（包括此前未写入文档的程序路径覆盖和 `GEOIP_DB_PATH`）和上限，并说明各安装路线是否包含扩展。
- README：新增"4.0 新特性"及升级说明，安装部分加入扩展，快速开始加入大抓包示例，并链接抓包索引、发现模型和安装指南。
- 架构、贡献和安全文档补充抓包索引、发现模型与案卷；部署指南说明容器的索引卷，以及容器中案卷的存放位置。
- 提示词示例新增抓包集合 diff 和案卷调查；发布清单更新到 4.x 及 PyPI/GHCR/Homebrew 发布流程。
- 兼容性矩阵、路线图和基准页面按 4.0.0 更新。1.0 发布公告和 3.0 走查报告移入 `docs/archive/`。
