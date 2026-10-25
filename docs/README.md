# Documentation

[中文版](README_zh.md)

Start with the page that matches the task at hand.

## Use Wireshark MCP

| Need | Guide |
|------|-------|
| Install automatically or diagnose an install | Run `wireshark-mcp install` and `wireshark-mcp doctor` from the main [README](../README.md) |
| Preview, scope, update or remove client registration | [Installation lifecycle](installation.md) |
| Install as a Codex/Claude Code plugin | [Plugin distribution](plugin-installation.md) |
| Configure an MCP client by hand | [Manual configuration](manual-configuration.md) |
| Look up an optional extra, environment variable or limit | [Configuration reference](configuration.md) |
| Run locally, over SSH, in WSL, or in a container | [Deployment scenarios](deployment-scenarios.md) |
| Migrate a 2.x deployment safely | [3.0 security migration](security-hardening-v3.md) |
| Ask better packet-analysis questions | [Prompt examples](prompt-engineering.md) |
| Compute capture-wide counts and distributions | [Aggregation guide](aggregation.md) |
| Read detector findings and keep investigation case files | [Findings and cases](findings-and-cases.md) |
| Index a large capture once and query it with DuckDB | [Capture index](capture-index.md) |
| Check supported operating systems, clients and tshark versions | [Compatibility matrix](compatibility-matrix.md) |

## Maintain the project

| Need | Guide |
|------|-------|
| Understand registration, execution, limits, and security boundaries | [Architecture](architecture.md) |
| Set up a development environment or submit a change | [Contributing](../CONTRIBUTING.md) |
| Validate macOS, Linux, and Windows | [Platform validation](platform-validation.md) |
| Prepare a release | [Release checklist](release-checklist.md) |
| Discover and use packet-analysis skills | [Skills](skills.md) |
| Evaluate Agent packet-analysis behavior | [Agent evaluation suite](agent-evaluation.md) |
| See how Agents scored on each analysis path | [Agent evaluation results](agent-evaluation-results.md) |
| Compare MCP with native tshark | [Analysis-path benchmark](analysis-path-benchmark.md) |
| Review shipped and planned work | [Changelog](../CHANGELOG.md) · [Roadmap](../ROADMAP.md) |
| Report a vulnerability | [Security policy](../SECURITY.md) |

Superseded release announcements and walkthroughs are kept in [archive/](archive/README.md). They explain past decisions but do not describe the current CLI or tool surface. Raw benchmark and evaluation results live in [benchmarks/](benchmarks/).
