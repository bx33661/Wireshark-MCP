# Documentation

[中文版](README_zh.md)

Start with the page that matches the task at hand.

## Use Wireshark MCP

| Need | Guide |
|------|-------|
| Install automatically or diagnose an install | Run `wireshark-mcp install` and `wireshark-mcp doctor` from the main [README](../README.md) |
| Configure an MCP client by hand | [Manual configuration](manual-configuration.md) |
| Run locally, over SSH, in WSL, or in a container | [Deployment scenarios](deployment-scenarios.md) |
| Migrate a 2.x deployment safely | [3.0 security migration](security-hardening-v3.md) |
| Ask better packet-analysis questions | [Prompt examples](prompt-engineering.md) |
| Compute capture-wide counts and distributions | [Aggregation guide](aggregation.md) |

## Maintain the project

| Need | Guide |
|------|-------|
| Understand registration, execution, limits, and security boundaries | [Architecture](architecture.md) |
| Set up a development environment or submit a change | [Contributing](../CONTRIBUTING.md) |
| Validate macOS, Linux, and Windows | [Platform validation](platform-validation.md) |
| Prepare a release | [Release checklist](release-checklist.md) |
| Evaluate Agent packet-analysis behavior | [Agent evaluation suite](agent-evaluation.md) |
| Compare MCP with native tshark | [Analysis-path benchmark](analysis-path-benchmark.md) |
| Review shipped and planned work | [Changelog](../CHANGELOG.md) · [Roadmap](../ROADMAP.md) |
| Report a vulnerability | [Security policy](../SECURITY.md) |

Files under `docs/superpowers/` are historical design and implementation records. They explain past decisions but do not define the current CLI or tool surface.
