# Agent Memory Security Lab

一个面向 AI Agent 长期记忆的安全攻防实验库。项目用确定性 Python 实现复现攻击链的核心理论，比较“脆弱基线”与“加固配置”，适合本地研究、回归测试和 CI 安全门禁。

> 安全边界：所有工具调用都是本地模拟；载荷只使用假域名、假凭证和 canary；不扫描网络、不执行 shell、不外传数据。

## 已实现方法

| Case | 核心理论 | 防御控制 | 参考分类 |
|---|---|---|---|
| `direct_override` | 将行为指令持久化为记忆，并在后续会话召回 | 写入风险评分、隔离区 | OWASP ASI06 / MITRE ATLAS Context Poisoning |
| `indirect_document` | 外部文档携带间接指令并进入长期记忆 | 来源信任、行为指令检测 | Prompt Injection / Memory Poisoning |
| `cross_namespace` | 租户或用户命名空间混淆导致跨域召回 | 强制 namespace 过滤 | Cross-user Contamination |
| `conflict_overwrite` | 低信任新记录覆盖已确认事实 | 冲突检测、确认升级 | Memory Integrity |
| `stale_memory` | 已过期事实继续影响决策 | TTL、读取时过期检查 | Stale Memory Object |
| `unicode_obfuscation` | 零宽字符隐藏行为指令 | Unicode 规范化、控制字符检测 | Obfuscated Injection |

框架参考：

- [MITRE ATLAS](https://atlas.mitre.org/)
- [OWASP Agentic AI Threats and Mitigations](https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/)
- [OWASP Agent Memory Guard](https://owasp.org/projects/agent-memory-guard)
- [NIST AI RMF Generative AI Profile](https://www.nist.gov/itl/ai-risk-management-framework)

## 快速开始（Windows PowerShell）

无需第三方运行时依赖：

```powershell
& 'D:\Python\Python314\python.exe' -m unittest discover -s tests -v
$env:PYTHONPATH = 'src'
& 'D:\Python\Python314\python.exe' -m amslab.cli list
& 'D:\Python\Python314\python.exe' -m amslab.cli run --profile both --output reports\latest.json
```

也可以安装到项目本地虚拟环境：

```powershell
& 'D:\Python\Python314\python.exe' -m venv .venv
& '.\.venv\Scripts\python.exe' -m pip install -e .
& '.\.venv\Scripts\amslab.exe' run --profile both
```

## 结果含义

- `write_active`：恶意候选是否成为活跃记忆。
- `recalled`：后续会话是否召回该对象。
- `behavior_influenced`：召回结果是否改变 Agent 行为。
- `tool_attempted`：污染记忆是否诱导工具调用。
- `forbidden_executed`：禁止动作是否真正执行；本实验的模拟网关始终应为 `false`。
- `attack_succeeded`：该案例定义的安全属性是否被突破。

“脆弱基线”用于证明测试可以捕获问题，不代表推荐配置。“加固配置”通过来源标签、写入筛查、冲突检测、TTL、命名空间隔离和工具最小权限形成纵深防御。

## 扩展新案例

1. 在 `src/amslab/cases.py` 注册案例元数据。
2. 在 `src/amslab/runner.py` 实现隔离、注入、跨会话触发和判定逻辑。
3. 为脆弱基线和加固配置分别添加断言。
4. 载荷必须使用 `.invalid` 域名和 `CANARY_` 前缀假数据；真实工具只能通过独立适配器接入，并默认禁用。

更完整的威胁模型见 [`docs/threat-model.md`](docs/threat-model.md)。

