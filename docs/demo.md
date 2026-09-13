# OpsGuard 三分钟演示脚本

## 0:00-0:30 说明问题与边界

打开工作台首页，说明 OpsGuard 处理的是多源事件到调查结论的闭环：搜索、检测、行为链、
ATT&CK、Sigma、沙箱和人工审批。强调响应适配器是模拟的，不会触碰真实生产主机。

## 0:30-1:20 调查可疑 SSH 行为

在问题框输入：`调查新来源 SSH 登录后的可疑行为`，点击开始调查。

展示以下结果：

- 事件列表包含 `evt-ssh-001` 到 `evt-ssh-003`，来源为 Linux audit；
- 行为链从新来源登录连接到 `curl` 下载和 `crontab` 持久化；
- ATT&CK 映射显示技术编号、证据事件和置信度；
- Sigma 候选已完成离线验证，但治理状态仍是 `awaiting_approval`；
- “Agent 观测”中可看到结构化计划、固定工具链、模型/Trace 元数据，而看不到 Prompt 和日志正文。

## 1:20-2:10 演示人工确认与回滚边界

先拒绝一次审批，展示不会执行响应、规则不会进入 Active。再次运行调查并提交带健康指标的
审批，展示规则经过 Canary 后进入 Active，审计记录保留 actor、scope、reason 和时间。

使用超阈值误报率的 Canary 指标再次演示，展示状态转为 `rolled_back`，而不是继续发布。

## 2:10-2:40 演示反馈飞轮

对一个命中事件提交误报或漏报反馈，点击候选规则优化。展示新版本与旧版本的离线指标对比，
并说明候选必须重新验证和审批，反馈不会直接改线上规则。

## 2:40-3:00 演示评测与工程门禁

在终端运行：

```powershell
conda run -n opsguard python -m opsguard.evals run --mode fixture
```

展示 `20/20 cases passed` 和安全指标：Prompt Injection 100%、审批绕过 0%、不安全工具调用
0%、敏感信息泄露 0%、Trace Payload 泄露 0%。最后打开 `docs/architecture.md` 说明 LLM 只负责
理解与规划，检测、验证、审批和生命周期始终由确定性代码控制。
