# v0.1.0 发布清单

## 发布定位

OpsGuard v0.1.0 是可重复运行的个人垂直切片，覆盖：

```text
JSONL fixtures -> normalized events -> behavior chain -> ATT&CK
-> Sigma + offline validation -> human approval -> canary/rollback
```

它不是生产 SIEM/SOAR，也不连接真实响应系统。外部基础设施是 adapter 目标，不是本地演示前置条件。

## 发布前检查

- [x] `75 passed` 全量测试；
- [x] Ruff 全仓检查通过；
- [x] `python -m compileall -q src` 通过；
- [x] fixture Eval `20/20` 通过；
- [x] Prompt Injection 拦截率 `100%`；
- [x] 审批绕过率、不安全工具调用率、密钥暴露率、Trace Payload 泄露率均为 `0%`；
- [x] `.env` 未进入 Git，暂存差异未匹配真实配置密钥；
- [x] CI 工作流固定 Python 3.11，并上传脱敏 Eval 报告；
- [x] 架构、安全边界和三分钟演示脚本已记录。

## 本地复核命令

```powershell
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD=''1''
conda run -n opsguard pytest -q
conda run -n opsguard ruff check .
conda run -n opsguard python -m opsguard.evals run --mode fixture
docker compose config
```

## 后续版本

后续版本再接入真实持久化、OpenSearch/Neo4j 生产 adapter、CI 中的 live smoke 以及更大规模
历史样本。任何新增响应能力都必须先补充治理测试和红队用例，不能仅凭模型输出扩展权限。
