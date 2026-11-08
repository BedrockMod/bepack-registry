# bepack-registry

BePack 来源登记、Release 独立复验与版本索引仓库。本仓库只保存索引、验证记录和桥接服务代码，不托管 `.bepack`、插件或游戏本体。

## 当前状态

已实现可离线测试的验证器、记录/撤回模型、内容寻址 catalog 生成器、四个 GitHub Actions 工作流、`pack-released` 签名 Webhook 桥和 JSON Schema。`npm test` 与空仓库 smoke 可在本地通过。

尚未部署 GitHub App、Actions Secrets、Webhook 主机、VirusTotal 生产凭证或 catalog Pages/镜像；`catalog` 分支、自动合并和生产端到端收录尚未实际运行。因此不要对外宣称索引服务已经上线。

## 数据与代码

- `sources/`：人工审核的包来源，一包一个文件。
- `releases/`：可信验证器生成的不可变版本记录，不接受作者自报扫描通过。
- `withdrawals/`：追加的撤回、隔离或恢复状态，不覆盖原始摘要。
- `schemas/`：source、release-record、withdrawal、registry、pack-history 的 JSON Schema。
- `lib/`：严格 JSON、路径、ZIP、包/锁复验、GitHub API、VirusTotal、Release 复验、记录、catalog、同步。
- `scripts/`：PR 检查、Release 复验、同步、catalog 构建、App token、Bot PR、空仓库 smoke。
- `bridge/`：接收 GitHub `release` Webhook、验签、持久化去重并发送 `pack-released` 的独立服务。
- `.github/workflows/`：`registry-check`、`registry-verify`、`registry-sync`、`registry-publish`。

## 最短验证

```powershell
cd D:\CopperGolem\Bepack\bepack-registry
npm ci --ignore-scripts --no-audit --no-fund
npm test
node scripts/smoke.mjs
node scripts/check-pr.mjs --offline --base origin/main
```

预期退出码均为 0。当前空仓库 smoke 输出 `packs=0`、`details=0`、`registry_bytes=177`。完整命令、缺失配置和退出码见 [索引服务模块](../../docs/bepack-索引服务模块.md)。

## 信任边界

1. 作者仓库、Release 资产和扫描报告都不可信；`registry-sync` 重新读取仓库、Tag、Release、资产 ID 和实际字节，并自己计算 SHA-256。
2. VirusTotal 具体 Analysis 必须为 `completed`，并独立查询 `/analyses/{id}/item` 绑定文件 SHA；文件和分析均零恶意/可疑且有有效引擎结果，作者报告不能替代独立查询。
3. 同包同版本出现资产 ID、Tag commit、大小或摘要变化时进入隔离，不重绑新摘要；删除 Release 只标记 unavailable。
4. 普通新增版本可由 Bot 生成 PR，但合并前必须通过 `registry-check` 和运行可信 base 代码的 `registry-verify`；来源转移、工具升级、策略变更和解除隔离始终人工审核。
5. `catalog` 只包含 `registry.json` 和内容寻址的 `packs/<sha256>.json`，不包含包体或可执行组件。

## 文档

- [收录指南](docs/收录指南.md)
- [运维与撤回](docs/运维与撤回.md)
- [索引服务模块](../../docs/bepack-索引服务模块.md)
- [工坊后端对接契约](../../docs/bepack-工坊后端对接契约.md)
- [仓库设计](../../docs/bepack-registry-仓库设计.md)

## 限制

仓库尚未确定开源许可，不默认授权。作者工作流不得持有官方写凭证；通知 App 与发布 Bot App 必须分离。所有外部配置和未验证风险见索引服务模块文档。
