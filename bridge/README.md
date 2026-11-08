# Release 通知桥

独立 Node 22 服务：验证 GitHub 原始 Release webhook，持久化 delivery 去重和 outbox，再向 registry 发送 `pack-released`。它不相信 webhook 的包 URL/摘要，不自己批准收录，不运行作者脚本；可信 sync 重新抓取已登记来源。

## 部署

实现及外部配置清单见 [索引服务模块](../../../docs/bepack-索引服务模块.md)。从 registry 根构建：

```sh
docker build -f bridge/Dockerfile -t bepack-registry-bridge .
docker volume create bepack-registry-bridge-data
docker run -d --name bepack-registry-bridge --restart unless-stopped \
  --env-file /secure/bepack-registry-bridge.env \
  -v bepack-registry-bridge-data:/data -p 127.0.0.1:8787:8787 \
  bepack-registry-bridge
```

镜像为非 root，卷必须对运行用户可写；不要因此把数据目录设成公开可写。上面是部署命令示例，本次没有运行 Docker 或实际部署。用反向代理提供 HTTPS、请求限流/超时，GitHub webhook URL 为 `https://YOUR_HOST/webhooks/github`。仓库根 `.gitignore` 排除私密 env、bridge-data；只提交 [.env.example](.env.example)。私钥支持用字面量 `\n` 编码 PEM 换行。

两个 GitHub App 必须分开：Notifier 只装作者仓库，Contents read / Metadata read + Release events；Registry writer 只装官方 registry，Contents write / Pull requests write / Metadata read。服务使用 Notifier 查验作者 installation ID，用 writer 给官方仓库 dispatch；同 App ID 拒绝启动。作者只安装只读 Notifier，不保管任何官方凭证。

## 响应与监控

- `GET /healthz`：200 和 pending 数量；仅证明存储可访问、进程存活，不是外部 GitHub/VT 深度健康检查。
- `POST /webhooks/github`：先验证 `X-Hub-Signature-256`，拒绝缺失/错误签名；最多 1 MiB 原始 body，不让代理 JSON 重编码。
- 202 表示 durable accepted/duplicate，不表示 Release 已通过审核。204 为忽略事件；400 载荷问题；401 签名问题；403 私有仓库或 installation 不匹配；503 installation 查询暂不可用。
- worker 指数退避并持久保留失败 outbox，投递为 at-least-once。监控 pending 积压、dispatch失败日志、磁盘满和最近一次6小时补偿任务结果。日志不打印私钥、完整请求体或 token。

## 持久化与恢复

只能运行**一个副本/进程**。`state.json` 使用串行 mutation + 临时文件 rename；无跨进程锁、事务数据库或 fsync 断电保证。不要多容器共享此文件。delivery 去重和已完成条目保留7天；未完成条目不按7天丢弃。即使超过去重期再次投递，registry不可变记录和同步幂等仍防止重复版本。

备份整个持久卷，恢复前停止唯一实例；损坏JSON启动失败，不清空后假装成功。恢复完成后手动执行 registry-sync 全量补偿，不以备份后的 delivery 遗漏为永久丢单理由。多副本需求应先替换事务 outbox，而不是简单增加 replicas。

轮换 webhook secret 与两个 App 私钥时安排停机/双端协调并演练重投；当前没有双 secret 过渡支持。撤销 App 或故障的补偿依赖6小时同步及人工重试，不承诺事件准时SLA。SIGTERM/SIGINT停止worker并排空HTTP，10秒后强制退出；重启通过持久outbox继续处理。