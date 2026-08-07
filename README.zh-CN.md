# Cloud Keyring

[English](README.md) | [简体中文](README.zh-CN.md)

一个面向 Cloudflare Workers、Pages Functions 和 D1 的安全、自托管 SSH **公钥**目录。

Cloud Keyring 提供受保护的网页管理后台、公开身份页、原始 `.keys` 端点，以及幂等的 `authorized_keys` 同步脚本。

> Cloud Keyring 永远不需要、也不接受 SSH 私钥。若私钥曾被提交到网站、数据库或 Git 仓库，请立即视为泄露并进行轮换。

## 功能

- 通过网页后台创建、修改、隐藏和删除身份
- 添加、验证、发布和撤销 SSH 公钥
- 支持 ED25519、RSA 2048 位以上、NIST ECDSA 和 OpenSSH FIDO2 公钥
- 验证 SSH wire format，并计算与 OpenSSH 兼容的 `SHA256:` 指纹
- 在 `/<handle>` 提供响应式身份和指纹页面
- 在 `/<handle>.keys` 提供标准 `authorized_keys` 公钥行
- 在 `/<handle>.sh` 提供幂等同步脚本
- 使用 D1 保存身份、公钥、登录限流状态和审计事件
- 同一套应用核心可以部署到 Cloudflare Workers 或 Pages Functions
- 强制启用严格安全响应头、同源检查、签名会话和撤销不缓存策略

## 端点

| 端点 | 用途 |
| --- | --- |
| `/` | 公开身份目录 |
| `/<handle>` | 展示公钥元数据和指纹的身份页面 |
| `/<handle>.keys` | 原始 SSH 公钥，每行一把 |
| `/<handle>.sh` | 幂等 `authorized_keys` 同步脚本 |
| `/admin` | 受口令保护的管理后台 |
| `/api/*` | 需要认证的管理 API |

## 安装器行为

生成的安装器只管理一个身份对应的区块：

```text
# >>> cloud-keyring/alice >>>
ssh-ed25519 AAAA... alice-laptop
# <<< cloud-keyring/alice <<<
```

修改 `authorized_keys` 前会创建备份：

```text
~/.ssh/authorized_keys.keyring.bak
```

公钥去重使用以下身份：

```text
算法 + Base64 公钥主体
```

注释、空白以及受支持的 `authorized_keys` options 不会让重复公钥被视为不同。例如下面三行会被识别为同一把公钥：

```text
ssh-ed25519 AAAAC3... old-comment
ssh-ed25519 AAAAC3... new-comment
restrict ssh-ed25519 AAAAC3... option-comment
```

安装器会删除管理区块外的等价副本，只写入一次当前发布版本，保留不相关公钥和注释，并且重复运行保持幂等。

不同 Handle 的管理区块相互独立。从一个身份撤销公钥，不会删除另一个身份有意发布的相同公钥。

## 安全模型

- D1 只保存公钥和展示元数据，不保存私钥。
- `ADMIN_PASSWORD` 和 `SESSION_SECRET` 使用 Cloudflare Secrets，不作为源码变量提交。
- 会话使用 HMAC 签名，以及有效期 8 小时的 `HttpOnly; Secure; SameSite=Strict` Cookie。
- 每个管理写操作都要求有效会话以及与请求 URL 完全同源的 `Origin`。
- 登录失败按照客户端 IP 的隐私化 HMAC 哈希进行限流。
- 审计事件保存操作和执行者哈希，不保存原始 IP 或口令。
- 公钥按照 SSH 二进制结构解析。解析器拒绝 DSA、低于 2048 位的 RSA、私钥、多行输入、错误编码以及内外算法不一致的密钥。
- 动态 HTML 全部转义，Content Security Policy 不允许内联脚本。
- 公开身份、`.keys` 和 `.sh` 响应使用 `Cache-Control: no-store`，避免边缘缓存继续提供已撤销公钥。
- 安装器使用 `mktemp`、`trap`、严格权限、本地备份和原子替换。

内置的单管理员登录适合个人部署或小型可信团队。生产环境建议额外使用 Cloudflare Access 和 MFA 保护 `/admin*` 与 `/api/*`。

上游审计、已实施控制和剩余风险见 [SECURITY_AUDIT.md](SECURITY_AUDIT.md)。

## 环境要求

- Node.js 22 或更高版本
- Cloudflare 账户
- 如需自定义域名，需要由 Cloudflare 管理的 Zone
- 通过 `npx wrangler login` 登录 Wrangler，或在 CI 中配置有限权限的 API Token

安装依赖：

```sh
npm install
```

## 配置

部署 Fork 前，请将 Wrangler 配置中的 Worker 路由和 D1 标识替换为自己 Cloudflare 账户中的资源。D1 ID 是资源标识符而非凭据。

### 创建 D1

```sh
npx wrangler d1 create cloud-keyring
```

将返回的 `database_id` 写入以下两个文件：

- `wrangler.worker.toml`
- `wrangler.toml`

绑定名称必须保持为 `DB`。

### 配置 Worker 域名

修改 `wrangler.worker.toml`：

```toml
workers_dev = false

[[routes]]
pattern = "keys.example.com"
custom_domain = true
```

部署时 Cloudflare 会自动创建 DNS 记录和证书。该主机名必须属于同一 Cloudflare 账户中的有效 Zone，并且不能存在冲突的 CNAME 记录。

### 配置本地 Secret

将 `.dev.vars.example` 复制为 `.dev.vars`，并设置两个相互独立的高熵值：

```dotenv
ADMIN_PASSWORD="至少 16 个随机字符"
SESSION_SECRET="至少 32 个不同的随机字符"
SITE_NAME="Cloud Keyring"
```

可以通过以下命令生成：

```sh
openssl rand -base64 32
openssl rand -base64 48
```

`.dev.vars` 已被 Git 忽略，绝对不要提交它。

## 本地开发

应用本地迁移并启动 Worker 开发服务器：

```sh
npm run db:migrate:local
npm run dev
```

访问 `http://localhost:8787/admin`。本地数据保存在 `.wrangler/` 下的 Wrangler 本地 D1 状态中。

运行全部检查：

```sh
npm run check
npm audit
```

安装器测试会在隔离的临时 `HOME` 中使用 `/bin/sh` 执行生成脚本，覆盖忽略注释的去重、受支持 options、幂等执行，以及完全撤销但不删除无关条目的场景。

## 部署到 Workers

应用远程迁移：

```sh
npm run db:migrate:worker
```

设置生产 Secret：

```sh
npx wrangler secret put ADMIN_PASSWORD -c wrangler.worker.toml
npx wrangler secret put SESSION_SECRET -c wrangler.worker.toml
```

部署 Worker 和自定义域名：

```sh
npm run deploy:worker
```

验证部署：

```sh
curl -I https://keys.example.com/
curl -fsSL https://keys.example.com/alice.keys
curl -fsSL https://keys.example.com/alice.sh
```

## 部署到 Pages

创建名为 `cloud-keyring` 的 Pages 项目，然后应用 D1 迁移：

```sh
npm run db:migrate:pages
```

设置 Pages Secret：

```sh
npx wrangler pages secret put ADMIN_PASSWORD --project-name cloud-keyring
npx wrangler pages secret put SESSION_SECRET --project-name cloud-keyring
```

部署静态输出和 Pages Function：

```sh
npm run deploy:pages
```

通过 Cloudflare Dashboard 连接 Git 仓库时，构建命令留空，输出目录设置为 `public`，并为相同数据库配置名为 `DB` 的 D1 绑定。自定义域名从 Pages 项目设置中添加。

## 使用

访问 `/admin`，创建身份，然后粘贴一整行 OpenSSH 公钥：

```text
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... device-name
```

最后一段是注释，可以修改而不会改变公钥指纹。算法和 Base64 主体不能修改。

获取已发布公钥：

```sh
curl -fsSL https://keys.example.com/alice.keys
```

执行前先审阅安装器：

```sh
curl -fsSL https://keys.example.com/alice.sh
```

确认 HTTPS 域名和脚本内容后执行：

```sh
curl -fsSL https://keys.example.com/alice.sh | sh
```

运行远程 Shell 代码属于供应链决策。请先审阅脚本，并保护域名、Cloudflare 账户、部署凭据和源码仓库。

## 运维

- 管理员权限变化时，使用 `wrangler secret put` 轮换 `ADMIN_PASSWORD`。
- 轮换 `SESSION_SECRET` 可以立即注销全部现有登录会话。
- 撤销公钥后，检查 `/<handle>.keys`，并在每台目标机器上重新运行安装器。
- 备份 D1，并定期测试恢复流程。
- 为管理端点启用 Cloudflare Access、MFA、WAF 规则和速率限制。
- 通过管理后台检查审计事件。
- 绝对不要提交 `.dev.vars`、API Token、管理员口令、Cookie 值或私钥。

## 项目结构

```text
functions/              Pages Functions 入口
migrations/             D1 SQL 迁移
public/                 Pages 静态输出和路由配置
src/app.ts              HTTP 路由、认证、CRUD 和安装器
src/security.ts         会话、常量时间比较和隐私哈希
src/ssh.ts              SSH 公钥解析和指纹
src/views.ts            服务端 HTML
src/worker.ts           Workers 入口
test/                   安全、SSH 解析和 Shell 安装器测试
wrangler.toml           Pages 配置
wrangler.worker.toml    Workers 和自定义域名配置
```

## 致谢

产品方向受到 [patrickhere/keys](https://github.com/patrickhere/keys) 启发，该项目是通过源码管理的 SSH 公钥身份站点。Cloud Keyring 是独立重写实现，增加了 D1 运行时管理、更严格的公钥验证、认证管理后台、审计事件和强化的安装器行为。
