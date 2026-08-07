# 安全审计与重构说明

审计对象：[`patrickhere/keys`](https://github.com/patrickhere/keys)，`main` 分支，审阅时间 2026-08-07。

## 审计范围

审阅了上游仓库的 Pages Functions、身份数据、HTML 渲染、公钥指纹、安装脚本、Wrangler 配置和 GitHub Actions。该上游项目只发布 SSH 公钥，不提供运行时管理后台；本项目是按相同使用场景重新设计和实现的独立代码库，而不是原仓库的直接扩展。

## 上游发现

### 中等风险

1. **缺少公钥结构与算法强度验证**

   上游 `_identities.js` 接受手工粘贴的任意字符串，`_render.js` 仅按空白拆分并对 Base64 解码后的字节求哈希。它没有验证 SSH wire-format 中的内层算法、字段长度、曲线、RSA 位数，也明确展示已废弃的 DSA。错误、截断或弱公钥可能被发布，并给用户造成已经验证的错觉。

2. **部署工具使用浮动版本**

   GitHub Actions 执行 `npx wrangler@latest`。部署结果会随上游包变化，且依赖供应链事件可直接影响生产发布。重构项目使用 lockfile 和精确版本，并要求 CI 使用 `npm ci`。

3. **`curl | sh` 缺少足够的风险提示**

   身份页将管道执行远程脚本标为推荐方式。任何域名、Cloudflare 账户、部署凭据或源码供应链被攻破，都可能转化为客户端命令执行。此风险无法由脚本本身完全消除。

4. **安装器临时文件和恢复能力有限**

   上游使用带 `$$` 的可预测临时文件名，并在替换 `authorized_keys` 前不创建备份。虽然 `.ssh` 通常为用户私有目录，仍应优先使用 `mktemp`、`trap` 和权限受限备份来增强数据完整性。

### 低风险

1. **CSP 允许内联 JavaScript**

   上游响应头包含 `script-src 'unsafe-inline'`。当前输出进行了 HTML 转义，未发现可直接利用的 XSS，但该策略会削弱未来代码变更时的纵深防御。

2. **安装器标记硬编码到特定域名**

   管理区块标记使用 `keys.hartforge.dev/<handle>`，与实际请求 Origin 分离。分叉或更换域名后容易出现重复管理区块，影响撤销语义。

3. **公钥撤销存在五分钟缓存窗口**

   `.keys` 和 `.sh` 使用 `public, max-age=300`。紧急删除后，缓存节点可能继续返回旧公钥。上游文档提到部署延迟，但这对撤销属于明确的安全权衡。

4. **缺少自动测试和安全依赖检查**

   上游没有验证指纹一致性、脚本幂等性、HTML 转义或路由边界的测试，也没有依赖审计步骤。

## 未发现的问题

- 上游公开数据均为 SSH 公钥，仓库中未看到对应私钥。
- 动态 HTML 字段经过实体转义，未发现直接存储型 XSS。
- SHA-256 指纹算法与 OpenSSH 通常格式一致。
- 安装脚本使用单引号 heredoc，公钥内容不会作为 shell 命令展开。
- 安全头包含 `nosniff`、`DENY` framing 和 `no-referrer`。

## 重构后的控制措施

| 风险边界 | 控制措施 |
| --- | --- |
| 私钥泄露 | 产品中不存在私钥字段或导入入口；多行及私钥头会被拒绝 |
| 弱或伪造公钥 | 解析 SSH 二进制字段，校验内外算法、字段长度、曲线和 RSA 最低位数 |
| 管理员认证 | 高熵 Secret、HMAC 会话、HttpOnly/Secure/Strict Cookie、8 小时有效期 |
| 暴力破解 | 按 HMAC 隐私化 IP 在 D1 中记录失败并指数退避 |
| CSRF | 所有管理写请求要求有效会话和与 URL 完全一致的 `Origin` |
| XSS | 服务器端转义；脚本为同源外部资源；严格 CSP 无 `unsafe-inline` |
| SQL 注入 | 所有动态值通过 D1 prepared statements 绑定 |
| 撤销延迟 | 动态公开响应使用 `Cache-Control: no-store` |
| 审计隐私 | 记录动作、目标和 HMAC actor hash，不保存原始 IP 或管理员口令 |
| 安装器完整性 | 安全 Handle、受引号保护 heredoc、`mktemp`、`trap`、原子替换和本地备份 |
| 供应链 | 精确依赖版本、package-lock、`npm audit`、Worker 和 Pages 双目标构建检查 |

## 剩余风险

1. 单一共享管理员口令没有用户级归因、MFA 或细粒度 RBAC。建议在 Cloudflare Access 中启用身份提供商与 MFA。
2. D1 限流按 IP 生效，无法完全阻止分布式攻击。建议叠加 Cloudflare WAF Rate Limiting。
3. 会话是无状态签名 Cookie。退出只清理当前浏览器 Cookie；轮换 `SESSION_SECRET` 才会立即注销所有会话。
4. 审计日志与业务数据位于同一个 D1 数据库，拥有数据库管理权限的攻击者可以修改日志。高保证环境应把日志同步到不可变外部系统。
5. `.sh` 端点仍属于远程代码执行供应链。用户必须先审阅脚本，并保护 DNS、Cloudflare 账户、部署 Token 和源代码仓库。
6. 公钥本身虽非秘密，但会暴露身份、设备标签和密钥关联。敏感身份应设为隐藏；隐藏不是加密，管理员仍可在 D1 中读取。

## 建议验证周期

- 每次提交执行 `npm run check`、`npm audit` 和两个 Cloudflare 构建目标。
- 每月复查 npm 与 Cloudflare 安全公告。
- 每季度测试 D1 恢复、管理员 Secret 轮换和公钥紧急撤销流程。
- 每次修改安装器后，在隔离 HOME 中验证添加、重复执行、撤销、保留非管理区公钥和备份恢复。
