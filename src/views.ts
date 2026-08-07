import { keyTypeLabel } from "./ssh";
import type { IdentityRow, IdentityWithKeys } from "./types";

function escapeHtml(value: unknown): string {
  return String(value).replace(/[&<>"']/g, (character) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[character] ?? character,
  );
}

function layout(siteName: string, title: string, body: string, admin = false): string {
  return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light"><meta name="theme-color" content="#c8f135"><title>${escapeHtml(title)}</title><link rel="stylesheet" href="/assets/app.css"></head><body${admin ? ' class="admin-body"' : ""}>${body}<script src="${admin ? "/assets/admin.js" : "/assets/app.js"}" defer></script></body></html>`;
}

function mast(siteName: string): string {
  return `<header class="mast"><a class="brand" href="/"><span class="brand-mark">K</span>${escapeHtml(siteName)}</a><nav class="nav"><a href="/">目录</a><a href="/admin">管理</a></nav></header>`;
}

export function renderHome(siteName: string, identities: IdentityRow[]): string {
  const rows = identities
    .map((identity) => {
      const count = Number((identity as IdentityRow & { key_count?: number }).key_count ?? 0);
      return `<li><a class="identity-row" href="/${encodeURIComponent(identity.handle)}"><span class="arrow">↗</span><span><span class="identity-name">${escapeHtml(identity.name)}</span><span class="identity-meta"> @${escapeHtml(identity.handle)}</span></span><span class="identity-meta">${count} PUBLIC KEY${count === 1 ? "" : "S"}</span></a></li>`;
    })
    .join("");
  return layout(
    siteName,
    siteName,
    `<div class="shell">${mast(siteName)}<main><section class="hero"><div><div class="eyebrow">SSH PUBLIC KEY DIRECTORY / EDGE DEPLOYED</div><h1>公钥，保持可验证。</h1><p>集中发布 SSH 公钥，以稳定端点同步到服务器。这里永远不接收或存储私钥。</p></div><div class="hero-stat"><strong>${identities.length}</strong><span>PUBLIC IDENTITIES</span></div></section><section><div class="section-head"><span class="section-label">身份目录</span><span class="identity-meta">/<em>handle</em>.keys</span></div><ul class="identity-list">${rows || '<li class="empty">目前没有公开身份。</li>'}</ul></section></main><footer><span>${escapeHtml(siteName)} / Cloudflare edge</span><span>PUBLIC KEYS ONLY</span></footer></div>`,
  );
}

export function renderIdentity(siteName: string, identity: IdentityWithKeys, origin: string): string {
  const baseUrl = `${origin}/${encodeURIComponent(identity.handle)}`;
  const install = `curl -fsSL ${baseUrl}.sh | sh`;
  const raw = `curl -fsSL ${baseUrl}.keys`;
  const cards = identity.keys
    .map(
      (key) => `<article class="key-card"><div class="key-top"><span class="key-type">${escapeHtml(keyTypeLabel(key.key_type))}</span><span class="key-date">ADDED ${escapeHtml(key.added_at)}</span></div><h2>${escapeHtml(key.label || key.key_comment || "未命名公钥")}</h2><div class="comment">${escapeHtml(key.key_comment)}</div><div class="fingerprint"><span>SHA256 FINGERPRINT</span><code>${escapeHtml(key.fingerprint)}</code></div><button class="full-key copy" data-copy="${escapeHtml(key.public_key)}" title="复制完整公钥">${escapeHtml(key.public_key)}</button></article>`,
    )
    .join("");
  return layout(
    siteName,
    `${identity.name} · ${siteName}`,
    `<div class="shell">${mast(siteName)}<main><section class="profile"><div class="eyebrow">IDENTITY / <span class="handle">@${escapeHtml(identity.handle)}</span></div><h1>${escapeHtml(identity.name)}</h1>${identity.description ? `<p class="description">${escapeHtml(identity.description)}</p>` : ""}</section><section><div class="section-head"><span class="section-label">同步到 authorized_keys</span><span class="identity-meta">${identity.keys.length} KEYS</span></div><div class="command-block"><div class="command"><span>$</span><code>${escapeHtml(install)}</code><button class="copy" data-copy="${escapeHtml(install)}">复制</button></div><p class="warning">执行 curl | sh 前请先访问 .sh 端点审阅脚本；也可使用下方只读 .keys 命令。</p><div class="command"><span>$</span><code>${escapeHtml(raw)}</code><button class="copy" data-copy="${escapeHtml(raw)}">复制</button></div></div></section><section><div class="section-head"><span class="section-label">已授权公钥</span><a class="identity-meta" href="/${encodeURIComponent(identity.handle)}.keys">查看原始数据 ↗</a></div><div class="key-grid">${cards || '<p class="empty">该身份尚无公钥。</p>'}</div></section></main><footer><span>${escapeHtml(siteName)} / @${escapeHtml(identity.handle)}</span><span>FINGERPRINTS COMPUTED ON INGEST</span></footer></div>`,
  );
}

export function renderLogin(siteName: string): string {
  return layout(
    siteName,
    `管理登录 · ${siteName}`,
    `<main class="login-wrap"><section class="login"><a class="brand" href="/"><span class="brand-mark">K</span>${escapeHtml(siteName)}</a><h1>管理入口</h1><p>使用部署时配置的管理员口令。登录会话将在 8 小时后自动失效。</p><form id="login-form"><div class="field"><label for="password">管理员口令</label><input id="password" name="password" type="password" minlength="16" autocomplete="current-password" required autofocus></div><p id="login-error" class="error" role="alert"></p><button class="btn primary" type="submit">安全登录</button></form></section></main>`,
    true,
  );
}

export function renderAdmin(siteName: string): string {
  return layout(
    siteName,
    `管理控制台 · ${siteName}`,
    `<div id="admin-app" class="admin-shell"><header class="admin-head"><a class="brand" href="/"><span class="brand-mark">K</span>${escapeHtml(siteName)}</a><div><span class="status-dot"></span><button id="logout" class="btn small">退出</button></div></header><main><div class="admin-toolbar"><div><span class="eyebrow">CONTROL PLANE / D1</span><h1>公钥管理</h1></div><button id="new-identity" class="btn primary">+ 新建身份</button></div><div class="admin-grid"><section class="panel"><header class="panel-head"><span>身份 <b id="identity-total">0</b></span><span>公钥 <b id="key-total">0</b></span></header><div id="identity-list"></div></section><aside class="panel audit-panel"><header class="panel-head">最近审计事件</header><div id="audit-list" class="audit"></div></aside></div></main></div><dialog id="identity-dialog"><header class="panel-head"><span>新建身份</span><button class="btn small" data-close>关闭</button></header><form id="create-identity" class="dialog-body form-grid"><div class="field"><label>名称</label><input name="name" maxlength="80" required></div><div class="field"><label>Handle</label><input name="handle" maxlength="32" pattern="[a-z0-9][a-z0-9-]{0,31}" required></div><div class="field wide"><label>简介</label><textarea name="description" maxlength="240" rows="3"></textarea></div><div class="field"><label>可见性</label><select name="isPublic"><option value="true">公开</option><option value="false">隐藏</option></select></div><div class="actions wide"><button class="btn primary" type="submit">创建</button></div></form></dialog><dialog id="key-dialog"><header class="panel-head"><span>添加 SSH 公钥</span><button class="btn small" data-close>关闭</button></header><form id="create-key" class="dialog-body"><input name="identityId" type="hidden"><div class="field"><label>完整 OpenSSH 公钥</label><textarea name="publicKey" rows="5" maxlength="16384" placeholder="ssh-ed25519 AAAA... device-name" required></textarea></div><div class="form-grid"><div class="field"><label>设备标签</label><input name="label" maxlength="80" placeholder="work-laptop"></div><div class="field"><label>添加日期</label><input name="addedAt" type="date"></div></div><p class="warning">只接受公钥。ED25519、RSA ≥ 2048、ECDSA 和 OpenSSH FIDO2 公钥受支持。</p><button class="btn primary" type="submit">验证并添加</button></form></dialog><div id="toast" class="toast" role="status" hidden></div>`,
    true,
  );
}
