// devices.js — admin-only device & enrollment management UI.
// Strict CSP: no inline handlers; everything bound here.

(() => {
  const $ = (id) => document.getElementById(id);

  function fmtDate(s) {
    if (!s) return "—";
    try {
      const d = new Date(s);
      if (isNaN(d.getTime())) return s;
      return d.toLocaleString();
    } catch { return s; }
  }

  function escapeHTML(s) {
    if (s === null || s === undefined) return "";
    return String(s)
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#39;");
  }

  async function api(path, opts = {}) {
    const res = await fetch(path, {
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      ...opts,
    });
    if (res.status === 401) {
      window.location.href = "/login.html";
      throw new Error("unauthorized");
    }
    return res;
  }

  // ---- CA ----
  async function loadCA() {
    try {
      const res = await api("/api/org-ca/cert");
      if (!res.ok) {
        $("ca-info").textContent = "CAの読み込みに失敗しました";
        return;
      }
      const data = await res.json();
      $("ca-info").innerHTML =
        `<div class="row"><span class="key">Subject:</span> ${escapeHTML(data.subject)}</div>` +
        `<div class="row"><span class="key">Not After:</span> ${escapeHTML(fmtDate(data.not_after))}</div>` +
        `<div class="row"><span class="key">Fingerprint (SHA-256):</span> ${escapeHTML(data.fingerprint)}</div>`;
      window.__caPEM = data.cert_pem || "";
    } catch (e) {
      $("ca-info").textContent = "CAの読み込みに失敗しました";
    }
  }

  function downloadCA() {
    const pem = window.__caPEM || "";
    if (!pem) return;
    const blob = new Blob([pem], { type: "application/x-pem-file" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "org-ca.pem";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  // ---- Tokens ----
  async function loadTokens() {
    const wrap = $("tokens-table-wrap");
    try {
      const res = await api("/api/enroll-tokens");
      if (!res.ok) {
        wrap.innerHTML = `<div class="empty">トークン一覧の読み込みに失敗しました</div>`;
        return;
      }
      const tokens = await res.json();
      if (!tokens || tokens.length === 0) {
        wrap.innerHTML = `<div class="empty">発行済みトークンはありません</div>`;
        return;
      }
      // Sort: newest first
      tokens.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
      const rows = tokens.map((t) => {
        const expired = new Date(t.expires_at) < new Date();
        let status;
        if (t.revoked) status = `<span class="badge badge-revoked">revoked</span>`;
        else if (expired) status = `<span class="badge badge-expired">expired</span>`;
        else if (t.used_count >= t.max_uses) status = `<span class="badge badge-expired">used</span>`;
        else status = `<span class="badge badge-ok">active</span>`;
        const revokeBtn = (t.revoked
          ? ""
          : `<button class="danger" data-revoke-token="${escapeHTML(t.id)}">失効</button>`);
        return `<tr>
          <td class="id">${escapeHTML(t.id)}</td>
          <td>${escapeHTML(t.description || "")}</td>
          <td>${status}</td>
          <td>${t.used_count}/${t.max_uses}</td>
          <td class="ts">${escapeHTML(fmtDate(t.created_at))}</td>
          <td class="ts">${escapeHTML(fmtDate(t.expires_at))}</td>
          <td>${revokeBtn}</td>
        </tr>`;
      }).join("");
      wrap.innerHTML = `<table>
        <thead><tr>
          <th>ID</th><th>用途</th><th>状態</th><th>使用回数</th>
          <th>発行</th><th>有効期限</th><th></th>
        </tr></thead>
        <tbody>${rows}</tbody>
      </table>`;

      wrap.querySelectorAll("[data-revoke-token]").forEach((btn) => {
        btn.addEventListener("click", async () => {
          const id = btn.getAttribute("data-revoke-token");
          if (!confirm(`トークン ${id} を失効させますか?`)) return;
          btn.disabled = true;
          const res = await api(`/api/enroll-tokens/${encodeURIComponent(id)}`, { method: "DELETE" });
          if (res.ok || res.status === 204) {
            await loadTokens();
          } else {
            alert("失効に失敗しました");
            btn.disabled = false;
          }
        });
      });
    } catch (e) {
      wrap.innerHTML = `<div class="empty">トークン一覧の読み込みに失敗しました</div>`;
    }
  }

  async function createToken() {
    const desc = $("desc-input").value.trim();
    const hours = parseInt($("hours-input").value, 10) || 24;
    const uses = parseInt($("uses-input").value, 10) || 1;

    const btn = $("create-token");
    btn.disabled = true;
    try {
      const res = await api("/api/enroll-tokens", {
        method: "POST",
        body: JSON.stringify({
          description: desc,
          expires_in_hours: hours,
          max_uses: uses,
        }),
      });
      if (!res.ok) {
        const text = await res.text();
        alert("トークン発行に失敗しました: " + text);
        return;
      }
      const tok = await res.json();
      const banner = $("new-token-banner");
      banner.innerHTML = `
        <div class="token-banner">
          <div class="label">新しいエンロールメントトークン (1度だけ表示)</div>
          <div>${escapeHTML(tok.token)}</div>
          <div class="warn">⚠ このページを離れると再表示されません。Connect エージェントに今すぐ設定してください。</div>
          <div style="margin-top:6px; font-family: -apple-system, sans-serif; font-size: 12px; color: #bbf7d0;">
            URL: ${escapeHTML(tok.url || "")}
          </div>
        </div>`;
      $("desc-input").value = "";
      await loadTokens();
    } catch (e) {
      alert("トークン発行に失敗しました");
    } finally {
      btn.disabled = false;
    }
  }

  // ---- Devices ----
  async function loadDevices() {
    const wrap = $("devices-table-wrap");
    try {
      const res = await api("/api/devices");
      if (!res.ok) {
        wrap.innerHTML = `<div class="empty">デバイス一覧の読み込みに失敗しました</div>`;
        return;
      }
      const devices = await res.json();
      if (!devices || devices.length === 0) {
        wrap.innerHTML = `<div class="empty">登録済みデバイスはありません</div>`;
        return;
      }
      devices.sort((a, b) => new Date(b.issued_at) - new Date(a.issued_at));
      const rows = devices.map((d) => {
        const expired = new Date(d.expires_at) < new Date();
        let status;
        if (d.revoked) status = `<span class="badge badge-revoked">revoked</span>`;
        else if (expired) status = `<span class="badge badge-expired">expired</span>`;
        else status = `<span class="badge badge-ok">active</span>`;
        const revokeBtn = (d.revoked
          ? ""
          : `<button class="danger" data-revoke-device="${escapeHTML(d.device_id)}">失効</button>`);
        return `<tr>
          <td class="id">${escapeHTML(d.device_id)}</td>
          <td class="subject">${escapeHTML(d.subject || "")}</td>
          <td>${escapeHTML(d.org || "")}</td>
          <td>${status}</td>
          <td class="ts">${escapeHTML(fmtDate(d.issued_at))}</td>
          <td class="ts">${escapeHTML(fmtDate(d.expires_at))}</td>
          <td class="ts">${escapeHTML(fmtDate(d.last_seen))}</td>
          <td>${revokeBtn}</td>
        </tr>`;
      }).join("");
      wrap.innerHTML = `<table>
        <thead><tr>
          <th>Device ID</th><th>Subject</th><th>Org</th><th>状態</th>
          <th>発行</th><th>有効期限</th><th>最終接続</th><th></th>
        </tr></thead>
        <tbody>${rows}</tbody>
      </table>`;

      wrap.querySelectorAll("[data-revoke-device]").forEach((btn) => {
        btn.addEventListener("click", async () => {
          const id = btn.getAttribute("data-revoke-device");
          if (!confirm(`デバイス ${id} を失効させますか?`)) return;
          btn.disabled = true;
          const res = await api(`/api/devices/${encodeURIComponent(id)}/revoke`, { method: "POST" });
          if (res.ok || res.status === 204) {
            await loadDevices();
          } else {
            alert("失効に失敗しました");
            btn.disabled = false;
          }
        });
      });
    } catch (e) {
      wrap.innerHTML = `<div class="empty">デバイス一覧の読み込みに失敗しました</div>`;
    }
  }

  // ---- Auth check + bootstrap ----
  async function bootstrap() {
    const me = await api("/api/auth/me");
    if (!me.ok) {
      window.location.href = "/login.html";
      return;
    }
    const user = await me.json();
    if (user.role !== "admin") {
      document.body.innerHTML = `<div style="padding: 60px; text-align:center; color:#fca5a5;">
        このページは admin ロールのみ利用できます。</div>`;
      return;
    }

    $("logout-btn").addEventListener("click", async () => {
      await api("/api/auth/logout", { method: "POST" });
      window.location.href = "/login.html";
    });
    $("create-token").addEventListener("click", createToken);
    $("ca-download").addEventListener("click", downloadCA);

    await loadCA();
    await loadTokens();
    await loadDevices();
  }

  bootstrap();
})();
