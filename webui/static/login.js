'use strict';

document.getElementById('login-form').addEventListener('submit', async e => {
  e.preventDefault();
  const btn = document.getElementById('login-btn');
  const errEl = document.getElementById('error-msg');
  errEl.textContent = '';
  btn.disabled = true;
  btn.textContent = 'ログイン中...';

  const username = document.getElementById('username').value.trim();
  const password = document.getElementById('password').value;

  try {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });
    if (res.ok) {
      window.location.replace('/');
      return;
    }
    const data = await res.json().catch(() => ({}));
    if (res.status === 429) {
      errEl.textContent = 'ログイン試行が多すぎます。しばらくお待ちください。';
    } else {
      errEl.textContent = data.error || '認証に失敗しました';
    }
  } catch {
    errEl.textContent = 'サーバーに接続できませんでした';
  } finally {
    btn.disabled = false;
    btn.textContent = 'ログイン';
  }
});
