// ─── Theme Toggle ─────────────────────────────────────────────
const html = document.documentElement;
const themeToggle = document.getElementById('themeToggle');
const savedTheme = localStorage.getItem('theme') || 'dark';
html.setAttribute('data-theme', savedTheme);

themeToggle?.addEventListener('click', () => {
  const current = html.getAttribute('data-theme');
  const next = current === 'dark' ? 'light' : 'dark';
  html.setAttribute('data-theme', next);
  localStorage.setItem('theme', next);
});

// ─── Char Counter ─────────────────────────────────────────────
const textarea = document.getElementById('emailInput');
const charCount = document.getElementById('charCount');
textarea?.addEventListener('input', () => {
  charCount.textContent = textarea.value.length.toLocaleString();
});

// ─── File Upload ──────────────────────────────────────────────
document.getElementById('fileUpload')?.addEventListener('change', async (e) => {
  const file = e.target.files[0];
  if (!file) return;
  const text = await file.text();
  textarea.value = text;
  charCount.textContent = text.length.toLocaleString();
  textarea.dispatchEvent(new Event('input'));
});

// ─── Clear ────────────────────────────────────────────────────
function clearAll() {
  textarea.value = '';
  charCount.textContent = '0';
  document.getElementById('resultPanel').style.display = 'none';
  document.getElementById('historyNote').style.display = 'none';
  textarea.focus();
}

// ─── Main Analysis ────────────────────────────────────────────
async function analyzeEmail() {
  const text = textarea?.value.trim();
  if (!text) {
    textarea.style.borderColor = 'var(--danger)';
    setTimeout(() => textarea.style.borderColor = '', 1200);
    return;
  }

  const btn = document.getElementById('analyzeBtn');
  const btnText = btn.querySelector('.btn-text');
  const btnLoading = btn.querySelector('.btn-loading');

  btn.disabled = true;
  btnText.style.display = 'none';
  btnLoading.style.display = 'flex';

  try {
    const res = await fetch('/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text })
    });

    if (!res.ok) throw new Error('Server error');
    const data = await res.json();
    renderResult(data, text);

  } catch (err) {
    showError('Failed to connect. Please try again.');
  } finally {
    btn.disabled = false;
    btnText.style.display = 'flex';
    btnLoading.style.display = 'none';
  }
}

// ─── Render Result ────────────────────────────────────────────
function renderResult(data, originalText) {
  const panel = document.getElementById('resultPanel');
  panel.style.display = 'block';

  const isPhishing = data.is_phishing;
  const riskLevel = (data.risk_level || 'Low').toLowerCase();

  // Header
  const header = document.getElementById('resultHeader');
  header.className = `result-header ${isPhishing ? 'phishing' : 'safe'}`;

  const icon = document.getElementById('verdictIcon');
  icon.className = `verdict-icon ${isPhishing ? 'phishing' : 'safe'}`;
  icon.textContent = isPhishing ? '⚠️' : '✅';

  const label = document.getElementById('verdictLabel');
  label.textContent = isPhishing ? 'PHISHING DETECTED' : 'EMAIL IS SAFE';
  label.className = `verdict-label ${isPhishing ? 'phishing' : 'safe'}`;

  document.getElementById('verdictSub').textContent = isPhishing
    ? 'This email contains suspicious patterns and may be a phishing attempt.'
    : 'No significant phishing indicators detected in this email.';

  const risk = document.getElementById('riskBadge');
  risk.textContent = data.risk_level?.toUpperCase() || 'LOW';
  risk.className = `risk-badge ${riskLevel}`;

  // Confidence
  const conf = data.confidence || 0;
  document.getElementById('confValue').textContent = conf.toFixed(1) + '%';
  const bar = document.getElementById('confBar');
  bar.className = `confidence-bar ${isPhishing ? 'phishing' : 'safe'}`;
  setTimeout(() => { bar.style.width = conf + '%'; }, 50);

  // Risk dots
  document.getElementById('riskValue').textContent = data.risk_level || 'Low';
  document.getElementById('riskValue').className = `metric-value risk-text ${riskLevel}`;
  const dotsEl = document.getElementById('riskDots');
  const dotCount = riskLevel === 'high' ? 3 : riskLevel === 'medium' ? 2 : 1;
  dotsEl.innerHTML = [1,2,3].map(i =>
    `<div class="risk-dot ${i <= dotCount ? 'active ' + riskLevel : ''}"></div>`
  ).join('');

  // Threats count
  const totalThreats = (data.suspicious_words?.length || 0) + (data.suspicious_urls?.filter(u=>u.suspicious).length || 0);
  document.getElementById('threatCount').textContent = totalThreats;

  // Suspicious words
  const wordsSection = document.getElementById('suspiciousWordsSection');
  const words = data.suspicious_words || [];
  if (words.length > 0) {
    wordsSection.style.display = 'block';
    document.getElementById('wordChips').innerHTML =
      words.map(w => `<span class="word-chip">${escHtml(w)}</span>`).join('');
  } else {
    wordsSection.style.display = 'none';
  }

  // URLs
  const urlSection = document.getElementById('suspiciousUrlsSection');
  const urls = data.suspicious_urls || [];
  if (urls.length > 0) {
    urlSection.style.display = 'block';
    document.getElementById('urlList').innerHTML = urls.map(u =>
      `<div class="url-item">
        <span class="url-text">${escHtml(u.url)}</span>
        <span class="url-flag ${u.suspicious ? 'sus' : 'ok'}">${u.suspicious ? 'SUSPICIOUS' : 'OK'}</span>
      </div>`
    ).join('');
  } else {
    urlSection.style.display = 'none';
  }

  // Highlighted text
  if (originalText) {
    const hlSection = document.getElementById('highlightSection');
    hlSection.style.display = 'block';
    document.getElementById('highlightedText').innerHTML = highlightText(originalText, data.suspicious_words || []);
  }

  // History note for guests
  const histNote = document.getElementById('historyNote');
  if (histNote) histNote.style.display = 'flex';

  // Scroll to result
  panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// ─── Text Highlighting ────────────────────────────────────────
function highlightText(text, words) {
  let escaped = escHtml(text);
  const urlRe = /(https?:\/\/[^\s]+|www\.[^\s]+)/gi;
  escaped = escaped.replace(urlRe, m => `<mark class="warn">${m}</mark>`);
  for (const w of words) {
    const re = new RegExp(`\\b(${escRegex(w)})\\b`, 'gi');
    escaped = escaped.replace(re, m => `<mark class="danger">${m}</mark>`);
  }
  return escaped;
}

function escHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function escRegex(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function showError(msg) {
  const panel = document.getElementById('resultPanel');
  panel.style.display = 'block';
  panel.innerHTML = `<div style="padding:2rem;text-align:center;color:var(--danger)">
    <div style="font-size:2rem;margin-bottom:.5rem">⚠️</div>
    <div>${msg}</div>
  </div>`;
}

// ─── Keyboard Shortcut ────────────────────────────────────────
document.addEventListener('keydown', e => {
  if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') analyzeEmail();
});
