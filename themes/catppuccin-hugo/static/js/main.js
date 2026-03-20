/* Catppuccin Hugo — main.js */
(() => {
  'use strict';

  /* ── Theme Toggle ── */
  const THEME_KEY = 'catppuccin-theme';
  const html = document.documentElement;

  function getTheme() {
    return localStorage.getItem(THEME_KEY) ||
      (window.matchMedia('(prefers-color-scheme: light)').matches ? 'latte' : 'mocha');
  }

  function setTheme(theme) {
    html.setAttribute('data-theme', theme);
    localStorage.setItem(THEME_KEY, theme);
    updateThemeBtn(theme);
  }

  function updateThemeBtn(theme) {
    const btn = document.getElementById('theme-toggle');
    if (!btn) return;
    btn.innerHTML = theme === 'mocha' ? '☀️' : '🌙';
    btn.title = theme === 'mocha' ? 'Switch to Latte (light)' : 'Switch to Mocha (dark)';
  }

  function toggleTheme() {
    const current = html.getAttribute('data-theme') || 'mocha';
    setTheme(current === 'mocha' ? 'latte' : 'mocha');
  }

  // Init
  setTheme(getTheme());

  document.addEventListener('DOMContentLoaded', () => {
    const themeBtn = document.getElementById('theme-toggle');
    if (themeBtn) themeBtn.addEventListener('click', toggleTheme);
    updateThemeBtn(getTheme());

    /* ── Mobile Menu ── */
    const toggle = document.getElementById('mobile-toggle');
    const nav = document.getElementById('site-nav');
    if (toggle && nav) {
      toggle.addEventListener('click', () => {
        const open = nav.classList.toggle('open');
        toggle.setAttribute('aria-expanded', open);
      });
    }

    /* ── Back to Top ── */
    const backTop = document.getElementById('back-to-top');
    if (backTop) {
      window.addEventListener('scroll', () => {
        backTop.classList.toggle('visible', window.scrollY > 400);
      }, { passive: true });
      backTop.addEventListener('click', () => {
        window.scrollTo({ top: 0, behavior: 'smooth' });
      });
    }

    /* ── Active Nav Link ── */
    const path = window.location.pathname;
    document.querySelectorAll('.nav-link').forEach(link => {
      const href = link.getAttribute('href');
      if (href && path.startsWith(href) && href !== '/') {
        link.classList.add('active');
      } else if (href === '/' && path === '/') {
        link.classList.add('active');
      }
    });

    /* ── Simple Search ── */
    const searchInput = document.getElementById('search-input');
    const searchResults = document.getElementById('search-results');
    if (searchInput && searchResults && window.__searchData) {
      searchInput.addEventListener('input', () => {
        const q = searchInput.value.toLowerCase().trim();
        if (!q) { searchResults.innerHTML = ''; return; }
        const matches = window.__searchData.filter(p =>
          p.title.toLowerCase().includes(q) ||
          (p.content && p.content.toLowerCase().includes(q))
        ).slice(0, 6);

        searchResults.innerHTML = matches.length
          ? matches.map(p => `
              <a class="search-result-item" href="${p.permalink}">
                <div class="search-result-title">${p.title}</div>
                <div class="search-result-date">${p.date || ''}</div>
              </a>`).join('')
          : '<div class="search-empty">No results found</div>';
      });
    }

    /* ── Reading Progress ── */
    const progress = document.getElementById('reading-progress');
    if (progress) {
      window.addEventListener('scroll', () => {
        const docH = document.documentElement.scrollHeight - window.innerHeight;
        const pct = docH > 0 ? (window.scrollY / docH) * 100 : 0;
        progress.style.width = pct + '%';
      }, { passive: true });
    }

    /* ── Copy Code Buttons ── */
    document.querySelectorAll('pre').forEach(pre => {
      const wrapper = document.createElement('div');
      wrapper.className = 'code-wrapper';
      pre.parentNode.insertBefore(wrapper, pre);
      wrapper.appendChild(pre);

      const btn = document.createElement('button');
      btn.className = 'copy-btn';
      btn.setAttribute('aria-label', 'Copy code');
      btn.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
      </svg>`;
      btn.addEventListener('click', () => {
        const code = pre.querySelector('code');
        const text = code ? code.textContent : pre.textContent;
        navigator.clipboard.writeText(text).then(() => {
          btn.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
            <polyline points="20 6 9 17 4 12"/>
          </svg>`;
          btn.classList.add('copy-btn--done');
          setTimeout(() => {
            btn.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
            </svg>`;
            btn.classList.remove('copy-btn--done');
          }, 2000);
        });
      });
      wrapper.appendChild(btn);
    });
  });
})();
