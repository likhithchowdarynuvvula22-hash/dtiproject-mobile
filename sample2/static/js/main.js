// SafeCall Sentinel — Frontend Logic
document.addEventListener('DOMContentLoaded', () => {

  // ─── Flash Message Auto-dismiss ──────────────────────────
  document.querySelectorAll('.flash-msg').forEach(el => {
    setTimeout(() => {
      el.classList.add('flash-exit');
      setTimeout(() => el.remove(), 300);
    }, 5000);
  });

  // ─── Password Visibility Toggle ─────────────────────────
  document.querySelectorAll('.toggle-pw').forEach(btn => {
    btn.addEventListener('click', () => {
      const input = btn.parentElement.querySelector('input');
      const icon = btn.querySelector('.material-symbols-outlined');
      if (input.type === 'password') { input.type = 'text'; icon.textContent = 'visibility_off'; }
      else { input.type = 'password'; icon.textContent = 'visibility'; }
    });
  });

  // ─── Mobile Navbar Menu Toggle ──────────────────────────
  const menuBtn = document.querySelector('.mobile-menu-btn');
  const navLinks = document.querySelector('.navbar-links');
  if (menuBtn && navLinks) {
    menuBtn.addEventListener('click', () => {
      navLinks.classList.toggle('open');
      const icon = menuBtn.querySelector('.material-symbols-outlined');
      icon.textContent = navLinks.classList.contains('open') ? 'close' : 'menu';
    });
    // Close menu when clicking a link
    navLinks.querySelectorAll('a').forEach(link => {
      link.addEventListener('click', () => navLinks.classList.remove('open'));
    });
  }

  // ─── Sidebar Toggle (Dashboard pages) ───────────────────
  const sidebarToggle = document.getElementById('sidebar-toggle');
  const sidebar = document.getElementById('sidebar');
  const sidebarOverlay = document.getElementById('sidebar-overlay');

  if (sidebarToggle && sidebar) {
    sidebarToggle.addEventListener('click', () => {
      sidebar.classList.toggle('open');
      if (sidebarOverlay) sidebarOverlay.classList.toggle('active');
    });
    if (sidebarOverlay) {
      sidebarOverlay.addEventListener('click', () => {
        sidebar.classList.remove('open');
        sidebarOverlay.classList.remove('active');
      });
    }
  }

  // ─── Category Pill Selection (SMS Analyzer) ─────────────
  document.querySelectorAll('.cat-pill').forEach(pill => {
    pill.addEventListener('click', () => {
      document.querySelectorAll('.cat-pill').forEach(p => {
        p.classList.remove('active');
        const dot = p.querySelector('.dot');
        if (dot) { dot.style.background = 'var(--bg-void)'; dot.style.color = 'var(--text-muted)'; }
      });
      pill.classList.add('active');
      const dot = pill.querySelector('.dot');
      if (dot) { dot.style.background = 'var(--cyan)'; dot.style.color = 'var(--bg-void)'; }
      const input = document.getElementById('category-input');
      if (input) input.value = pill.dataset.category;
    });
  });

  // ─── Animate Stat Numbers on Scroll ─────────────────────
  const animateNumbers = () => {
    document.querySelectorAll('[data-count]').forEach(el => {
      if (el.dataset.animated) return;
      const rect = el.getBoundingClientRect();
      if (rect.top > window.innerHeight || rect.bottom < 0) return;
      el.dataset.animated = 'true';

      const target = parseFloat(el.dataset.count);
      const suffix = el.dataset.suffix || '';
      let current = 0;
      const step = target / 50;
      const timer = setInterval(() => {
        current += step;
        if (current >= target) { current = target; clearInterval(timer); }
        el.textContent = (Number.isInteger(target) ? Math.floor(current) : current.toFixed(1)) + suffix;
      }, 25);
    });
  };

  if (document.querySelector('[data-count]')) {
    animateNumbers();
    window.addEventListener('scroll', animateNumbers, { passive: true });
  }

  // ─── Copy Code Buttons ──────────────────────────────────
  document.querySelectorAll('.copy-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const code = btn.dataset.code;
      navigator.clipboard.writeText(code).then(() => {
        const orig = btn.innerHTML;
        btn.innerHTML = '<span class="material-symbols-outlined" style="font-size:14px">check</span> Copied';
        btn.style.color = 'var(--cyan)';
        setTimeout(() => { btn.innerHTML = orig; btn.style.color = ''; }, 1500);
      }).catch(() => {
        // Fallback for older browsers
        const ta = document.createElement('textarea');
        ta.value = code; ta.style.position = 'fixed'; ta.style.opacity = '0';
        document.body.appendChild(ta); ta.select();
        document.execCommand('copy'); document.body.removeChild(ta);
        const orig = btn.innerHTML;
        btn.innerHTML = '<span class="material-symbols-outlined" style="font-size:14px">check</span> Copied';
        setTimeout(() => btn.innerHTML = orig, 1500);
      });
    });
  });

  // ─── Password Strength Indicator (Signup) ───────────────
  const pwInput = document.getElementById('password');
  const pwStrengthFill = document.getElementById('pw-strength-fill');
  const pwStrengthText = document.getElementById('pw-strength-text');

  if (pwInput && pwStrengthFill && pwStrengthText) {
    pwInput.addEventListener('input', () => {
      const pw = pwInput.value;
      let strength = 0;
      let label = '';
      let color = '';

      if (pw.length >= 8) strength += 25;
      if (pw.length >= 12) strength += 15;
      if (/[A-Z]/.test(pw)) strength += 15;
      if (/[a-z]/.test(pw)) strength += 10;
      if (/\d/.test(pw)) strength += 15;
      if (/[^A-Za-z0-9]/.test(pw)) strength += 20;

      if (strength <= 25) { label = 'Weak'; color = 'var(--error)'; }
      else if (strength <= 50) { label = 'Fair'; color = 'var(--warning)'; }
      else if (strength <= 75) { label = 'Good'; color = 'var(--cyan)'; }
      else { label = 'Strong'; color = '#4ade80'; }

      pwStrengthFill.style.width = strength + '%';
      pwStrengthFill.style.background = color;
      pwStrengthFill.style.boxShadow = `0 0 8px ${color}40`;
      pwStrengthText.textContent = pw.length === 0 ? 'Min 8 chars, 1 letter, 1 number' : `Strength: ${label}`;
      pwStrengthText.style.color = pw.length === 0 ? '' : color;
    });
  }

  // ─── Scroll-triggered Fade In Animations ─────────────────
  const fadeElements = document.querySelectorAll('.fade-in-up');
  if (fadeElements.length > 0) {
    const observer = new IntersectionObserver(entries => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          entry.target.style.animationPlayState = 'running';
          observer.unobserve(entry.target);
        }
      });
    }, { threshold: 0.1 });

    fadeElements.forEach(el => {
      el.style.animationPlayState = 'paused';
      observer.observe(el);
    });
  }

  // ─── Form Submit Loading State ───────────────────────────
  document.querySelectorAll('form').forEach(form => {
    form.addEventListener('submit', () => {
      const btn = form.querySelector('button[type="submit"]');
      if (btn) {
        btn.disabled = true;
        btn.style.opacity = '0.7';
        const origHTML = btn.innerHTML;
        btn.innerHTML = '<span class="material-symbols-outlined animate-pulse" style="font-size:1.1rem">hourglass_top</span>Processing...';
        // Re-enable after 10s in case of issues
        setTimeout(() => { btn.disabled = false; btn.style.opacity = '1'; btn.innerHTML = origHTML; }, 10000);
      }
    });
  });

});
