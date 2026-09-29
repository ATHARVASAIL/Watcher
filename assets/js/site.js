/**
 * Watcher website: motion, micro-interactions and copy buttons.
 *
 * Everything here is progressive. Without JavaScript, or with reduced motion, the page is complete
 * and static. The page makes no network requests of its own.
 */
(() => {
  'use strict';

  const root = document.documentElement;
  const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)');
  const finePointer = window.matchMedia('(hover: hover) and (pointer: fine)');
  const motionOK = !reducedMotion.matches;

  const clamp = (value, min, max) => Math.min(max, Math.max(min, value));
  const lerp = (from, to, t) => from + (to - from) * t;

  root.classList.add('js');

  /* ------------------------------------------------------------------ scroll reveals */

  const revealables = [...document.querySelectorAll('[data-reveal]')];

  if (motionOK && 'IntersectionObserver' in window) {
    // Anything already on screen is shown immediately, so nothing visible ever blinks out.
    const viewport = window.innerHeight;
    for (const el of revealables) {
      const rect = el.getBoundingClientRect();
      if (rect.top < viewport * 0.92 && rect.bottom > 0) el.classList.add('is-in');
    }
    root.classList.add('js-reveal');

    const revealObserver = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (!entry.isIntersecting) continue;
          entry.target.classList.add('is-in');
          revealObserver.unobserve(entry.target);
        }
      },
      { rootMargin: '0px 0px -8% 0px', threshold: 0.12 },
    );
    for (const el of revealables) if (!el.classList.contains('is-in')) revealObserver.observe(el);

    window.addEventListener('beforeprint', () => {
      for (const el of revealables) el.classList.add('is-in');
    });
  }

  /* ------------------------------------------------------------------ counters */

  function countUp(el) {
    const target = Number(el.dataset.countTo);
    const decimals = Number(el.dataset.decimals) || 0;
    if (!Number.isFinite(target)) return;
    const start = performance.now();
    const duration = 1500;
    const tick = (now) => {
      const t = clamp((now - start) / duration, 0, 1);
      const eased = 1 - (1 - t) ** 4;
      el.textContent = (target * eased).toFixed(decimals);
      if (t < 1) requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  }

  if (motionOK && 'IntersectionObserver' in window) {
    const counterObserver = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (!entry.isIntersecting) continue;
          counterObserver.unobserve(entry.target);
          countUp(entry.target);
        }
      },
      { threshold: 0.6 },
    );
    for (const el of document.querySelectorAll('[data-count-to]')) counterObserver.observe(el);
  }

  /* ------------------------------------------------------------------ nav, story, parallax */

  const nav = document.querySelector('[data-nav]');
  const storyVisual = document.querySelector('[data-story-visual]');
  const steps = [...document.querySelectorAll('.story-steps [data-step]')];
  const storyProgress = document.querySelector('[data-story-progress]');
  const parallaxItems = motionOK ? [...document.querySelectorAll('[data-parallax]')] : [];
  let lastY = window.scrollY;

  function updateNav() {
    if (!nav) return;
    const y = window.scrollY;
    nav.classList.toggle('is-scrolled', y > 24);
    if (y < 480 || y < lastY - 4) nav.classList.remove('is-hidden');
    else if (y > lastY + 4 && !nav.contains(document.activeElement)) nav.classList.add('is-hidden');
    lastY = y;
  }

  function updateStory() {
    if (!storyVisual || steps.length === 0) return;
    const viewport = window.innerHeight;
    const readingLine = viewport * (window.innerWidth <= 900 ? 0.7 : 0.5);

    let active = steps[0];
    let best = Infinity;
    for (const step of steps) {
      const rect = step.getBoundingClientRect();
      const distance = Math.abs(rect.top + rect.height / 2 - readingLine);
      if (distance < best) {
        best = distance;
        active = step;
      }
    }

    const n = active.dataset.step;
    if (storyVisual.dataset.active !== n) {
      storyVisual.dataset.active = n;
      for (const pane of storyVisual.querySelectorAll('.dt-pane')) pane.classList.remove('is-live');
      const pane = storyVisual.querySelector(`.p${n}`);
      if (pane && motionOK) {
        void pane.offsetWidth; // restart the highlight animation
        pane.classList.add('is-live');
      }
    }
    for (const step of steps) step.classList.toggle('is-active', step === active);

    if (storyProgress) {
      const first = steps[0].getBoundingClientRect();
      const last = steps[steps.length - 1].getBoundingClientRect();
      const p = clamp((readingLine - first.top) / Math.max(1, last.bottom - first.top), 0, 1);
      storyProgress.style.setProperty('--p', (0.06 + p * 0.94).toFixed(3));
    }
  }

  function updateParallax() {
    const viewport = window.innerHeight;
    const factor = window.innerWidth <= 760 ? 0.05 : 0.12;
    for (const el of parallaxItems) {
      const rect = el.getBoundingClientRect();
      if (rect.bottom < -200 || rect.top > viewport + 200) continue;
      const offset = rect.top + rect.height / 2 - viewport / 2;
      el.style.setProperty('--py', `${(offset * -factor).toFixed(1)}px`);
    }
  }

  let scrollQueued = false;
  function onScroll() {
    if (scrollQueued) return;
    scrollQueued = true;
    requestAnimationFrame(() => {
      scrollQueued = false;
      updateNav();
      updateStory();
      updateParallax();
    });
  }

  window.addEventListener('scroll', onScroll, { passive: true });
  window.addEventListener('resize', onScroll, { passive: true });
  nav?.addEventListener('focusin', () => nav.classList.remove('is-hidden'));
  updateNav();
  updateStory();
  updateParallax();

  /* ------------------------------------------------------------------ the watching eye */

  const eye = document.querySelector('[data-eye]');
  const iris = eye?.querySelector('[data-iris]');
  const chips = [...document.querySelectorAll('.chip-wrap[data-depth]')];
  const hero = document.querySelector('[data-hero]');

  if (motionOK && eye && iris) {
    const MAX_X = 78;
    const MAX_Y = 34;
    const look = { x: 0, y: 0, tx: 0, ty: 0, px: 0, py: 0, tpx: 0, tpy: 0 };
    let frameId = 0;
    let heroVisible = true;
    let lastPointer = 0;

    const frame = () => {
      frameId = 0;
      look.x = lerp(look.x, look.tx, 0.12);
      look.y = lerp(look.y, look.ty, 0.12);
      look.px = lerp(look.px, look.tpx, 0.07);
      look.py = lerp(look.py, look.tpy, 0.07);
      iris.setAttribute('transform', `translate(${look.x.toFixed(2)} ${look.y.toFixed(2)})`);
      for (const chip of chips) {
        const depth = Number(chip.dataset.depth) || 0;
        chip.style.transform = `translate3d(${(look.px * depth).toFixed(2)}px, ${(look.py * depth).toFixed(2)}px, 0)`;
      }
      const settling =
        Math.abs(look.x - look.tx) > 0.05 ||
        Math.abs(look.y - look.ty) > 0.05 ||
        Math.abs(look.px - look.tpx) > 0.002 ||
        Math.abs(look.py - look.tpy) > 0.002;
      if (settling && heroVisible) frameId = requestAnimationFrame(frame);
    };
    const kick = () => {
      if (!frameId && heroVisible) frameId = requestAnimationFrame(frame);
    };

    window.addEventListener(
      'pointermove',
      (event) => {
        if (event.pointerType !== 'mouse' && event.pointerType !== 'pen') return;
        lastPointer = performance.now();
        const rect = eye.getBoundingClientRect();
        const dx = event.clientX - (rect.left + rect.width / 2);
        const dy = event.clientY - (rect.top + rect.height / 2);
        const distance = Math.hypot(dx, dy) || 1;
        const reach = Math.min(1, distance / 420);
        look.tx = (dx / distance) * reach * MAX_X;
        look.ty = (dy / distance) * reach * MAX_Y;
        look.tpx = event.clientX / window.innerWidth - 0.5;
        look.tpy = event.clientY / window.innerHeight - 0.5;
        kick();
      },
      { passive: true },
    );

    // Touch screens and idle mice: the eye looks around on its own.
    setInterval(() => {
      if (!heroVisible || document.hidden || performance.now() - lastPointer < 4000) return;
      const centre = Math.random() < 0.3;
      look.tx = centre ? 0 : (Math.random() * 2 - 1) * MAX_X * 0.85;
      look.ty = centre ? 0 : (Math.random() * 2 - 1) * MAX_Y * 0.7;
      look.tpx = look.tx / MAX_X / 3;
      look.tpy = look.ty / MAX_Y / 3;
      kick();
    }, 2600);

    if (hero && 'IntersectionObserver' in window) {
      new IntersectionObserver(([entry]) => {
        heroVisible = entry.isIntersecting;
        if (heroVisible) kick();
      }).observe(hero);
    }
  }

  /* ------------------------------------------------------------------ pointer micro-interactions */

  if (motionOK && finePointer.matches) {
    // Magnetic buttons: pulled toward the cursor, label pulled a little further.
    for (const button of document.querySelectorAll('[data-magnetic]')) {
      let mx = 0;
      let my = 0;
      button.addEventListener('pointermove', (event) => {
        const rect = button.getBoundingClientRect();
        const left = rect.left - mx;
        const top = rect.top - my;
        const x = event.clientX - left;
        const y = event.clientY - top;
        mx = (x - rect.width / 2) * 0.22;
        my = (y - rect.height / 2) * 0.34;
        button.style.setProperty('--mx', `${mx.toFixed(1)}px`);
        button.style.setProperty('--my', `${my.toFixed(1)}px`);
        button.style.setProperty('--hx', `${x.toFixed(0)}px`);
        button.style.setProperty('--hy', `${y.toFixed(0)}px`);
      });
      button.addEventListener('pointerleave', () => {
        mx = 0;
        my = 0;
        button.style.setProperty('--mx', '0px');
        button.style.setProperty('--my', '0px');
      });
    }

    // Spotlight cards: a soft light and a lit edge follow the cursor.
    for (const card of document.querySelectorAll('[data-spot]')) {
      card.addEventListener('pointermove', (event) => {
        const rect = card.getBoundingClientRect();
        card.style.setProperty('--sx', `${(event.clientX - rect.left).toFixed(0)}px`);
        card.style.setProperty('--sy', `${(event.clientY - rect.top).toFixed(0)}px`);
      });
    }

    // Footer wordmark lights up under the cursor.
    const footer = document.querySelector('.footer');
    footer?.addEventListener('pointermove', (event) => {
      const rect = footer.getBoundingClientRect();
      footer.style.setProperty('--wx', `${(((event.clientX - rect.left) / rect.width) * 100).toFixed(1)}%`);
    });
  }

  /* ------------------------------------------------------------------ copy buttons */

  for (const button of document.querySelectorAll('button[data-copy]')) {
    button.addEventListener('click', async () => {
      const target = document.querySelector(button.dataset.copy);
      const text = target ? target.textContent.trim() : '';
      try {
        await navigator.clipboard.writeText(text);
        button.textContent = 'Copied';
      } catch {
        if (target) window.getSelection()?.selectAllChildren(target);
        button.textContent = 'Press Ctrl+C';
      }
      setTimeout(() => {
        button.textContent = 'Copy';
      }, 1600);
    });
  }

  /* ------------------------------------------------------------------ footer year */

  for (const el of document.querySelectorAll('[data-year]'))
    el.textContent = String(new Date().getFullYear());
})();
