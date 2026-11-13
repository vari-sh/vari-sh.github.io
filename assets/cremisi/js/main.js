import "./chroma.js";
import { createNave } from "./nave.js";
import { createRelics } from "./relics.js";

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
const root = document.documentElement;
const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
const fine = matchMedia("(hover: hover) and (pointer: fine)").matches;
const clamp = (x, a = 0, b = 1) => Math.min(b, Math.max(a, x));
const smooth = (a, b, x) => { const t = clamp((x - a) / (b - a)); return t * t * (3 - 2 * t); };

// ── Headings are set letter by letter, so each one can stand up in turn.
for (const el of $$("[data-split]")) {
  const text = el.textContent.trim();
  el.setAttribute("aria-label", text);
  el.textContent = "";
  let i = 0;
  text.split(" ").forEach((word, n, all) => {
    const w = document.createElement("span");
    w.className = "w";
    w.setAttribute("aria-hidden", "true");
    for (const ch of word) {
      const l = document.createElement("span");
      l.className = "l";
      l.textContent = ch;
      l.style.setProperty("--i", i++);
      w.append(l);
    }
    el.append(w, n < all.length - 1 ? " " : "");
  });
}

// ── Reveal
const reveal = new IntersectionObserver(
  (entries) => {
    for (const e of entries) {
      if (!e.isIntersecting) continue;
      e.target.classList.add("is-visible");
      reveal.unobserve(e.target);
    }
  },
  { threshold: 0.12, rootMargin: "0px 0px -40px 0px" }
);
$$(".reveal, [data-head], [data-chart], [data-ramp], [data-facade]").forEach((el) => reveal.observe(el));

// ── The nave and the relics
const naveCanvas = $("[data-nave]");
const nave = naveCanvas ? createNave(naveCanvas, naveCanvas.dataset.palette.split(","), { still: reduced }) : null;
const relics = createRelics($$("canvas[data-relic]"), { still: reduced });
if (nave) root.classList.add("has-gl");
if (nave && !reduced) root.classList.add("fly");

// ── Nav, rail and the current chapter
const nav = $("[data-nav]");
const rail = $("[data-rail]");
const links = $$(".nav-links a, [data-rail-link]");
const spy = new IntersectionObserver(
  (entries) => {
    for (const e of entries) {
      if (!e.isIntersecting) continue;
      links.forEach((a) => a.classList.toggle("is-current", a.hash === `#${e.target.id}`));
    }
  },
  { rootMargin: "-45% 0px -50% 0px" }
);
$$("section[id]").forEach((s) => spy.observe(s));

// ── Hero: the title, lit by the pointer
const hero = $("[data-hero]");
const stage = $(".hero-stage");
const heroInner = $("[data-hero-inner]");
const title = $("[data-spotlight]");
const letters = $$(".ch", title);
const measureTitle = () => letters.forEach((l) => l.style.setProperty("--ox", `${l.offsetLeft}px`));
if (title) {
  let tx = 0, ty = 0, x = 0, y = 0, raf = 0;
  const paint = () => { title.style.setProperty("--mx", `${x}px`); title.style.setProperty("--my", `${y}px`); };
  const step = () => {
    x += (tx - x) * 0.14;
    y += (ty - y) * 0.14;
    paint();
    raf = Math.abs(tx - x) + Math.abs(ty - y) > 0.5 ? requestAnimationFrame(step) : 0;
  };
  const target = (e) => { const r = title.getBoundingClientRect(); tx = e.clientX - r.left; ty = e.clientY - r.top; };
  title.addEventListener("pointerenter", (e) => { target(e); x = tx; y = ty; paint(); title.style.setProperty("--la", ".9"); });
  title.addEventListener("pointermove", (e) => { target(e); if (!raf) raf = requestAnimationFrame(step); });
  title.addEventListener("pointerleave", () => title.style.setProperty("--la", "0"));
}
if (stage && nave && fine) {
  stage.addEventListener("pointermove", (e) => nave.setPointer((e.clientX / innerWidth) * 2 - 1, (e.clientY / innerHeight) * 2 - 1));
  stage.addEventListener("pointerleave", () => nave.setPointer(0, 0));
}
let heroSeen = true;
if (hero) new IntersectionObserver(([e]) => { heroSeen = e.isIntersecting; if (nave) heroSeen && isReady ? nave.start() : nave.stop(); }).observe(hero);

// ── Everything tied to the scroll position is computed in one place, once per frame.
const parallax = $$("[data-parallax]");
const editorStage = $("[data-editor-stage]");
const diptych = $("[data-diptych]");
const codex = $("[data-codex]");
const codexItems = codex ? $$("li", codex) : [];
let vh = innerHeight, docH = 1, heroSpan = 1, dirty = true, isReady = false;
const measure = () => {
  vh = innerHeight;
  docH = Math.max(1, root.scrollHeight - vh);
  heroSpan = hero ? Math.max(1, hero.offsetHeight - vh) : 1;
  measureTitle();
  dirty = true;
};
const onScroll = () => {
  const y = scrollY;
  nav?.classList.toggle("is-scrolled", y > 40);
  nav?.style.setProperty("--sp", clamp(y / docH).toFixed(4));
  rail?.classList.toggle("is-on", y > heroSpan + vh * 0.5);

  if (stage && heroSeen) {
    const flying = root.classList.contains("fly");
    const p = flying ? clamp(y / heroSpan) : 0;
    stage.style.setProperty("--hp", p.toFixed(4));
    stage.style.setProperty("--flash", smooth(0.8, 0.97, p).toFixed(3));
    nave?.setProgress(clamp((p - 0.015) / 0.965));
    if (heroInner && flying) {
      const k = clamp(p * 3.4);
      heroInner.style.opacity = (1 - k).toFixed(3);
      heroInner.style.transform = `translate3d(0, ${(-p * 150).toFixed(1)}px, 0) scale(${(1 + p * 1.1).toFixed(4)})`;
      heroInner.style.pointerEvents = k > 0.5 ? "none" : "";
      heroInner.style.visibility = k >= 1 ? "hidden" : "";
    }
  }
  if (reduced) return;
  for (const el of parallax) {
    const r = el.parentElement.getBoundingClientRect();
    if (r.bottom < -200 || r.top > vh + 200) continue;
    el.style.setProperty("--py", `${((r.top + r.height / 2 - vh / 2) * -0.14).toFixed(1)}px`);
  }
  if (editorStage) {
    const r = editorStage.getBoundingClientRect();
    if (r.top < vh * 1.2 && r.bottom > -100) editorStage.style.setProperty("--lift", (1 - smooth(0.42, 0.98, 1 - r.top / vh + 0.4)).toFixed(4));
  }
  if (diptych) {
    const r = diptych.getBoundingClientRect();
    if (r.top < vh * 1.2 && r.bottom > -100) diptych.style.setProperty("--fold", (0.1 + 0.9 * (1 - smooth(0, 0.6, 1 - r.top / vh))).toFixed(4));
  }
  if (codex) {
    const r = codex.getBoundingClientRect();
    const inside = r.top < vh * 0.72 && r.bottom > vh * 0.3;
    codex.classList.toggle("is-reading", inside);
    let best = null, bestD = 1e9;
    for (const li of codexItems) {
      const q = li.getBoundingClientRect();
      const d = Math.abs(q.top + q.height / 2 - vh * 0.5);
      if (d < bestD) { bestD = d; best = li; }
    }
    for (const li of codexItems) li.classList.toggle("is-read", inside && li === best);
  }
};
addEventListener("scroll", () => { dirty = true; }, { passive: true });
addEventListener("resize", () => { measure(); if (reduced) nave?.render(); });

// ── Tilt: cards lean towards the pointer and catch a little light.
const tilts = [];
if (fine && !reduced) {
  for (const el of $$("[data-tilt]")) {
    const t = { el, rx: 0, ry: 0, tx: 0, ty: 0, live: false };
    tilts.push(t);
    el.addEventListener("pointermove", (e) => {
      const r = el.getBoundingClientRect();
      const nx = (e.clientX - r.left) / r.width, ny = (e.clientY - r.top) / r.height;
      const max = Math.min(7, 2200 / r.width);
      t.ty = (nx - 0.5) * 2 * max;
      t.tx = (0.5 - ny) * 2 * max * 0.8;
      el.style.setProperty("--gx", `${(nx * 100).toFixed(1)}%`);
      el.style.setProperty("--gy", `${(ny * 100).toFixed(1)}%`);
      el.style.setProperty("--glare", "1");
      t.live = true;
    });
    el.addEventListener("pointerleave", () => { t.tx = t.ty = 0; el.style.setProperty("--glare", "0"); });
  }
}
const tickTilt = () => {
  for (const t of tilts) {
    if (!t.live) continue;
    t.rx += (t.tx - t.rx) * 0.12;
    t.ry += (t.ty - t.ry) * 0.12;
    if (Math.abs(t.rx) + Math.abs(t.ry) + Math.abs(t.tx) + Math.abs(t.ty) < 0.02) { t.rx = t.ry = 0; t.live = false; }
    t.el.style.setProperty("--rx", `${t.rx.toFixed(2)}deg`);
    t.el.style.setProperty("--ry", `${t.ry.toFixed(2)}deg`);
  }
};

// ── Magnetic buttons
if (fine && !reduced) {
  for (const el of $$("[data-magnet]")) {
    el.addEventListener("pointermove", (e) => {
      const r = el.getBoundingClientRect();
      el.style.setProperty("--bx", `${((e.clientX - r.left - r.width / 2) * 0.16).toFixed(1)}px`);
      el.style.setProperty("--by", `${((e.clientY - r.top - r.height / 2) * 0.3 - 2).toFixed(1)}px`);
    });
    el.addEventListener("pointerleave", () => { el.style.setProperty("--bx", "0px"); el.style.setProperty("--by", "0px"); });
  }
}

// ── Lantern
const lantern = $("[data-lantern]");
const tracery = lantern?.firstElementChild;
const lamp = { x: innerWidth / 2, y: innerHeight / 2, tx: innerWidth / 2, ty: innerHeight / 2, on: false };
if (lantern && fine && !reduced) {
  addEventListener("pointermove", (e) => {
    lamp.tx = e.clientX; lamp.ty = e.clientY;
    if (!lamp.on) { lamp.on = true; lamp.x = lamp.tx; lamp.y = lamp.ty; lantern.classList.add("is-on"); }
  }, { passive: true });
  document.addEventListener("pointerleave", () => { lamp.on = false; lantern.classList.remove("is-on"); });
}
const tickLantern = () => {
  if (!lamp.on) return;
  lamp.x += (lamp.tx - lamp.x) * 0.16;
  lamp.y += (lamp.ty - lamp.y) * 0.16;
  lantern.style.transform = `translate3d(${lamp.x.toFixed(1)}px, ${lamp.y.toFixed(1)}px, 0)`;
  // The tracery stays where it is carved: it moves against the lamp and with the page.
  tracery.style.transform = `translate3d(${(-(((lamp.x % 120) + 120) % 120)).toFixed(1)}px, ${(-((((lamp.y + scrollY) % 120) + 120) % 120)).toFixed(1)}px, 0)`;
};

// ── One loop for the whole page
const frame = (now) => {
  requestAnimationFrame(frame);
  if (dirty) { dirty = false; onScroll(); }
  tickTilt();
  tickLantern();
  nave?.tick(now);
  // A nave that costs this much at full size means a software rasteriser: start the stones on the plainest tier.
  if (relics && !hinted && nave?.state.full) { hinted = true; if (nave.state.full > 20) relics.setTier(0); }
  relics?.tick(now);
};
let hinted = false;

// ── Variant switches: the new variant spreads from the switch like light from a window.
for (const scope of $$("[data-variant-scope]")) {
  const buttons = $$("[data-set-variant]", scope);
  for (const btn of buttons) {
    btn.addEventListener("click", (e) => {
      const variant = btn.dataset.setVariant;
      if (scope.dataset.variant === variant) return;
      const apply = () => {
        scope.dataset.variant = variant;
        buttons.forEach((b) => {
          const on = b.dataset.setVariant === variant;
          b.classList.toggle("is-active", on);
          b.setAttribute("aria-pressed", String(on));
        });
        relics?.snap(scope);
      };
      if (reduced || !document.startViewTransition) return apply();
      const r = btn.getBoundingClientRect();
      const x = e.clientX || r.left + r.width / 2, y = e.clientY || r.top + r.height / 2;
      root.style.setProperty("--vt-x", `${x}px`);
      root.style.setProperty("--vt-y", `${y}px`);
      root.style.setProperty("--vt-r", `${Math.hypot(Math.max(x, innerWidth - x), Math.max(y, innerHeight - y))}px`);
      document.startViewTransition(apply);
    });
  }
}

// ── Editor tabs
for (const editor of $$("[data-tabs]")) {
  const tabs = $$("[data-tab]", editor);
  const panes = $$("[data-pane]", editor);
  const lang = $("[data-status-lang]", editor);
  const pos = $("[data-status-pos]", editor);
  for (const pane of panes) $$(".line", pane).forEach((line, i) => line.style.setProperty("--ln", i));
  const select = (i) => {
    tabs.forEach((t, j) => {
      t.classList.toggle("is-active", i === j);
      t.setAttribute("aria-selected", String(i === j));
      t.tabIndex = i === j ? 0 : -1;
    });
    panes.forEach((p, j) => { p.hidden = i !== j; p.classList.toggle("is-active", i === j); });
    const p = panes[i];
    lang.textContent = p.dataset.lang;
    pos.textContent = `Line ${p.dataset.ln}, Column ${p.dataset.col}`;
  };
  tabs.forEach((t, i) => {
    t.addEventListener("click", () => select(i));
    t.addEventListener("keydown", (e) => {
      const d = e.key === "ArrowRight" ? 1 : e.key === "ArrowLeft" ? -1 : 0;
      if (!d) return;
      const n = (i + d + tabs.length) % tabs.length;
      select(n);
      tabs[n].focus();
    });
  });
}

// ── Caret at the column shown in the status bar
for (const pane of $$("[data-pane]")) {
  const line = $(".hl .cl", pane);
  if (!line) continue;
  let left = Number(pane.dataset.col) - 1;
  const walker = document.createTreeWalker(line, NodeFilter.SHOW_TEXT);
  while (walker.nextNode()) {
    const node = walker.currentNode;
    if (left <= node.length) {
      const caret = document.createElement("span");
      caret.className = "caret";
      node.splitText(left).before(caret);
      break;
    }
    left -= node.length;
  }
}

// ── Legend: hover a material to find it in the code. Tokens are matched to materials by their computed colour.
const legend = $("[data-legend]");
const seeker = $(".editor");
if (legend && seeker) {
  const items = $$("[data-material]", legend);
  const byMaterial = new Map(items.map((b) => [b.dataset.material, []]));
  let tagged = false, locked = null;
  const tag = () => {
    if (tagged) return;
    tagged = true;
    const probe = document.createElement("span");
    seeker.append(probe);
    const colour = new Map();
    for (const key of byMaterial.keys()) {
      probe.style.color = `var(--syn-${key})`;
      colour.set(getComputedStyle(probe).color, key);
    }
    probe.remove();
    for (const span of $$(".cl span:not(.caret)", seeker)) {
      if (span.firstElementChild) continue;
      const key = colour.get(getComputedStyle(span).color);
      if (!key) continue;
      span.dataset.m = key;
      byMaterial.get(key).push(span);
    }
  };
  const seek = (key) => {
    tag();
    $$(".is-lit", seeker).forEach((s) => s.classList.remove("is-lit"));
    seeker.classList.toggle("is-seeking", Boolean(key));
    items.forEach((b) => b.classList.toggle("is-on", b.dataset.material === key));
    if (key) for (const s of byMaterial.get(key)) s.classList.add("is-lit");
  };
  for (const b of items) {
    b.addEventListener("pointerenter", () => seek(b.dataset.material));
    b.addEventListener("focus", () => seek(b.dataset.material));
    b.addEventListener("click", () => { locked = locked === b.dataset.material ? null : b.dataset.material; seek(locked); });
  }
  legend.addEventListener("pointerleave", () => seek(locked));
  legend.addEventListener("focusout", (e) => { if (!legend.contains(e.relatedTarget)) seek(locked); });
}

// ── Contrast chart: the ratios count up as the bars grow.
const chart = $("[data-chart]");
if (chart && !reduced) {
  const cells = $$("[data-count]", chart);
  new IntersectionObserver(([e], io) => {
    if (!e.isIntersecting) return;
    io.disconnect();
    const t0 = performance.now();
    const run = (now) => {
      let busy = false;
      cells.forEach((el, i) => {
        const k = clamp((now - t0 - (i >> 1) * 55) / 1500);
        if (k < 1) busy = true;
        el.textContent = (Number(el.dataset.count) * (1 - Math.pow(1 - k, 3))).toFixed(2);
      });
      if (busy) requestAnimationFrame(run);
    };
    requestAnimationFrame(run);
  }, { threshold: 0.12 }).observe(chart);
}

// ── Copy
const toast = $("[data-toast]");
let toastTimer;
const showToast = (text, colour) => {
  toast.innerHTML = "";
  const sw = document.createElement("i");
  sw.style.background = colour;
  toast.append(sw, text);
  toast.classList.add("is-visible");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.remove("is-visible"), 1800);
};
for (const plate of $$("[data-copy-o]")) {
  plate.addEventListener("click", async () => {
    const scope = plate.closest("[data-variant]");
    const hex = scope?.dataset.variant === "ivory" ? plate.dataset.copyI : plate.dataset.copyO;
    try {
      await navigator.clipboard.writeText(hex);
    } catch {
      /* clipboard unavailable (insecure context or permissions): still show the value */
    }
    showToast(`${hex} copied`, hex);
  });
}
for (const btn of $$("[data-copy-code]")) {
  btn.addEventListener("click", async () => {
    const code = $(btn.dataset.copyCode)?.querySelector("code");
    if (!code) return;
    try {
      await navigator.clipboard.writeText(code.textContent);
    } catch {
      /* clipboard unavailable: nothing to copy into */
    }
    showToast("Variables copied", "#c42740");
  });
}

// ── Raise the veil once the type is in, and light the windows.
measure();
requestAnimationFrame(frame);
const lift = () => {
  if (isReady) return;
  isReady = true;
  measure();
  if (nave && heroSeen) nave.start();
  requestAnimationFrame(() => requestAnimationFrame(() => root.classList.add("is-ready")));
};
(document.fonts?.ready ?? Promise.resolve()).then(lift);
setTimeout(lift, 900);
addEventListener("load", measure);
