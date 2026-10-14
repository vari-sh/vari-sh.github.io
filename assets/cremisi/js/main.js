const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

// Nav
const nav = document.querySelector("[data-nav]");
if (nav) {
  const onScroll = () => nav.classList.toggle("is-scrolled", window.scrollY > 40);
  onScroll();
  window.addEventListener("scroll", onScroll, { passive: true });
}

// Title spotlight
for (const el of $$("[data-spotlight]")) {
  let tx = 0, ty = 0, x = 0, y = 0, raf = 0;
  const paint = () => {
    el.style.setProperty("--mx", `${x}px`);
    el.style.setProperty("--my", `${y}px`);
  };
  const step = () => {
    x += (tx - x) * 0.12;
    y += (ty - y) * 0.12;
    paint();
    raf = Math.abs(tx - x) + Math.abs(ty - y) > 0.5 ? requestAnimationFrame(step) : 0;
  };
  const target = (e) => {
    const r = el.getBoundingClientRect();
    tx = e.clientX - r.left;
    ty = e.clientY - r.top;
  };
  el.addEventListener("pointerenter", (e) => {
    target(e);
    x = tx;
    y = ty;
    paint();
  });
  el.addEventListener("pointermove", (e) => {
    target(e);
    if (!raf) raf = requestAnimationFrame(step);
  });
}

const links = $$(".nav-links a");
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

// Reveal
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
$$(".reveal, .chart").forEach((el) => reveal.observe(el));

// Variant switches
for (const scope of $$("[data-variant-scope]")) {
  const buttons = $$("[data-set-variant]", scope);
  for (const btn of buttons) {
    btn.addEventListener("click", () => {
      scope.dataset.variant = btn.dataset.setVariant;
      buttons.forEach((b) => {
        const on = b === btn;
        b.classList.toggle("is-active", on);
        b.setAttribute("aria-pressed", String(on));
      });
    });
  }
}

// Editor tabs
for (const editor of $$("[data-tabs]")) {
  const tabs = $$("[data-tab]", editor);
  const panes = $$("[data-pane]", editor);
  const lang = editor.querySelector("[data-status-lang]");
  const pos = editor.querySelector("[data-status-pos]");
  const select = (i) => {
    tabs.forEach((t, j) => {
      t.classList.toggle("is-active", i === j);
      t.setAttribute("aria-selected", String(i === j));
      t.tabIndex = i === j ? 0 : -1;
    });
    panes.forEach((p, j) => (p.hidden = i !== j));
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

// Chroma does not tell control flow apart from other keywords, so restore it word by word.
const CTRL = new Set("if elif else for while do return match case switch default break continue loop yield try except finally catch throw raise goto await".split(" "));
const IMPORT = new Set("use import from export mod extern".split(" "));
const NULLS = new Set("None null undefined nil".split(" "));
const BOOLS = new Set("True False true false".split(" "));
for (const el of $$(".chroma .k, .chroma .kr, .chroma .kc")) {
  const w = el.textContent.trim();
  if (el.classList.contains("kc")) {
    if (BOOLS.has(w)) el.classList.add("is-bool");
    else if (NULLS.has(w)) el.classList.add("is-null");
  } else if (CTRL.has(w)) el.classList.add("is-ctrl");
  else if (IMPORT.has(w)) el.classList.add("is-import");
  else if (NULLS.has(w)) el.classList.add("is-null");
  else el.classList.add("is-decl");
}

// Chroma leaves member access as plain names: after . or -> and not called, it is a property.
const tokenAfter = (el) => {
  let n = el.nextSibling;
  while (n && !n.textContent.trim()) n = n.nextSibling;
  return n ? n.textContent.trim() : "";
};
for (const el of $$(".chroma .n, .chroma .nx")) {
  const prev = el.previousSibling;
  if (prev && (prev.textContent.endsWith(".") || prev.textContent === "->") && !tokenAfter(el).startsWith("(")) el.classList.add("is-prop");
}

// Chroma does not mark printf placeholders in C strings: wrap them like the other interpolations.
for (const el of $$('[data-lang="C"] .chroma .s')) {
  if (!el.textContent.includes("%")) continue;
  el.innerHTML = el.textContent
    .replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" })[c])
    .replace(/%(?:%|[-+ #0]*\d*(?:\.\d+)?(?:hh|h|ll|l|z|j|t|L)?[diouxXeEfFgGaAcspn])/g, (m) => m === "%%" ? `<span class="se">${m}</span>` : `<span class="si">${m}</span>`);
}

// Caret at the column shown in the status bar
for (const pane of $$("[data-pane]")) {
  const line = pane.querySelector(".hl .cl");
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

// Copy hex
const toast = document.querySelector("[data-toast]");
let toastTimer;
const showToast = (hex) => {
  toast.innerHTML = "";
  const sw = document.createElement("i");
  sw.style.background = hex;
  toast.append(sw, `${hex} copied`);
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
    showToast(hex);
  });
}
