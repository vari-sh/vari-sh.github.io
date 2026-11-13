// Chroma is coarser than the editors' grammars. These passes restore, token by token, the distinctions
// the theme draws: control flow, imports, booleans, properties, docstrings, separators, placeholders.

const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

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
// ...and C's NULL is a builtin name to Chroma.
for (const el of $$('[data-lang="C"] .chroma .nb')) {
  if (NULLS.has(el.textContent.trim())) el.classList.add("is-null");
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

// Chroma reads Python docstrings as plain strings: a string that opens its line with """ or ''' is documentation.
let docQuote = null;
for (const el of $$('[data-lang="Python"] .chroma .s1, [data-lang="Python"] .chroma .s2, [data-lang="Python"] .chroma .sd')) {
  const text = el.textContent.trim();
  if (!docQuote) {
    let prev = el.previousSibling;
    while (prev && !prev.textContent.trim()) prev = prev.previousSibling;
    const quote = text.slice(0, 3);
    if (prev || (quote !== '"""' && quote !== "'''")) continue;
    docQuote = text.length > 3 && text.endsWith(quote) ? null : quote;
  } else if (text.includes(docQuote)) docQuote = null;
  el.classList.add("is-doc");
}

// Chroma leaves the key-value colon of YAML and JSON as plain punctuation.
for (const el of $$('[data-lang="YAML"] .chroma .p, [data-lang="JSON"] .chroma .p')) {
  if (el.textContent.trim() === ":") el.classList.add("is-sep");
}
for (const el of $$('[data-lang="YAML"] .chroma .l')) {
  if (el.textContent.startsWith("%")) el.classList.add("is-directive");
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
