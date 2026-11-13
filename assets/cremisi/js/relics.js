// The reliquary: every material as a cut stone. The front faces are rasterised, then each fragment
// refracts into the solid and bounces between its facets analytically, absorbing the material's
// colour along the way. Every stone in view is drawn into one atlas, read back once per frame and
// handed to its niche: a single readback costs far less than one per canvas.

import { cutFor } from "./cuts.js";
import { srgbToLinear } from "./nave.js";

const MAXP = 34;

const VERT = `#version 300 es
in vec3 aPos;
in vec3 aNor;
uniform mat3 uRot;
uniform float uFocal, uDist;
out vec3 vP;
out vec3 vN;
void main() {
  vP = aPos; vN = aNor;
  vec3 w = uRot * aPos;
  gl_Position = vec4(w.x * uFocal, -w.y * uFocal, -w.z * .1, uDist - w.z);
}`;

const FRAG = `#version 300 es
precision highp float;
#define MAXP ${MAXP}
uniform vec4 uPl[MAXP];
uniform int uCount, uBounces;
uniform mat3 uRot;
uniform vec3 uCamObj, uCol, uEnvA, uEnvB;
uniform vec4 uMat;   // transmission, ior, gloss, metal
uniform vec4 uFx;    // density, milk, glow, lit
uniform float uDisp;
in vec3 vP;
in vec3 vN;
out vec4 outColor;

const vec3 KEY = vec3(-.46, .66, .59), RIM = vec3(.74, .22, -.63), C1 = vec3(.31, .5, .81), C2 = vec3(-.79, -.1, .6);

// The room around the stone: a crypt with one tall window, a cold rim and two candles.
vec3 env(vec3 d) {
  float bands = .5 + .5 * sin(d.y * 10. + d.x * 5. + d.z * 3.);
  vec3 c = mix(uEnvA, uEnvB, .5 + .5 * d.y) * (.5 + .8 * bands * bands);
  c += vec3(1., .93, .84) * smoothstep(.74, .95, dot(d, KEY)) * 4.2;
  c += vec3(.72, .8, 1.) * smoothstep(.72, .96, dot(d, RIM)) * 2.2;
  c += vec3(1., .26, .32) * smoothstep(.45, 1., -d.y) * .45;
  c += vec3(1., .8, .55) * pow(max(dot(d, C1), 0.), 160.) * 12.;
  c += vec3(1., .86, .7) * pow(max(dot(d, C2), 0.), 220.) * 9.;
  return c;
}

void main() {
  vec3 n = normalize(vN), rd = normalize(vP - uCamObj);
  float ior = uMat.y, c0 = max(dot(-rd, n), 0.);
  float f0 = (ior - 1.) / (ior + 1.); f0 *= f0;
  float F = f0 + (1. - f0) * pow(1. - c0, 5.);
  vec3 refl = env(uRot * reflect(rd, n));
  vec3 nw = uRot * n;

  // Opaque matter: stone, bone, wax, metal.
  float dif = max(dot(nw, KEY), 0.) * .95 + max(dot(nw, RIM), 0.) * .3 + .12 + .1 * nw.y;
  vec3 surf = uCol * dif * vec3(1., .96, .9) + refl * F * uMat.z + mix(uEnvB, vec3(.5, .54, .66), .5) * pow(1. - c0, 3.) * .5;
  surf = mix(surf, refl * mix(uCol, vec3(1.), F) * (.35 + .65 * uMat.z) + uCol * dif * .25, uMat.w);

  vec3 col = surf;
  if (uMat.x > .01) {
    vec3 d = refract(rd, n, 1. / ior), o = vP, thr = vec3(1.), acc = vec3(0.);
    vec3 sig = -log(max(uCol, vec3(.012))) * uFx.x;
    for (int b = 0; b < 4; b++) {
      if (b >= uBounces) break;
      float t = 1e9; vec3 ne = n;
      for (int i = 0; i < MAXP; i++) {
        if (i >= uCount) break;
        vec4 pl = uPl[i];
        float dn = dot(pl.xyz, d);
        if (dn > 1e-5) { float tt = (pl.w - dot(pl.xyz, o)) / dn; if (tt < t) { t = tt; ne = pl.xyz; } }
      }
      thr *= exp(-sig * t);
      o += d * t;
      vec3 od = refract(d, -ne, ior);
      float Fi = 1.;
      if (dot(od, od) > 0.) {
        Fi = f0 + (1. - f0) * pow(1. - max(dot(od, ne), 0.), 5.);
        vec3 e = env(uRot * od);
        if (uDisp > 0.) {
          vec3 o1 = refract(d, -ne, ior * (1. - .035 * uDisp)), o2 = refract(d, -ne, ior * (1. + .03 * uDisp));
          e.r = dot(o1, o1) > 0. ? env(uRot * o1).r : e.r;
          e.b = dot(o2, o2) > 0. ? env(uRot * o2).b : 0.;
        }
        acc += thr * (1. - Fi) * e;
      }
      thr *= Fi;
      d = reflect(d, ne);
    }
    acc += thr * mix(uEnvB, uCol, .6) * .5;
    // Milk: wax and smoke scatter the light instead of carrying it.
    acc = mix(acc, uCol * (dif * .8 + .3), uFx.y);
    acc += uCol * uFx.z * (.4 + .6 * c0);
    col = mix(surf, acc * (1. - F) + refl * F, uMat.x);
  }
  col *= 1. + .35 * uFx.w;
  col = 1. - exp(-col * 1.25);
  outColor = vec4(pow(col, vec3(.4545)), 1.);
}`;

const compile = (gl, type, src) => {
  const s = gl.createShader(type);
  gl.shaderSource(s, src);
  gl.compileShader(s);
  if (!gl.getShaderParameter(s, gl.COMPILE_STATUS)) throw new Error(gl.getShaderInfoLog(s));
  return s;
};

const DIST = 5.4;
const FOCAL = 4.55;

// canvases: <canvas data-relic="blood" data-o="#e2586a" data-i="#bb1f39"> inside a [data-variant] scope.
export function createRelics(canvases, { still = false } = {}) {
  const glc = document.createElement("canvas");
  const gl = glc.getContext("webgl2", { antialias: true, alpha: true, premultipliedAlpha: true, depth: false, stencil: false });
  if (!gl) return null;
  let prog;
  try {
    prog = gl.createProgram();
    gl.attachShader(prog, compile(gl, gl.VERTEX_SHADER, VERT));
    gl.attachShader(prog, compile(gl, gl.FRAGMENT_SHADER, FRAG));
    gl.bindAttribLocation(prog, 0, "aPos");
    gl.bindAttribLocation(prog, 1, "aNor");
    gl.linkProgram(prog);
    if (!gl.getProgramParameter(prog, gl.LINK_STATUS)) throw new Error(gl.getProgramInfoLog(prog));
  } catch (err) {
    console.warn("Cremisi relics: shader failed", err);
    return null;
  }
  gl.useProgram(prog);
  gl.enable(gl.CULL_FACE);
  gl.frontFace(gl.CW);
  gl.enable(gl.SCISSOR_TEST);
  gl.clearColor(0, 0, 0, 0);
  const U = Object.fromEntries(["uPl", "uCount", "uBounces", "uRot", "uFocal", "uDist", "uCamObj", "uCol", "uEnvA", "uEnvB", "uMat", "uFx", "uDisp"].map((n) => [n, gl.getUniformLocation(prog, n)]));
  gl.uniform1f(U.uFocal, FOCAL);
  gl.uniform1f(U.uDist, DIST);

  const cuts = new Map();
  const cut = (key) => {
    if (cuts.has(key)) return cuts.get(key);
    const { spec, planes, mesh } = cutFor(key);
    const vao = gl.createVertexArray();
    gl.bindVertexArray(vao);
    gl.bindBuffer(gl.ARRAY_BUFFER, gl.createBuffer());
    gl.bufferData(gl.ARRAY_BUFFER, mesh.data, gl.STATIC_DRAW);
    gl.enableVertexAttribArray(0);
    gl.vertexAttribPointer(0, 3, gl.FLOAT, false, 24, 0);
    gl.enableVertexAttribArray(1);
    gl.vertexAttribPointer(1, 3, gl.FLOAT, false, 24, 12);
    const pl = new Float32Array(MAXP * 4);
    planes.slice(0, MAXP).forEach((p, i) => pl.set(p, i * 4));
    const c = { spec, vao, count: mesh.count, pl, n: Math.min(planes.length, MAXP) };
    cuts.set(key, c);
    return c;
  };

  const dpr = Math.min(window.devicePixelRatio || 1, 2);
  const slots = [...canvases].map((el, i) => {
    const key = el.dataset.relic;
    return {
      el, key, ctx: el.getContext("2d"), cut: cut(key),
      o: srgbToLinear(el.dataset.o), i: srgbToLinear(el.dataset.i || el.dataset.o),
      scope: el.closest("[data-variant]"), card: el.closest("[data-relic-card]") || el.parentElement,
      mix: 0, yaw: i * 1.7 + 0.4, vel: 0.26 + (i % 5) * 0.035, kick: 0, px: 0, py: 0, tx: 0, ty: 0, lit: 0, hover: false,
      visible: false, size: 0, dirty: true,
    };
  });

  const COLS = 4;
  let pixels = new Uint8ClampedArray(4);
  const measure = () => {
    for (const s of slots) {
      const size = Math.max(2, Math.round(s.el.clientWidth * dpr * state.res));
      if (size !== s.size) { s.size = s.el.width = s.el.height = size; s.dirty = true; }
    }
  };
  const io = new IntersectionObserver((entries) => {
    for (const e of entries) {
      const s = slots.find((x) => x.el === e.target);
      if (s) { s.visible = e.isIntersecting; s.dirty = true; }
    }
  }, { rootMargin: "120px 0px" });
  for (const s of slots) {
    io.observe(s.el);
    const card = s.card;
    card.addEventListener("pointerenter", () => { s.hover = true; });
    card.addEventListener("pointerleave", () => { s.hover = false; s.tx = s.ty = 0; });
    card.addEventListener("pointermove", (e) => {
      const r = card.getBoundingClientRect();
      s.tx = ((e.clientX - r.left) / r.width) * 2 - 1;
      s.ty = ((e.clientY - r.top) / r.height) * 2 - 1;
    });
    card.addEventListener("click", () => { s.kick = 9; });
  }

  const draw = (s, x, y) => {
    const { spec } = s.cut;
    gl.viewport(x, y, s.size, s.size);

    // Rotation: spin about the stone's own axis, then tilt it towards the eye.
    const tilt = (spec.tilt || 0.3) + s.py * 0.5, lean = spec.lean || 0, yaw = s.yaw + s.px * 0.9;
    const cy = Math.cos(yaw), sy = Math.sin(yaw), cx = Math.cos(tilt), sx = Math.sin(tilt), cz = Math.cos(lean), sz = Math.sin(lean);
    // R = Rz(lean) · Rx(tilt) · Ry(yaw), column-major.
    const m = [
      cz * cy - sz * sx * sy, sz * cy + cz * sx * sy, -cx * sy,
      -sz * cx, cz * cx, sx,
      cz * sy + sz * sx * cy, sz * sy - cz * sx * cy, cx * cy,
    ];
    gl.uniformMatrix3fv(U.uRot, false, m);
    // Camera at (0, 0, DIST) in the world: into object space with the transpose.
    gl.uniform3f(U.uCamObj, m[2] * DIST, m[5] * DIST, m[8] * DIST);
    const k = s.mix;
    gl.uniform3f(U.uCol, s.o[0] + (s.i[0] - s.o[0]) * k, s.o[1] + (s.i[1] - s.o[1]) * k, s.o[2] + (s.i[2] - s.o[2]) * k);
    gl.uniform3f(U.uEnvA, 0.012 + 0.5 * k, 0.012 + 0.45 * k, 0.018 + 0.36 * k);
    gl.uniform3f(U.uEnvB, 0.06 + 0.84 * k, 0.06 + 0.78 * k, 0.085 + 0.66 * k);
    gl.uniform4f(U.uMat, spec.trans, spec.ior, spec.gloss, spec.metal);
    gl.uniform4f(U.uFx, spec.density || 0.5, spec.milk || 0, spec.glow || 0, s.lit);
    gl.uniform4fv(U.uPl, s.cut.pl);
    gl.uniform1i(U.uCount, s.cut.n);
    gl.bindVertexArray(s.cut.vao);
    gl.drawArrays(gl.TRIANGLES, 0, s.cut.count);
  };

  // Draw the given stones into the atlas, read it back once, and hand each its own rectangle.
  const render = (list) => {
    if (!list.length) return;
    const cell = list.reduce((m, s) => Math.max(m, s.size), 2);
    const w = Math.min(list.length, COLS) * cell, h = Math.ceil(list.length / COLS) * cell;
    if (glc.width < w || glc.height < h) { glc.width = Math.max(glc.width, w); glc.height = Math.max(glc.height, h); }
    gl.scissor(0, 0, w, h);
    gl.clear(gl.COLOR_BUFFER_BIT);
    gl.uniform1f(U.uDisp, state.tier > 2 ? 1 : 0);
    gl.uniform1i(U.uBounces, state.tier > 1 ? 3 : 2);
    list.forEach((s, i) => draw(s, (i % COLS) * cell, Math.floor(i / COLS) * cell));
    const n = w * h * 4;
    if (pixels.length < n) pixels = new Uint8ClampedArray(n);
    gl.readPixels(0, 0, w, h, gl.RGBA, gl.UNSIGNED_BYTE, pixels);
    // The edges come back premultiplied; ImageData wants them straight.
    for (let i = 3; i < n; i += 4) {
      const a = pixels[i];
      if (a === 0 || a === 255) continue;
      const k = 255 / a;
      pixels[i - 3] *= k; pixels[i - 2] *= k; pixels[i - 1] *= k;
    }
    const img = new ImageData(pixels.subarray(0, n), w, h);
    list.forEach((s, i) => {
      const x = (i % COLS) * cell, y = Math.floor(i / COLS) * cell;
      s.ctx.putImageData(img, -x, -y, x, y, s.size, s.size);
      s.dirty = false;
    });
  };

  // The tier follows the measured cost of a pass (the readback waits for the rasteriser, so the clock is honest):
  // 3 three bounces with dispersion · 2 three bounces · 1 two bounces · 0 smaller and at half rate ·
  // -1 only the stones being touched move.
  const state = { tier: 3, res: 1, over: 0, under: 0, hold: 0, skip: 0, last: 0, cost: 0 };
  const setTier = (tier) => {
    state.tier = Math.max(-1, Math.min(3, tier));
    state.over = state.under = 0;
    const res = state.tier < 1 ? 0.75 : 1;
    if (res !== state.res) { state.res = res; measure(); }
  };
  measure();
  new ResizeObserver(measure).observe(document.documentElement);

  const tick = (now) => {
    const live = slots.filter((s) => s.visible && s.size > 2);
    if (!live.length) { state.last = 0; return; }
    const dt = state.last ? Math.min(now - state.last, 100) : 16;
    state.last = now;
    const step = dt / 1000;
    for (const s of live) {
      const target = s.scope && s.scope.dataset.variant === "ivory" ? 1 : 0;
      s.busy = s.hover || s.kick > 0.05 || Math.abs(target - s.mix) > 0.004 || s.lit > 0.01;
      s.mix += (target - s.mix) * Math.min(1, step * 5);
      s.px += (s.tx - s.px) * Math.min(1, step * 6);
      s.py += (s.ty - s.py) * Math.min(1, step * 6);
      s.lit += ((s.hover ? 1 : 0) - s.lit) * Math.min(1, step * 6);
      s.kick *= Math.exp(-step * 2.6);
      if (state.tier >= 0 || s.busy) s.yaw += (s.vel * (1 + s.lit * 1.5) + s.kick) * step;
    }
    if (still || state.tier < 0) { render(live.filter((s) => s.dirty || (!still && s.busy))); return; }
    if (state.tier === 0 && (state.skip ^= 1)) return;
    const a = performance.now();
    render(live);
    const cost = performance.now() - a;
    state.cost = state.cost * 0.9 + cost * 0.1;
    const limit = state.tier === 0 ? 20 : 8;
    if (cost > limit) { state.over++; state.under = 0; } else if (cost < 2.5) { state.under++; state.over = 0; } else state.over = Math.max(0, state.over - 1);
    if (state.over > 8) { setTier(state.tier - 1); state.hold = now + 30000; }
    else if (state.under > 240 && state.tier < 3 && now > state.hold) setTier(state.tier + 1);
  };

  return {
    slots, state, tick, measure, setTier,
    // Jump straight to a scope's variant (used inside a view transition, where the new state is photographed at once).
    snap(scope) {
      for (const s of slots) {
        if (s.scope !== scope) continue;
        s.mix = scope.dataset.variant === "ivory" ? 1 : 0;
      }
      render(slots.filter((s) => s.scope === scope && s.visible && s.size > 2));
    },
  };
}
