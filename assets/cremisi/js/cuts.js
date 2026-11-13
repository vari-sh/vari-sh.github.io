// Gem cuts as sets of half-spaces. A plane is [nx, ny, nz, d] with a unit normal; the stone is the
// intersection of n·p <= d. Convex by construction, so a ray can be bounced inside it in closed form.

const TAU = Math.PI * 2;
const RAD = Math.PI / 180;

// A ring of `count` facets whose normals rise `elev` degrees above the horizon and pass through radius r at height y.
const ring = (out, count, elev, r, y, offset = 0) => {
  const c = Math.cos(elev * RAD), s = Math.sin(elev * RAD);
  for (let i = 0; i < count; i++) {
    const a = ((i + offset) / count) * TAU;
    out.push([c * Math.cos(a), s, c * Math.sin(a), c * r + s * y]);
  }
  return out;
};

// Facets tangent to an ellipsoid of semi-axes (a, b, c) centred at height cy.
const tangent = (out, n, a, b, c, cy = 0, k = 1) => {
  const l = Math.hypot(n[0], n[1], n[2]);
  const u = [n[0] / l, n[1] / l, n[2] / l];
  out.push([...u, Math.hypot(a * u[0], b * u[1], c * u[2]) * k + u[1] * cy]);
  return out;
};
const tangentRing = (out, count, elev, a, b, c, cy = 0, offset = 0) => {
  const ce = Math.cos(elev * RAD), se = Math.sin(elev * RAD);
  for (let i = 0; i < count; i++) {
    const ang = ((i + offset) / count) * TAU;
    tangent(out, [ce * Math.cos(ang), se, ce * Math.sin(ang)], a, b, c, cy);
  }
  return out;
};

const lift = (planes, dy) => planes.map(([x, y, z, d]) => [x, y, z, d + y * dy]);
const scale = (planes, k) => planes.map(([x, y, z, d]) => [x, y, z, d * k]);
const rng = (seed) => () => ((seed = (seed * 16807) % 2147483647) - 1) / 2147483646;

// Round brilliant: table, star facets, bezels, pavilion mains and lower halves.
const brilliant = (n = 8) => {
  const p = [[0, 1, 0, 0.3]];
  ring(p, n, 68, 0.58, 0.295, 0.5);
  ring(p, n, 56, 1, 0);
  ring(p, n, -49, 1, 0);
  ring(p, n, -44, 1.035, 0, 0.5);
  return lift(p, 0.27);
};

// Step cut: a chamfered rectangle in tiers.
const step = (ax, az, { table = 0.34, cham = 0.26, crown = [[42, 0, 0], [64, 0.2, 0.19]], pav = [[-40, 0, 0], [-57, 0.3, -0.27]], dy = 0.2 } = {}) => {
  const s = Math.SQRT1_2;
  const dirs = [[1, 0, ax], [-1, 0, ax], [0, 1, az], [0, -1, az], [s, s, (ax + az) * s - cham], [s, -s, (ax + az) * s - cham], [-s, s, (ax + az) * s - cham], [-s, -s, (ax + az) * s - cham]];
  const p = [[0, 1, 0, table]];
  for (const [elev, inset, y] of [...crown, ...pav]) {
    const c = Math.cos(elev * RAD), sn = Math.sin(elev * RAD);
    for (const [hx, hz, dh] of dirs) p.push([c * hx, sn, c * hz, c * (dh - inset) + sn * y]);
  }
  return lift(p, dy);
};

// A slab: the stone everything rests on.
const slab = () => {
  const p = step(1, 0.66, { table: 0.3, cham: 0.2, crown: [[45, 0.07, 0.3]], pav: [[0, 0, 0], [-45, 0.07, -0.3]], dy: 0 });
  p.push([0, -1, 0, 0.3]);
  return p;
};

// Briolette: a faceted drop, every plane tangent to one sphere so the upper ring closes into a point.
const briolette = () => {
  const p = [];
  const cy = -0.34, r = 0.6;
  for (const [count, elev, off] of [[8, 28, 0], [8, -8, 0.5], [8, -42, 0], [6, -72, 0.5]]) tangentRing(p, count, elev, r, r, r, cy, off);
  return p;
};

// A crystal point: hexagonal prism, uneven terminations.
const crystal = (double = false) => {
  const p = [];
  ring(p, 6, 0, 0.5, 0);
  for (let i = 0; i < 6; i++) p.push(ring([], 6, i % 2 ? 48 : 56, 0.5, i % 2 ? 0.5 : 0.56)[i]);
  if (double) ring(p, 6, -58, 0.5, -0.62, 0.5);
  else p.push([0, -1, 0, 0.92]);
  return lift(p, double ? 0 : 0.05);
};

// A nugget: irregular facets around an ellipsoid, for wax and resin.
const nugget = (seed, a, b, c, count = 20) => {
  const r = rng(seed), p = [];
  for (let i = 0; i < count; i++) {
    const y = 1 - ((i + 0.5) / count) * 2, rad = Math.sqrt(1 - y * y), ang = i * 2.39996 + r() * 0.5;
    const k = 0.86 + r() * 0.18;
    tangent(p, [Math.cos(ang) * rad + (r() - 0.5) * 0.3, y + (r() - 0.5) * 0.3, Math.sin(ang) * rad + (r() - 0.5) * 0.3], a, b, c, 0, k);
  }
  return p;
};

// A faceted bead.
const bead = (count, a, b, c) => {
  const p = [];
  for (let i = 0; i < count; i++) {
    const y = 1 - ((i + 0.5) / count) * 2, rad = Math.sqrt(1 - y * y), ang = i * 2.39996;
    tangent(p, [Math.cos(ang) * rad, y, Math.sin(ang) * rad], a, b, c);
  }
  return p;
};

// Octahedron with its points struck off: a nail head, a copper crystal.
const octa = (a, b, c, trunc = 0.7) => {
  const p = [];
  for (const sx of [1, -1]) for (const sy of [1, -1]) for (const sz of [1, -1]) {
    const n = [sx / a, sy / b, sz / c], l = Math.hypot(...n);
    p.push([n[0] / l, n[1] / l, n[2] / l, 1 / l]);
  }
  for (const s of [1, -1]) p.push([s, 0, 0, a * trunc], [0, s, 0, b * trunc], [0, 0, s, c * trunc]);
  return p;
};

// A baton of bone: a hexagonal shaft with bevelled ends.
const baton = () => {
  const p = [];
  ring(p, 6, 0, 0.34, 0);
  ring(p, 6, 50, 0.34, 0.74);
  ring(p, 6, -50, 0.34, -0.74);
  ring(p, 6, 24, 0.37, 0.5, 0.5);
  ring(p, 6, -24, 0.37, -0.5, 0.5);
  p.push([0, 1, 0, 0.94], [0, -1, 0, 0.94]);
  return p;
};

// A seal: a bevelled disc.
const seal = (n = 10) => {
  const p = [[0, 1, 0, 0.2], [0, -1, 0, 0.2]];
  ring(p, n, 0, 0.94, 0);
  ring(p, n, 48, 0.86, 0.2, 0.5);
  ring(p, n, -48, 0.86, -0.2, 0.5);
  return p;
};

// Rose cut: flat back, domed crown.
const roseCut = () => {
  const p = [[0, -1, 0, 0.3]];
  tangentRing(p, 6, 74, 0.98, 0.66, 0.98, -0.3, 0);
  tangentRing(p, 12, 44, 0.98, 0.66, 0.98, -0.3, 0.5);
  tangentRing(p, 12, 14, 0.98, 0.66, 0.98, -0.3, 0);
  return lift(p, -0.04);
};

// Marquise: the pointed oval.
const marquise = () => {
  const p = [[0, 1, 0, 0.3]];
  const [a, b, c] = [1.14, 0.5, 0.56];
  tangentRing(p, 8, 58, a, b, c, 0, 0.5);
  tangentRing(p, 8, 22, a, b, c, 0, 0);
  tangentRing(p, 8, -30, a, b, c, 0, 0.5);
  tangentRing(p, 8, -62, a, b, c, 0, 0);
  return lift(p, 0.08);
};

// trans: how much light passes through · ior · gloss · metal · glow: light the stone gives off by itself
export const RELICS = {
  ground: { cut: () => slab(), trans: 0, ior: 1.5, gloss: 0.55, metal: 0, tilt: 0.42, size: 0.98 },
  ink: { cut: () => baton(), trans: 0.12, ior: 1.5, gloss: 0.5, metal: 0, tilt: 0.3, lean: 0.5, size: 1.05 },
  iron: { cut: () => octa(0.95, 1.1, 0.95, 0.84), trans: 0, ior: 2.4, gloss: 0.9, metal: 1, tilt: 0.42, lean: 0.2 },
  incense: { cut: () => crystal(false), trans: 0.82, ior: 1.5, gloss: 1, metal: 0, tilt: 0.2, lean: 0.25, milk: 0.35 },
  crimson: { cut: () => brilliant(8), trans: 1, ior: 2.1, gloss: 1, metal: 0, tilt: 0.62, density: 0.95 },
  crimson_deep: { cut: () => step(0.96, 0.7), trans: 1, ior: 1.85, gloss: 1, metal: 0, tilt: 0.7, density: 0.6 },
  blood: { cut: () => briolette(), trans: 1, ior: 1.7, gloss: 1, metal: 0, tilt: 0.12, density: 0.9, size: 1.05 },
  lapis: { cut: () => bead(30, 0.9, 0.84, 0.9), trans: 0.1, ior: 1.6, gloss: 0.75, metal: 0, tilt: 0.3 },
  tallow: { cut: () => nugget(11, 0.86, 0.98, 0.8, 20), trans: 0.6, ior: 1.44, gloss: 0.6, metal: 0, tilt: 0.25, milk: 0.6 },
  amber: { cut: () => nugget(47, 1.02, 0.8, 0.86, 18), trans: 1, ior: 1.54, gloss: 1, metal: 0, tilt: 0.3, density: 0.55, glow: 0.25 },
  sealwax: { cut: () => seal(10), trans: 0.05, ior: 1.5, gloss: 0.85, metal: 0, tilt: 1.05 },
  malachite: { cut: () => step(0.8, 0.8, { cham: 0.3 }), trans: 0.3, ior: 1.66, gloss: 0.9, metal: 0, tilt: 0.7, density: 0.9 },
  verdigris: { cut: () => octa(0.92, 1.12, 0.92, 0.9), trans: 0, ior: 1.8, gloss: 0.45, metal: 0.55, tilt: 0.34, lean: -0.25 },
  amethyst: { cut: () => crystal(true), trans: 1, ior: 1.58, gloss: 1, metal: 0, tilt: 0.2, lean: -0.3, density: 0.6, size: 1.06 },
  wine: { cut: () => roseCut(), trans: 1, ior: 1.8, gloss: 1, metal: 0, tilt: 0.85, density: 0.8 },
  petal: { cut: () => marquise(), trans: 0.92, ior: 1.7, gloss: 1, metal: 0, tilt: 0.75, lean: 0.45, density: 0.7, milk: 0.1 },
};

// Vertices and faces of the solid bounded by the planes. Returns interleaved position + normal triangles.
export function hull(planes) {
  const n = planes.length, verts = [], EPS = 1e-6;
  for (let i = 0; i < n; i++) for (let j = i + 1; j < n; j++) for (let k = j + 1; k < n; k++) {
    const a = planes[i], b = planes[j], c = planes[k];
    const bc = [b[1] * c[2] - b[2] * c[1], b[2] * c[0] - b[0] * c[2], b[0] * c[1] - b[1] * c[0]];
    const det = a[0] * bc[0] + a[1] * bc[1] + a[2] * bc[2];
    if (Math.abs(det) < 1e-9) continue;
    const ca = [c[1] * a[2] - c[2] * a[1], c[2] * a[0] - c[0] * a[2], c[0] * a[1] - c[1] * a[0]];
    const ab = [a[1] * b[2] - a[2] * b[1], a[2] * b[0] - a[0] * b[2], a[0] * b[1] - a[1] * b[0]];
    const p = [0, 1, 2].map((m) => (a[3] * bc[m] + b[3] * ca[m] + c[3] * ab[m]) / det);
    if (planes.some((q) => q[0] * p[0] + q[1] * p[1] + q[2] * p[2] > q[3] + EPS)) continue;
    if (!verts.some((v) => Math.hypot(v[0] - p[0], v[1] - p[1], v[2] - p[2]) < 1e-5)) verts.push(p);
  }
  const out = [], used = [];
  let radius = 0, faces = 0;
  for (const v of verts) radius = Math.max(radius, Math.hypot(...v));
  for (const q of planes) {
    const on = verts.filter((v) => Math.abs(q[0] * v[0] + q[1] * v[1] + q[2] * v[2] - q[3]) < 1e-5);
    if (on.length < 3) continue;
    const c = [0, 1, 2].map((m) => on.reduce((s, v) => s + v[m], 0) / on.length);
    const ref = Math.abs(q[1]) < 0.9 ? [0, 1, 0] : [1, 0, 0];
    let u = [ref[1] * q[2] - ref[2] * q[1], ref[2] * q[0] - ref[0] * q[2], ref[0] * q[1] - ref[1] * q[0]];
    const ul = Math.hypot(...u);
    u = u.map((x) => x / ul);
    const w = [q[1] * u[2] - q[2] * u[1], q[2] * u[0] - q[0] * u[2], q[0] * u[1] - q[1] * u[0]];
    const ang = (v) => Math.atan2((v[0] - c[0]) * w[0] + (v[1] - c[1]) * w[1] + (v[2] - c[2]) * w[2], (v[0] - c[0]) * u[0] + (v[1] - c[1]) * u[1] + (v[2] - c[2]) * u[2]);
    on.sort((p1, p2) => ang(p1) - ang(p2));
    for (let i = 1; i + 1 < on.length; i++) for (const v of [on[0], on[i], on[i + 1]]) out.push(v[0], v[1], v[2], q[0], q[1], q[2]);
    faces++;
    used.push(q);
  }
  return { data: new Float32Array(out), count: out.length / 6, radius, faces, verts: verts.length, used };
}

export const cutFor = (key) => {
  const spec = RELICS[key] || RELICS.crimson;
  let planes = spec.cut();
  const mesh = hull(planes);
  // Normalise every stone to the same bounding radius, then apply its own size.
  const k = ((spec.size || 1) * 1.0) / mesh.radius;
  planes = scale(mesh.used, k);
  for (let i = 0; i < mesh.data.length; i += 6) { mesh.data[i] *= k; mesh.data[i + 1] *= k; mesh.data[i + 2] *= k; }
  return { spec, planes, mesh };
};
