// The nave: a gothic interior traced analytically in a fragment shader. No meshes: every ray is
// intersected in closed form with the floor, the walls (slabs with their arcades, triforium and
// clerestory cut through), the clustered piers, the pointed vault and the end wall. One building,
// traced by the same code (BASE, TRACE), in two cuts that light it differently:
//  - The plain nave (FRAG): the rose and the windows, one ray and its reflection a pixel. Cheap
//    enough for software rasterisers, and where every visit starts.
//  - The full nave (HQ_FRAG and its passes), when a frame proves there is a real GPU behind the
//    canvas: the sun through the glass, on the floor and in the air, soft shadows from the rose,
//    richer stone and glass, supersampling and bloom. Its resolution and sample count follow the
//    measured cost of a frame.
// The glass takes its colours from the palette in data/cremisi.yaml.

const VERT = `#version 300 es
in vec2 aPos;
void main() { gl_Position = vec4(aPos, 0., 1.); }`;

// ── Shared by every cut of the nave: the building's measures, a few helpers, its openings.
const BASE = `#version 300 es
precision highp float;
uniform vec2 uRes;
uniform float uTime, uFocal, uIgnite, uPix;
uniform vec3 uCam;
uniform mat3 uBasis;
uniform vec3 uPal[12];
uniform vec3 uBay[20];
uniform vec3 uRose;
uniform int uMarch, uBounces;
out vec4 outColor;

#define TAU 6.2831853
const float WN = 3.2, WA = 6.8, BAY = 4.4, CR = .44, CAPR = .6, SHR = .19, HTOP = 5.14, WT = .25;
const float HCAP = 5., HS = 1.8, RAD = 3.4;
const float HAISLE = 8.9, HCL0 = 10.2, HCLS = 13.1, HV = 15.4, VC = 1.7, RV = WN + VC;
const float ZEND = 39.6, HROSE = 11.3, RROSE = 2.8;
const vec3 ROSECOL = vec3(1., .40, .44);
const vec3 LROSE = vec3(0., HROSE, ZEND - .4);
const int JEWEL[6] = int[6](1, 2, 5, 3, 7, 6);
const int ENDL[5] = int[5](1, 10, 2, 10, 5);

float h21(vec2 p) { p = fract(p * vec2(123.34, 456.21)); p += dot(p, p + 45.32); return fract(p.x * p.y); }
float vnoise(vec2 p) {
  vec2 i = floor(p), f = fract(p); f = f * f * (3. - 2. * f);
  return mix(mix(h21(i), h21(i + vec2(1, 0)), f.x), mix(h21(i + vec2(0, 1)), h21(i + vec2(1, 1)), f.x), f.y);
}
float sdArch(vec2 p, float hs, float rad) { p.x = abs(p.x); return p.y < 0. ? p.x - hs : length(vec2(p.x + rad - hs, p.y)) - rad; }
float sdUCap(vec2 p, float r1, float r2, float h) {
  p.x = abs(p.x);
  float b = (r1 - r2) / h, a = sqrt(1. - b * b), k = dot(p, vec2(-b, a));
  if (k < 0.) return length(p) - r1;
  if (k > a * h) return length(p - vec2(0., h)) - r2;
  return dot(p, vec2(a, b)) - r1;
}

// The windows light up bay by bay, from the rose towards the viewer.
float roseIgn() { return smoothstep(0., .16, uIgnite); }
float ign(float k) { return smoothstep(0., 1., uIgnite * 13. - (10. - max(k, -1.))); }
vec3 bayTint(float k, float side) { return uBay[int(clamp(k, -1., 8.) + 1.) * 2 + (side > 0. ? 1 : 0)]; }

// The openings of the nave wall, in (z, y), negative inside: the arcades, the triforium above them
// (four small arches a bay, opening on a passage), and the clerestory lancets, two a bay.
// Below the springing the arcades open right up to the core of each pier, so that no jamb shows
// between its shafts; the step where the arch begins is hidden in the abacus.
float arcadeHole(vec2 q) {
  float zl = mod(q.x, BAY) - BAY * .5;
  return q.y < HCAP - .04 ? abs(zl) - 2.05 : sdArch(vec2(zl, q.y - HCAP), HS, RAD);
}
float trifHole(vec2 q) { return max(sdArch(vec2(mod(q.x, BAY * .25) - BAY * .125, q.y - HAISLE - .68), .34, .7), HAISLE + .2 - q.y); }
float clerHole(vec2 q) { return max(sdArch(vec2(abs(mod(q.x, BAY) - BAY * .5) - .98, q.y - HCLS), .6, 1.3), HCL0 + .1 - q.y); }
float hole(vec2 q) { return min(min(arcadeHole(q), trifHole(q)), clerHole(q)); }

vec3 fog(vec3 col, float t) {
  float f = exp(-t * .021);
  return mix(vec3(.02, .008, .012) * (.4 + .6 * roseIgn()), col, f);
}

// The rose is set back in the end wall: an embrasure RD deep, then a plate of tracery RT thick with
// the glass in it, halfway.
const float RD = .55, RT = .14;

// The rose's tracery, in units of its radius: negative in the glass, with the tint and the number of
// the light the point belongs to.
float roseShape(vec2 q, out vec3 tint, out float lid) {
  float r = length(q), a = atan(q.y, q.x);
  float sa = a / TAU * 12., id = floor(sa + .5);
  float la = (sa - id) * TAU / 12.;
  vec2 p = r * vec2(cos(la), sin(la));
  float la2 = (sa - floor(sa) - .5) * TAU / 12.;
  vec2 p2 = r * vec2(cos(la2), sin(la2));
  float s6 = a / TAU * 6., la6 = (s6 - floor(s6 + .5)) * TAU / 6.;
  vec2 p6 = r * vec2(cos(la6), sin(la6));
  float s24 = a / TAU * 24., id24 = floor(s24), la24 = (s24 - id24 - .5) * TAU / 24.;
  vec2 p24 = r * vec2(cos(la24), sin(la24));
  float idm = mod(id + 12., 12.);
  lid = id;

  float d = sdUCap(vec2(p.y, p.x - .25), .03, .105, .31);
  tint = mod(idm, 2.) < .5 ? uPal[10] : uPal[0];
  float dr = length(p - vec2(.8, 0.)) - .105;
  if (dr < d) { d = dr; tint = uPal[JEWEL[int(mod(idm, 6.))]]; }
  float dd = length(p2 - vec2(.685, 0.)) - .05;
  if (dd < d) { d = dd; tint = uPal[2]; }
  dd = length(p2 - vec2(.905, 0.)) - .04;
  if (dd < d) { d = dd; tint = uPal[3]; }
  dd = length(p6 - vec2(.105, 0.)) - .05;
  if (dd < d) { d = dd; tint = uPal[10]; }
  dd = r - .045;
  if (dd < d) { d = dd; tint = uPal[11]; }
  // A border of small oculi round the rim, crimson and bone by turns.
  dd = length(p24 - vec2(.962, 0.)) - .022;
  if (dd < d) { d = dd; tint = mod(id24, 2.) < .5 ? uPal[10] : uPal[11]; lid = id24 + 40.; }
  return d;
}
float roseSd(vec2 q) { vec3 t; float l; return roseShape(q, t, l); }

// The embrasure and the tracery are lit by the rose itself, from behind: the stone is dark, and
// bright where it faces the glass, the more so the nearer it is to it.
vec3 roseStone(vec3 p, vec3 n, int id) {
  vec2 c = p.xy - vec2(0., HROSE);
  vec3 tint; float lid;
  float d = roseShape(c / RROSE, tint, lid) * RROSE;
  float on = roseIgn();
  if (id == 10) {
    // The embrasure: voussoirs round a cylinder, warmer towards the glass.
    float f = clamp((p.z - ZEND) / (RD - RT), 0., 1.);
    float v = abs(fract(atan(c.y, c.x) / TAU * 36.) - .5);
    vec3 alb = vec3(.36, .34, .38) * (1. - .5 * smoothstep(.43, .5, v)) * (.85 + .3 * h21(vec2(floor(atan(c.y, c.x) / TAU * 36.), 3.)));
    return alb * (vec3(.012, .011, .016) + ROSECOL * on * (.05 + .55 * f * f));
  }
  vec3 alb = vec3(.34, .32, .36);
  if (n.z > -.5) {
    // A side of the tracery, facing a light: brightest where it meets the glass.
    float f = clamp((p.z - ZEND - RD + RT) / (RT * .5), 0., 1.);
    return alb * (vec3(.014, .013, .017) + tint * on * (.25 + 1.5 * f * f));
  }
  // Its face: dark stone, the rounded edges catching the light of the glass beside them.
  return alb * (vec3(.014, .013, .017) + tint * on * exp(-max(d, 0.) * 22.) * .6 + ROSECOL * on * .02);
}

// The five lancets under the rose: their outline, the light each spreads on the wall around it (all
// five together, so that their colours blend), and the light they cast into the end of the nave.
float lancetSd(vec2 q, float i) {
  float dx = q.x - (i - 2.) * 1.22;
  if (q.y >= 2.4) return sdArch(vec2(dx, q.y - 6.1), .42, 1.);
  vec2 e = vec2(abs(dx) - .42, 2.4 - q.y);
  return length(max(e, 0.)) + min(max(e.x, e.y), 0.);
}
vec3 lancetGlow(vec2 q) {
  vec3 acc = vec3(0.);
  for (int i = 0; i < 5; i++) acc += uPal[ENDL[i]] * exp(-max(lancetSd(q, float(i)), 0.) * 2.2);
  return acc * ign(8.5) * .075;
}
vec3 lancetLight(vec3 p, vec3 n) {
  vec3 acc = vec3(0.);
  for (int i = 0; i < 5; i++) {
    vec3 L = vec3((float(i) - 2.) * 1.22, 4.6, ZEND) - p;
    float d2 = dot(L, L);
    acc += uPal[ENDL[i]] * max(dot(n, L) * inversesqrt(d2) + .25, 0.) / (1. + d2 * .3);
  }
  return acc * ign(8.5) * .3;
}

// The rose seen from afar: beams and a halo, drawn on the screen around where it stands.
vec3 roseGlow(vec2 uv) {
  if (uRose.z <= 0.) return vec3(0.);
  vec2 dv = uv - uRose.xy;
  float dist = length(dv), ang = atan(dv.y, dv.x), rr = uRose.z;
  float beams = pow(.5 + .5 * cos(ang * 12.), 4.) * .35 + .65 * (.5 + .3 * cos(ang * 7. + uTime * .11) + .2 * cos(ang * 19. - uTime * .07));
  beams *= .4 + .6 * (.5 + .3 * cos(ang * 31. + uTime * .23) + .2 * cos(ang * 53. - uTime * .17));
  return (ROSECOL * beams * exp(-dist * 2.6) * smoothstep(rr * .8, rr * 2.6, dist) * (.3 / (1. + rr * rr * 6.))
        + ROSECOL * exp(-dist * dist / (rr * rr * 7. + .02)) * (.2 / (1. + rr * rr * 30.))) * roseIgn();
}
`;

// ── The tracing of a ray through the building: every surface in closed form, but for the clustered
// piers and the reveals of the openings, which are found by a few steps of sphere tracing.
// id: 0 floor · 1 end wall · 2 vault · 3 column · 4 nave wall · 5 aisle wall · 6 aisle ceiling
//     7 reveal of an opening · 8 clerestory glass · 9 triforium passage
//     10 the rose's embrasure · 11 its tracery · 12 its glass
const TRACE = `
// A clustered pier in plan: a core with four main shafts and four lesser ones between them, each a
// circle (centre, radius). As the pier is their union, the first circle a ray enters is where it hits.
const vec3 PIER[9] = vec3[9](vec3(0., 0., .31), vec3(.33, 0., .11), vec3(-.33, 0., .11), vec3(0., .33, .11), vec3(0., -.33, .11),
                             vec3(.25, .25, .085), vec3(-.25, .25, .085), vec3(.25, -.25, .085), vec3(-.25, -.25, .085));
// How deep in the groove between two of those circles a point of the pier lies: the distance to
// the second nearest of them (the nearest is the one it is on).
float pierGroove(vec2 q) {
  float d1 = 1e9, d2 = 1e9;
  for (int i = 0; i < 9; i++) {
    float d = length(q - PIER[i].xy) - PIER[i].z;
    if (d < d1) { d2 = d1; d1 = d; } else if (d < d2) d2 = d;
  }
  return d2;
}
// An octagon of inradius r, in plan.
float sdOct(vec2 q, float r) { q = abs(q); return max(max(q.x, q.y), (q.x + q.y) * .70711) - r; }

// The capital and the base of a pier, in its own frame (q.xz from its axis, q.y the height): above, an
// astragal round the top of the shafts, a bell flaring to the abacus with a crocket under each of its
// corners (a stalk rising along the bell, curling out at the top), and an octagonal abacus; below, a
// torus on an octagonal plinth. All within radius .7.
float sdSeg(vec3 p, vec3 a, vec3 b) { vec3 pa = p - a, ba = b - a; return length(pa - ba * clamp(dot(pa, ba) / dot(ba, ba), 0., 1.)); }
float colSd(vec3 q) {
  float r = length(q.xz);
  if (q.y < 2.) return min(max(sdOct(q.xz, .6), abs(q.y - .09) - .09), length(vec2(r - .42, q.y - .25)) - .07);
  float k = clamp((q.y - 4.5) / .47, 0., 1.);
  float bell = max(max(r - .34 - .27 * k * sqrt(k), 4.5 - q.y), q.y - 4.97) * .72;
  float ring = length(vec2(r - .4, q.y - 4.5)) - .06;
  float abac = max(sdOct(q.xz, .64), abs(q.y - 5.055) - .085);
  float s = TAU / 8., a = mod(atan(q.z, q.x) - s * .5, s) - s * .5;
  vec3 c = vec3(r * cos(a), q.y, r * sin(a));
  float crock = min(sdSeg(c, vec3(.4, 4.62, 0.), vec3(.55, 4.86, 0.)) - .035, length(c - vec3(.585, 4.88, 0.)) - .055);
  return min(min(bell, ring), min(abac, crock));
}

// The stone of a capital or a base, by height. A little carving on the bell goes into nn.
vec3 capStone(vec3 p, vec3 n, inout vec3 nn) {
  if (p.y < 2.) return p.y < .19 ? vec3(.40, .38, .42) : vec3(.46, .44, .47);
  if (p.y > HTOP + .02) return vec3(.37, .355, .395);
  if (p.y > 4.965) return vec3(.47, .45, .48) * (.82 + .18 * smoothstep(0., .03, 5.14 - p.y));
  if (p.y < 4.56) return vec3(.46, .44, .47);
  float az = atan(n.z, n.x), leaf = sin(az * 24.) * smoothstep(4.56, 4.9, p.y);
  nn = normalize(n + vec3(-sin(az), 0., cos(az)) * leaf * .18);
  return vec3(.42, .40, .44) * (.78 + .22 * smoothstep(4.56, 4.95, p.y)) * (.92 + .08 * leaf);
}

float pierHit(vec2 o, vec2 d, float a, out vec2 nc) {
  float best = 1e9;
  nc = vec2(1., 0.);
  for (int i = 0; i < 9; i++) {
    vec2 oc = o - PIER[i].xy;
    float r = PIER[i].z, b = dot(oc, d), h = b * b - a * (dot(oc, oc) - r * r);
    if (h > 0.) {
      float tt = (-b - sqrt(h)) / a;
      if (tt > 0. && tt < best) { best = tt; nc = (oc + d * tt) / r; }
    }
  }
  return best;
}

float trace(vec3 ro, vec3 rd, out int idOut, out vec3 nOut) {
  float sx = rd.x < 0. ? -1. : 1.;
  float irx = 1. / (abs(rd.x) + 1e-6);
  float t = rd.y < 0. ? -ro.y / rd.y : 1e9;
  int id = 0;
  vec3 n = vec3(0., 1., 0.);
  float tE = (ZEND - ro.z) / max(rd.z, 1e-4);
  if (tE < t) { t = tE; id = 1; n = vec3(0., 0., -1.); }
  float tA = (WA - sx * ro.x) * irx;
  float tC = rd.y > 0. ? (HAISLE - ro.y) / rd.y : 1e9;

  if (abs(ro.x) < WN) {
    if (rd.y > 0.) {
      float a = dot(rd.xy, rd.xy);
      for (int i = 0; i < 2; i++) {
        float s = i == 0 ? 1. : -1.;
        vec2 c = vec2(-s * VC, HV), o = ro.xy - c;
        float b = dot(o, rd.xy), h = b * b - a * (dot(o, o) - RV * RV);
        if (h > 0.) {
          float tt = (-b + sqrt(h)) / a;
          vec2 q = ro.xy + rd.xy * tt;
          if (tt < t && q.x * s >= 0. && q.y >= HV) { t = tt; id = 2; n = vec3((c - q) / RV, 0.); }
        }
      }
    }
    // The piers, nearest first: each is bounded by a cylinder of radius .7 that holds its capital
    // and base. Within it the pier is met exactly, the capital and the base by sphere tracing (they
    // are solids of revolution), and the vault shaft that rises from the capital as a cylinder.
    float zIn = ro.z + rd.z * (WN - .7 - sx * ro.x) * irx;
    float k = ceil((zIn - .7) / BAY), a2 = dot(rd.xz, rd.xz);
    for (int i = 0; i < 3; i++) {
      float zk = (k + float(i)) * BAY;
      if (zk > ZEND + 1.) break;
      vec2 o = vec2(ro.x - sx * WN, ro.z - zk);
      float b = dot(o, rd.xz), h = b * b - a2 * (dot(o, o) - .49);
      if (h <= 0.) continue;
      float sq = sqrt(h), c0 = max((-b - sq) / a2, 0.), c1 = (-b + sq) / a2;
      float best = 1e9;
      vec3 bn = vec3(0.);
      bool solid = false;
      vec2 pn;
      float tp = pierHit(o, rd.xz, a2, pn), y = ro.y + rd.y * tp;
      if (tp < 1e8 && y > .3 && y < 4.5) { best = tp; bn = vec3(pn.x, 0., pn.y); }
      vec3 o3 = vec3(o.x, ro.y, o.y);
      for (int band = 0; band < 2; band++) {
        // The base, then the capital (or the other way round for a ray going down).
        bool cap = (band == 0) == (rd.y < 0.);
        float lo = cap ? 4.42 : 0., hi = cap ? 5.16 : .34;
        float ta = c0, tb = min(c1, best);
        if (abs(rd.y) > 1e-6) {
          float y0 = (lo - ro.y) / rd.y, y1 = (hi - ro.y) / rd.y;
          ta = max(ta, min(y0, y1)); tb = min(tb, max(y0, y1));
        } else if (ro.y < lo || ro.y > hi) continue;
        if (tb <= ta) continue;
        float tm = ta, d = 1.;
        for (int j = 0; j < uMarch; j++) {
          d = colSd(o3 + rd * tm);
          if (d < 1e-3) break;
          tm += d;
          if (tm > tb) break;
        }
        // A ray still in the band when the steps run out is grazing the stone: it hits.
        if (tm <= tb && d < .01) { best = tm; solid = true; break; }
      }
      if (solid) {
        vec3 q = o3 + rd * best, e = vec3(1e-3, 0., 0.);
        bn = normalize(vec3(colSd(q + e.xyy) - colSd(q - e.xyy), colSd(q + e.yxy) - colSd(q - e.yxy), colSd(q + e.yyx) - colSd(q - e.yyx)));
      }
      // The vault shafts stand proud of the wall, on the nave side, from the abacus up; against the end
      // wall they keep to the corner, clear of the rose.
      vec2 os = vec2(ro.x - sx * (zk > ZEND - 1. ? WN : WN - WT - .06), ro.z - zk);
      float bs = dot(os, rd.xz), hs = bs * bs - a2 * (dot(os, os) - SHR * SHR);
      if (hs > 0.) {
        float ts = (-bs - sqrt(hs)) / a2, ys = ro.y + rd.y * ts;
        if (ts > 0. && ts < best && ys >= HTOP && ys < HV + .4) { best = ts; vec2 qs = os + rd.xz * ts; bn = vec3(qs.x, 0., qs.y) / SHR; }
      }
      if (best < 1e8) {
        if (best < t) { t = best; id = 3; n = bn; }
        break;
      }
    }
    // The nave wall is a slab: the arcades open through it onto the aisle, the triforium onto a
    // passage behind it, and the clerestory glass is set in its outer face.
    float tW = (WN - WT - sx * ro.x) * irx;
    if (tW < t) {
      tW = max(tW, 0.);
      float tO = (WN + WT - sx * ro.x) * irx;
      if (hole((ro + rd * tW).zy) > 0.) { t = tW; id = 4; n = vec3(-sx, 0., 0.); }
      else {
        float tm = tW, iq = 1. / max(length(rd.yz), 1e-4);
        bool rev = false;
        float d = -1.;
        for (int j = 0; j < uMarch; j++) {
          d = hole((ro + rd * tm).zy);
          if (d > -1e-3) { rev = true; break; }
          tm += max(-d, 2e-3) * iq;
          if (tm >= tO) break;
        }
        rev = rev || (tm < tO && d > -.03);
        vec2 po = (ro + rd * tO).zy;
        if (rev && tm < tO) {
          if (tm < t) {
            t = tm; id = 7;
            vec2 q = (ro + rd * tm).zy, e = vec2(2e-3, 0.);
            n = normalize(vec3(0., hole(q - e.yx) - hole(q + e.yx), hole(q - e.xy) - hole(q + e.xy)));
          }
        } else if (clerHole(po) < 0.) {
          if (tO < t) { t = tO; id = 8; n = vec3(-sx, 0., 0.); }
        } else if (trifHole(po) < 0.) {
          // The passage: its back wall, its floor, its ceiling.
          float tB = (WN + WT + .6 - sx * ro.x) * irx;
          float tF = rd.y < 0. ? (HAISLE + .2 - ro.y) / rd.y : 1e9;
          float tK = rd.y > 0. ? (HAISLE + 1.4 - ro.y) / rd.y : 1e9;
          float tp = min(tB, min(tF, tK));
          if (tp < t) { t = tp; id = 9; n = tp == tB ? vec3(-sx, 0., 0.) : vec3(0., tp == tF ? 1. : -1., 0.); }
        } else {
          if (tA < t) { t = tA; id = 5; n = vec3(-sx, 0., 0.); }
          if (tC < t && tC > tO) { t = tC; id = 6; n = vec3(0., -1., 0.); }
        }
      }
    }
  } else {
    if (tA < t) { t = tA; id = 5; n = vec3(-sx, 0., 0.); }
    if (tC < t) { t = tC; id = 6; n = vec3(0., -1., 0.); }
  }
  // Into the rose: the embrasure, then the tracery, its face or its sides, then the glass.
  if (id == 1) {
    vec2 o = ro.xy - vec2(0., HROSE), c = o + rd.xy * t;
    if (dot(c, c) < RROSE * RROSE) {
      float zf = ZEND + RD - RT, izr = 1. / max(rd.z, 1e-4);
      float a = dot(rd.xy, rd.xy), b = dot(o, rd.xy), h = b * b - a * (dot(o, o) - RROSE * RROSE);
      float tx = a > 1e-9 && h > 0. ? (-b + sqrt(h)) / a : 1e9;
      float tf = (zf - ro.z) * izr;
      if (tx < tf) { t = tx; id = 10; n = vec3(-(o + rd.xy * tx) / RROSE, 0.); }
      else if (roseSd((o + rd.xy * tf) / RROSE) > 0.) { t = tf; id = 11; n = vec3(0., 0., -1.); }
      else {
        float tg = (zf + RT * .5 - ro.z) * izr, tm = tf, iq = 1. / max(length(rd.xy), 1e-5);
        bool side = false;
        float d = -1.;
        for (int j = 0; j < uMarch; j++) {
          d = roseSd((o + rd.xy * tm) / RROSE) * RROSE;
          if (d > -1e-3) { side = true; break; }
          tm += max(-d, 1e-3) * iq;
          if (tm >= tg) break;
        }
        side = side || (tm < tg && d > -.02);
        if (side && tm < tg) {
          t = tm; id = 11;
          vec2 q = (o + rd.xy * tm) / RROSE, e = vec2(1e-3, 0.);
          n = normalize(vec3(roseSd(q - e.xy) - roseSd(q + e.xy), roseSd(q - e.yx) - roseSd(q + e.yx), 0.));
        } else { t = tg; id = 12; n = vec3(0., 0., -1.); }
      }
    }
  }
  idOut = id; nOut = n;
  return t;
}
`;

// ── The plain nave: the same building, lit by the rose and the windows alone, one ray and its
// reflection a pixel. It is cheap enough for software rasterisers, and is where every visit starts.
const FRAG = BASE + TRACE + `
uniform float uExpo;

vec3 glass(vec2 q, vec3 tint, float d, float aa, float seed) {
  vec2 g = vec2(q.x + q.y * .6, q.x - q.y * .6) * 3.3;
  vec2 id = floor(g), f = abs(fract(g) - .5);
  float c = h21(id + seed);
  float far = clamp(1. - aa * 12., 0., 1.);
  float lead = smoothstep(.41, .47, max(f.x, f.y)) * far;
  vec3 col = tint * mix(1., .4 + 1.35 * c * c, far);
  col = mix(col, vec3(1., .86, .7) * dot(tint, vec3(.4)), step(.94, c) * far * .5);
  col *= 1. - .93 * lead;
  col *= smoothstep(0., -.09 - aa, d);
  return col * 1.9;
}

// Ashlar: x is the albedo factor, yz the tilt of the face towards its nearest joint.
vec3 masonry(vec2 uv, float aa) {
  vec2 s = vec2(1.1, .55);
  float row = floor(uv.y / s.y), x = uv.x / s.x + .5 * mod(row, 2.);
  vec2 f = vec2(fract(x), fract(uv.y / s.y)), m = min(f, 1. - f) * s;
  float far = clamp(1. - aa * 5., 0., 1.), jd = min(m.x, m.y);
  float tone = .8 + .4 * h21(vec2(floor(x), row));
  vec2 dir = m.x < m.y ? vec2(f.x < .5 ? -1. : 1., 0.) : vec2(0., f.y < .5 ? -1. : 1.);
  return vec3(mix(1., tone * (.5 + .5 * smoothstep(0., .03, jd)), far), dir * smoothstep(.06, 0., jd) * far * .7);
}

vec3 stone(vec3 p, vec3 n, vec3 alb) {
  vec3 L = LROSE - p;
  float d2 = dot(L, L); L *= inversesqrt(d2);
  float wrap = max((dot(n, L) + .55) / 1.55, 0.);
  vec3 key = ROSECOL * wrap * wrap * (.78 / (1.7 + d2 * .0042)) * roseIgn();
  float k = floor(p.z / BAY);
  float xl = p.x + WA, xr = WA - p.x;
  float wl = (max(-n.x, 0.) + .5 * max(n.y, 0.) + .1) / (1. + .07 * xl * xl);
  float wr = (max(n.x, 0.) + .5 * max(n.y, 0.) + .1) / (1. + .07 * xr * xr);
  vec3 side = (bayTint(k, -1.) * wl + bayTint(k, 1.) * wr) * .42;
  vec3 amb = vec3(.016, .016, .025) * (.65 + .35 * n.y) + vec3(.012, .014, .024) * max(-n.z, 0.);
  return alb * (amb + key + side + lancetLight(p, n));
}

// Every branch gathers what the surface is made of; glass, light and self-lit surfaces are then
// evaluated once each, which keeps the compiled shader small.
vec3 shade(vec3 p, vec3 rd, float t, int id, vec3 n, out vec3 nr, out float refl) {
  float aa = t * uPix;
  float zl = mod(p.z, BAY) - BAY * .5, kb = floor(p.z / BAY);
  float sx = n.x > 0. ? -1. : 1.;
  refl = 0.; nr = n;
  vec2 gq = vec2(0.); vec3 gt = vec3(0.); float gsd = 1., gseed = 0., gk = 1.;
  vec3 alb = vec3(0.), nn = n, em = vec3(0.), own = vec3(0.);
  float mul = 1.;
  bool unlit = false;

  if (id == 0) {
    vec2 g = vec2(p.x + p.z, p.x - p.z) * .64;
    vec2 gi = floor(g), gf = fract(g) - .5, ga = abs(gf);
    float far = clamp(1. - aa * 3.2, 0., 1.), edge = max(ga.x, ga.y);
    alb = mix(vec3(.105, .048, .06), mix(vec3(.05, .046, .056), vec3(.16, .05, .065), mod(gi.x + gi.y, 2.)), far);
    alb *= mix(1., (.45 + .55 * smoothstep(.5, .468, edge)) * (.78 + .44 * h21(gi)), far);
    // Each slab lies a little out of true, and its edges are worn round.
    vec2 dg = ga.x > ga.y ? vec2(sign(gf.x), 0.) : vec2(0., sign(gf.y));
    vec2 tl = ((vec2(h21(gi + 3.1), h21(gi + 7.7)) - .5) * .014 + vec2(dg.x + dg.y, dg.x - dg.y) * smoothstep(.44, .5, edge) * .3) * far;
    nn = nr = normalize(vec3(tl.x, 1., tl.y));
    float cz = p.z - floor(p.z / BAY + .5) * BAY;
    mul = 1. - .5 * exp(-max(length(vec2(abs(p.x) - WN, cz)) - CAPR, 0.) * 4.);
    refl = (.045 + .955 * pow(1. - max(dot(-rd, nr), 0.), 5.)) * .72 * mix(1., smoothstep(.5, .47, edge), far);
  } else if (id == 1) {
    vec2 q = p.xy, lc = vec2(0., HROSE);
    vec3 ash = masonry(q, aa);
    alb = vec3(.3, .29, .33) * ash.x;
    if (abs(q.x) < WN) {
      vec2 rq = (q - lc) / RROSE;
      float rr = length(rq);
      float li = clamp(floor(q.x / 1.22 + .5), -2., 2.);
      float sdL = max(sdArch(vec2(q.x - li * 1.22, q.y - 6.1), .42, 1.), 2.4 - q.y);
      vec3 tint = uPal[ENDL[int(li) + 2]] * ign(8.5);
      gq = q * 1.4; gt = tint; gsd = sdL; gseed = li * 3.; gk = .62;
      em = lancetGlow(q) + ROSECOL * exp(-max(rr - 1., 0.) * 1.5) * .22 * roseIgn();
      alb = mix(alb, vec3(.46, .44, .47), smoothstep(.09, .04, abs(rr - 1.07)) + smoothstep(.07, .03, abs(sdL - .07)) * .7);
      alb *= .55 + .45 * smoothstep(1., 1.2, rr);
      if (rr > 1.07) lc = vec2(li * 1.22, 6.8);
    } else {
      lc = vec2(sign(q.x) * 5., 5.4);
      float sdL = max(sdArch(vec2(abs(q.x) - 5., q.y - 5.4), .72, 1.6), 2.2 - q.y);
      vec3 tint = bayTint(8., q.x);
      if (q.y < HAISLE) { gq = q; gt = tint; gsd = sdL; gseed = 5.; gk = 1.; }
      em = tint * exp(-max(sdL, 0.) * 2.4) * .12 + lancetGlow(q) * .5;
      alb *= step(q.y, HAISLE) * .8 + .2;
    }
    // The joints catch the glow of the glass beside them.
    float rel = max(1. + dot(ash.yz, normalize(lc - q + 1e-4)) * .9, 0.);
    own = alb * (vec3(.011, .011, .017) + em * 2.4 * rel) + em * .4;
    unlit = true;
  } else if (id == 2) {
    float th = atan(p.y - HV, abs(p.x) + VC), u = th / 1.2165;
    float rib = smoothstep(.17 + aa, .1, BAY * .5 - abs(zl));
    rib = max(rib, smoothstep(.17 + aa, .1, (1. - u) * 1.2165 * RV));
    rib = max(rib, smoothstep(.13 + aa, .07, abs(abs(zl) - BAY * .5 * (1. - u)) * .8));
    alb = mix(vec3(.17, .165, .2) * (.86 + .14 * sin(p.z * 5.3 + th * 23.) * sin(th * 31. - p.z * 2.9)), vec3(.4, .38, .42), rib);
    mul = .5 + .5 * (1. - u);
  } else if (id == 3) {
    alb = vec3(.33, .32, .36) * (.8 + .2 * smoothstep(.5, .47, abs(fract(p.y / 1.25) - .5)));
    if (p.y > 4.5 || p.y < .3) {
      alb = capStone(p, n, nn);
      // The underside of the bell, where it leaves the pier, is in shadow.
      mul = p.y > 4.5 && p.y < 4.97 ? mix(.55, 1., smoothstep(.0, .12, length(p.xz - vec2(sign(p.x) * WN, floor(p.z / BAY + .5) * BAY)) - .34)) : 1.;
    } else {
      // Far off, the shafts of the pier are narrower than a few pixels: their relief fades into the
      // round of the whole pier, instead of breaking into a dashed line of highlights.
      vec2 cc = vec2(sign(p.x) * WN, floor(p.z / BAY + .5) * BAY);
      nn = normalize(mix(n, normalize(vec3(p.x - cc.x, 0., p.z - cc.y)), smoothstep(.008, .05, aa)));
      // The grooves between the shafts are in shadow.
      mul = mix(.3, 1., smoothstep(0., .07, pierGroove(p.xz - cc)));
    }
    mul *= .45 + .55 * smoothstep(0., .9, p.y);
  } else if (id == 4) {
    vec3 ash = masonry(p.zy, aa);
    alb = vec3(.3, .29, .33) * ash.x;
    vec2 tilt = ash.yz;
    if (p.y < HAISLE) {
      float sd = arcadeHole(p.zy);
      float band = smoothstep(.34, .3, sd);
      alb = mix(alb, vec3(.43, .41, .45) * (.62 + .38 * smoothstep(.02, .06, abs(sd - .17))), band);
      // The archivolt: a roll and a hollow turning round the arch.
      vec2 gs = vec2(arcadeHole(p.zy + vec2(.01, 0.)) - sd, arcadeHole(p.zy + vec2(0., .01)) - sd) / .01;
      tilt = mix(tilt, -gs * cos(sd * 18.48) * .45, band);
      em = bayTint(kb, sx) * smoothstep(.3, 0., sd) * .05;
      alb = mix(alb, vec3(.46, .44, .47), smoothstep(.12, .07, abs(p.y - HAISLE + .12)));
    } else if (p.y < HCL0 - .12) {
      // The triforium: a moulding round each small arch.
      float sdT = trifHole(p.zy);
      float ring = smoothstep(.12, .0, abs(sdT - .06));
      alb = mix(alb, vec3(.44, .42, .46), ring * .55);
      vec2 gt2 = vec2(trifHole(p.zy + vec2(.01, 0.)) - sdT, trifHole(p.zy + vec2(0., .01)) - sdT) / .01;
      tilt = mix(tilt, -gt2 * cos(sdT * 26.) * .4, ring);
    } else {
      float sdC = clerHole(p.zy);
      em = bayTint(kb, sx) * exp(-max(sdC, 0.) * 2.3) * .1;
      alb = mix(alb, vec3(.45, .43, .47), smoothstep(.1, .05, abs(sdC - .08)) * .6);
    }
    nn = normalize(n + vec3(0., tilt.y, tilt.x));
  } else if (id == 7) {
    float side = p.x > 0. ? 1. : -1.;
    float dep = clamp((abs(p.x) - WN + WT) / (2. * WT), 0., 1.);
    alb = vec3(.4, .38, .42);
    mul = 1. - .4 * dep;
    em = alb * bayTint(kb, side) * (p.y > HCL0 ? .3 : p.y > HAISLE ? 0. : .05) * dep * dep;
  } else if (id == 8) {
    float zc = abs(zl) - .98;
    gq = vec2(zc, p.y); gt = bayTint(kb, sx); gseed = kb * 7. + sx;
    gsd = min(clerHole(p.zy), -1e-4);
  } else if (id >= 10) {
    if (id == 12) {
      vec3 tint; float lid;
      vec2 q = (p.xy - vec2(0., HROSE)) / RROSE;
      float d = roseShape(q, tint, lid);
      gq = q * RROSE * 1.25; gseed = lid; gk = 1.15;
      gt = tint * roseIgn() * (.86 + .14 * vnoise(vec2(uTime * .22 + lid * 1.7, lid)));
      gsd = min(d * RROSE, -1e-4);
    } else { own = roseStone(p, n, id); unlit = true; }
  } else if (id == 9) {
    // The passage behind the triforium: dark, lit only by what comes through its arches.
    alb = vec3(.2, .19, .22) * (n.x != 0. ? masonry(p.zy, aa).x : 1.);
    mul = .35;
  } else if (id == 5) {
    float sdL = max(sdArch(vec2(zl, p.y - 5.5), .9, 2.), 2. - p.y);
    vec3 tint = bayTint(kb, sx);
    gq = vec2(zl, p.y); gt = tint; gsd = sdL; gseed = kb * 3. + sx; gk = mix(.42, 1., smoothstep(4., 16., t));
    vec3 ash = masonry(p.zy, aa);
    alb = vec3(.28, .27, .31) * ash.x;
    alb = mix(alb, vec3(.44, .42, .46), smoothstep(.1, .05, abs(sdL - .09)) * .6);
    own = alb * (vec3(.012, .012, .018) + tint * exp(-sdL * 1.7) * .5 + bayTint(kb, -sx) * .03) * (1. - ash.z * .5);
    unlit = true;
  } else {
    float rib = smoothstep(.16, .1, BAY * .5 - abs(zl));
    own = mix(vec3(.02, .019, .025), vec3(.045, .042, .05), rib) * (.5 + (bayTint(kb, sx) + .2));
    unlit = true;
  }

  if (gsd < 0.) return glass(gq, gt, gsd, aa, gseed) * gk;
  if (unlit) return own;
  return stone(p, nn, alb) * mul + em;
}

void main() {
  vec2 uv = (gl_FragCoord.xy * 2. - uRes) / uRes.y;
  vec3 ro = uCam, rd = normalize(uBasis * vec3(uv, uFocal)), col = vec3(0.);
  float t0 = 0., w = 0.;
  for (int b = 0; b < uBounces; b++) {
    int id; vec3 n, nr; float refl;
    float t = trace(ro, rd, id, n);
    vec3 p = ro + rd * t;
    vec3 c = shade(p, rd, b > 0 ? t + t0 : t, id, n, nr, refl);
    if (b == 0) { col = c; t0 = t; w = refl; }
    else col += fog(c, t) * w;
    if (b > 0 || refl <= 0.) break;
    ro = p + vec3(0., 1e-3, 0.);
    rd = reflect(rd, nr);
    rd.y = abs(rd.y) + 2e-3;
  }
  col = fog(col, t0) + roseGlow(uv);

  col *= uExpo;
  col = (col * (2.51 * col + .03)) / (col * (2.43 * col + .59) + .14);
  col = pow(clamp(col, 0., 1.), vec3(.4545));
  col *= 1. - .3 * smoothstep(.5, 1.9, length(uv * vec2(.82, 1.)));
  col += (h21(gl_FragCoord.xy + fract(uTime)) - .5) / 160.;
  outColor = vec4(col, 1.);
}`;

// ── What the full nave and the light in its air add to the shared part: the sun, and richer glass.
const HQ_HEAD = BASE + `
uniform float uAAk;
uniform int uSS, uSteps;
// Towards the sun: it comes in through the left windows, falls to the right and a little towards the viewer.
const vec3 SUN = vec3(-.4060, .8933, .1929);
const float SK = SUN.y / -SUN.x, SUNK = 1.15, SHAFTK = .045;
// Set while shading a reflection: the floor mirrors the light, not the shadows and sun patches.
bool gCheap = false;
const vec2 SS4[4] = vec2[4](vec2(-.125, -.375), vec2(.375, -.125), vec2(.125, .375), vec2(-.375, .125));
const vec2 SS8[8] = vec2[8](vec2(.0625, -.1875), vec2(-.0625, .1875), vec2(.3125, .0625), vec2(-.1875, -.3125),
                            vec2(-.3125, .3125), vec2(-.4375, -.0625), vec2(.1875, .4375), vec2(.4375, -.4375));

float fbm(vec2 p) { return vnoise(p) * .5 + vnoise(p * 2.03 + 17.1) * .3 + vnoise(p * 4.07 + 3.7) * .2; }

vec3 glass(vec2 q, vec3 tint, float d, float aa, float seed) {
  vec2 g = vec2(q.x + q.y * .6, q.x - q.y * .6) * 3.3;
  vec2 id = floor(g), f = abs(fract(g) - .5);
  float c = h21(id + seed), c2 = h21(id + seed + 41.7);
  float far = clamp(1. - aa * 9., 0., 1.), fine = clamp(1. - aa * 40., 0., 1.);
  float e = max(f.x, f.y), w = aa * 2.6 + .006;
  float lead = smoothstep(.44 - w, .45 + w, e) * far;
  vec3 col = tint * mix(1., .4 + 1.35 * c * c, far);
  // Now and then a pane of another colour, as in old glass mended over the centuries. It takes the
  // brightness of its own window, so it lights up with it.
  if (c2 > .92) {
    vec3 alt = uPal[int(c2 * 1000.) % 10];
    alt *= max(tint.r, max(tint.g, tint.b)) / max(max(alt.r, max(alt.g, alt.b)), 1e-3);
    col = mix(col, alt * (.5 + .9 * c), .7 * far);
  }
  col = mix(col, vec3(1., .86, .7) * dot(tint, vec3(.4)), step(.94, c) * far * .5);
  // Streaks drawn into the glass, and the grisaille painted along the leads.
  if (fine > 0.) col *= 1. + (vnoise(vec2(q.x * 38. + seed * 7., q.y * 3.)) - .5) * .5 * fine;
  col *= 1. - .38 * smoothstep(.28, .44, e) * far;
  col *= 1. - .93 * lead;
  col *= smoothstep(0., -.09 - aa, d);
  return col * 2.1;
}

// The sunlight reaching a point, coloured by the window it came through: a clerestory lancet for the
// nave and the right aisle, an aisle window for the left aisle.
vec3 sunLight(vec3 p, float blur) {
  vec2 gq; float sd, seed, kb;
  if (p.x > -WN + WT) {
    if (p.x > WN - WT) {
      vec3 c0 = p + SUN * max((p.x - WN - WT) / -SUN.x, 0.), c1 = p + SUN * ((p.x - WN + WT) / -SUN.x);
      if (max(arcadeHole(c0.zy), arcadeHole(c1.zy)) > 0.) return vec3(0.);
    }
    vec3 hi = p + SUN * ((p.x + WN - WT) / -SUN.x);
    float s = (p.x + WN + WT) / -SUN.x;
    vec3 ho = p + SUN * s;
    if (ho.y < HCL0 || hi.y > HV) return vec3(0.);
    float zc = abs(mod(ho.z, BAY) - BAY * .5) - .98;
    sd = max(clerHole(ho.zy), clerHole(hi.zy));
    kb = floor(ho.z / BAY); gq = vec2(zc, ho.y); seed = kb * 7. - 1.;
    blur += s * .0025;
  } else if (p.x > -WN - WT) {
    return vec3(0.);
  } else {
    float s = (p.x + WA) / -SUN.x;
    vec3 h = p + SUN * s;
    if (h.y > HAISLE - .3) return vec3(0.);
    float zl = mod(h.z, BAY) - BAY * .5;
    sd = max(sdArch(vec2(zl, h.y - 5.5), .9, 2.), 2. - h.y);
    kb = floor(h.z / BAY); gq = vec2(zl, h.y); seed = kb * 3. - 1.;
    blur += s * .0025;
  }
  if (sd > 0.) return vec3(0.);
  return glass(gq, bayTint(kb, -1.), sd, blur, seed);
}
`;

// ── The full nave. Same building, same light, same palette as FRAG, and on top the sun through the
// left windows, soft shadows from the rose, richer glass and stone, supersampling. Output is linear
// HDR with the depth in alpha: the light in the air, the bloom, exposure and tone curve come after.
const HQ_FRAG = HQ_HEAD + TRACE + `
// Ashlar: x is the albedo factor, yz the tilt of the surface towards the nearest joint.
vec3 ashlar(vec2 uv, float aa) {
  vec2 s = vec2(1.1, .55);
  float row = floor(uv.y / s.y), x = uv.x / s.x + .5 * mod(row, 2.);
  vec2 f = vec2(fract(x), fract(uv.y / s.y)), m = min(f, 1. - f) * s;
  float far = clamp(1. - aa * 5., 0., 1.), fine = clamp(1. - aa * 30., 0., 1.);
  float id = h21(vec2(floor(x), row));
  float grain = vnoise(uv * 9. + id * 31.) * .6 + vnoise(uv * 29. - id * 7.) * .4;
  float jd = min(m.x, m.y), j = smoothstep(0., .028 + aa, jd);
  float alb = (.8 + .4 * id) * (.5 + .5 * j) * (1. + (grain - .5) * .4 * fine);
  vec2 dir = m.x < m.y ? vec2(f.x < .5 ? -1. : 1., 0.) : vec2(0., f.y < .5 ? -1. : 1.);
  return vec3(mix(1., alb, far), dir * smoothstep(.06, 0., jd) * far * .7);
}

// How much of the rose a point sees: from the aisles only through the arcades, softly, as the rose is large.
float roseShadow(vec3 p) {
  float ax = abs(p.x);
  if (ax < WN - WT) return 1.;
  vec3 v = LROSE - p;
  float s0 = max((ax - WN - WT) / ax, 0.), s1 = (ax - WN + WT) / ax;
  float sd = max(hole((p + v * s0).zy), hole((p + v * s1).zy));
  float w = .03 + RROSE * s1 * .5;
  return smoothstep(w, -w, sd);
}

vec3 lit(vec3 p, vec3 n, vec3 alb, float ao, float aa) {
  vec3 L = LROSE - p;
  float d2 = dot(L, L); L *= inversesqrt(d2);
  float wrap = max((dot(n, L) + .55) / 1.55, 0.);
  vec3 key = ROSECOL * wrap * wrap * (.78 / (1.7 + d2 * .0042)) * roseIgn() * (gCheap ? 1. : roseShadow(p));
  float k = floor(p.z / BAY);
  float xl = p.x + WA, xr = WA - p.x;
  float wl = (max(-n.x, 0.) + .5 * max(n.y, 0.) + .1) / (1. + .07 * xl * xl);
  float wr = (max(n.x, 0.) + .5 * max(n.y, 0.) + .1) / (1. + .07 * xr * xr);
  vec3 side = (bayTint(k, -1.) * wl + bayTint(k, 1.) * wr) * .42;
  vec3 amb = vec3(.016, .016, .025) * (.65 + .35 * n.y) + vec3(.012, .014, .024) * max(-n.z, 0.);
  float ns = dot(n, SUN);
  vec3 sun = ns > 0. && !gCheap ? sunLight(p, aa) * ns * SUNK : vec3(0.);
  return alb * ((amb + side + lancetLight(p, n)) * ao + key * (.5 + .5 * ao) + sun);
}

// Every branch only gathers what the surface is made of; the glass, the lighting and the self-lit
// surfaces are then evaluated in one place each, which keeps the compiled shader small.
vec3 shade(vec3 p, vec3 rd, float t, int id, vec3 n, vec2 jit, out vec3 nr, out float refl) {
  float aa = t * uPix * uAAk;
  float zl = mod(p.z, BAY) - BAY * .5, kb = floor(p.z / BAY);
  float sx = n.x > 0. ? -1. : 1.;
  refl = 0.; nr = n;
  vec2 gq = vec2(0.); vec3 gt = vec3(0.); float gsd = 1., gseed = 0., gk = 1.;
  vec3 alb = vec3(0.), nn = n, em = vec3(0.), own = vec3(0.);
  float ao = 1., mul = 1.;
  bool unlit = false;

  if (id == 0) {
    vec2 g = vec2(p.x + p.z, p.x - p.z) * .64;
    vec2 gi = floor(g), gf = fract(g) - .5, ga = abs(gf);
    float far = clamp(1. - aa * 3.2, 0., 1.);
    float chk = mod(gi.x + gi.y, 2.), th = h21(gi), edge = max(ga.x, ga.y);
    alb = mix(vec3(.05, .046, .056), vec3(.16, .05, .065), chk) * (.78 + .44 * th);
    // Veins in the marble, a different stone in every slab.
    float wv = fbm(p.xz * .9 + th * 17.);
    float vein = smoothstep(.07 + aa * 3., 0., abs(fract(wv * 3. + (p.x - p.z) * .15) - .5));
    alb = mix(alb, mix(vec3(.13, .12, .14), vec3(.34, .13, .15), chk), vein * .5 * far);
    float joint = smoothstep(.5, .47 - aa, edge);
    alb *= mix(1., .4 + .6 * joint, far);
    alb = mix(vec3(.105, .048, .06), alb, far);
    // Each slab lies a little out of true, and its edges are worn round.
    vec2 dg = ga.x > ga.y ? vec2(sign(gf.x), 0.) : vec2(0., sign(gf.y));
    vec2 tl = ((vec2(h21(gi + 3.1), h21(gi + 7.7)) - .5) * .014 + vec2(dg.x + dg.y, dg.x - dg.y) * smoothstep(.44, .5, edge) * .3) * far;
    nn = normalize(vec3(tl.x, 1., tl.y));
    float cz = p.z - floor(p.z / BAY + .5) * BAY;
    float dc = length(vec2(abs(p.x) - WN, cz)) - CAPR;
    ao = (1. - .6 * exp(-max(dc, 0.) * 4.)) * mix(.45, 1., smoothstep(0., 1.8, WA - abs(p.x)))
       * mix(.5, 1., smoothstep(0., 2., ZEND - p.z)) * (abs(p.x) > WN ? .8 : 1.);
    // A glossy, not mirror-like, reflection: only where several samples average the jitter out.
    nr = normalize(nn + vec3(jit.x, 0., jit.y) * .03 * (.4 + th) * max(1. - 2. * uAAk, 0.));
    refl = (.045 + .955 * pow(1. - max(dot(-rd, nr), 0.), 5.)) * .72 * mix(1., joint, far);
  } else if (id == 1) {
    vec2 q = p.xy, lc = vec2(0., HROSE);
    vec3 ash = ashlar(q, aa);
    alb = vec3(.3, .29, .33) * ash.x;
    if (abs(q.x) < WN) {
      vec2 rq = (q - lc) / RROSE;
      float rr = length(rq);
      float li = clamp(floor(q.x / 1.22 + .5), -2., 2.);
      float sdL = max(sdArch(vec2(q.x - li * 1.22, q.y - 6.1), .42, 1.), 2.4 - q.y);
      vec3 tint = uPal[ENDL[int(li) + 2]] * ign(8.5);
      gq = q * 1.4; gt = tint; gsd = sdL; gseed = li * 3.; gk = .62;
      em = lancetGlow(q) + ROSECOL * exp(-max(rr - 1., 0.) * 1.5) * .22 * roseIgn();
      alb = mix(alb, vec3(.46, .44, .47), smoothstep(.09, .04, abs(rr - 1.07)) + smoothstep(.07, .03, abs(sdL - .07)) * .7);
      alb *= .55 + .45 * smoothstep(1., 1.2, rr);
      if (rr > 1.07) lc = vec2(li * 1.22, 6.8);
    } else {
      lc = vec2(sign(q.x) * 5., 5.4);
      float sdL = max(sdArch(vec2(abs(q.x) - 5., q.y - 5.4), .72, 1.6), 2.2 - q.y);
      vec3 tint = bayTint(8., q.x);
      if (q.y < HAISLE) { gq = q; gt = tint; gsd = sdL; gseed = 5.; }
      em = tint * exp(-max(sdL, 0.) * 2.4) * .12 + lancetGlow(q) * .5;
      alb *= step(q.y, HAISLE) * .8 + .2;
    }
    // The joints catch the glow of the glass beside them.
    float rel = max(1. + dot(ash.yz, normalize(lc - q + 1e-4)) * .9, 0.);
    float a1 = mix(.5, 1., smoothstep(0., 1.4, q.y)) * mix(.6, 1., smoothstep(0., 1., WA - abs(q.x)))
             * mix(.65, 1., smoothstep(0., .7, abs(abs(q.x) - WN + WT)));
    own = alb * (vec3(.011, .011, .017) * a1 + em * 2.4 * rel) + em * .4;
    unlit = true;
  } else if (id == 2) {
    float th = atan(p.y - HV, abs(p.x) + VC), u = th / 1.2165;
    float ra = (1. - u) * 1.2165 * RV, w = aa * 1.5;
    float tr = BAY * .5 - abs(zl), dgn = abs(abs(zl) - BAY * .5 * (1. - u)) * .8;
    float rib = max(max(smoothstep(.17 + w, .1, tr), smoothstep(.17 + w, .1, ra)), smoothstep(.13 + w, .07, dgn));
    float far = clamp(1. - aa * 20., 0., 1.);
    float web = .86 + .14 * sin(p.z * 5.3 + th * 23.) * sin(th * 31. - p.z * 2.9);
    float cf = fract(th * RV * 2.);
    web *= (1. - .3 * smoothstep(.06 + aa * 4., 0., min(cf, 1. - cf)) * far) * (.9 + .2 * vnoise(vec2(p.z, th * RV) * 5.));
    alb = mix(vec3(.17, .165, .2) * web, vec3(.4, .38, .42), rib);
    // Gilt stars on the webs, and a boss where the ribs cross.
    vec2 sg = vec2(p.z, th * RV) * 2.2, si = floor(sg);
    float sh = h21(si + 5.3);
    vec2 so = vec2(h21(si + 1.1), h21(si + 2.7)) * .5 + .25;
    float star = step(.5, sh) * smoothstep(.07 + aa * 2.2, 0., length(fract(sg) - so)) * (1. - rib) * clamp(1. - aa * 22., 0., 1.);
    alb = mix(alb, vec3(.62, .46, .22), star);
    float bd = length(vec2(zl, ra)), boss = smoothstep(.27 + w, .21, bd);
    alb = mix(alb, mix(vec3(.55, .42, .2), uPal[10] * .5, smoothstep(.17, .12, bd)), boss);
    ao = mix(.55, 1., smoothstep(0., .3, u));
    mul = .5 + .5 * (1. - u);
    em = vec3(1., .78, .45) * (star * (.5 + .5 * sin(uTime * 1.7 + sh * 60.)) + boss * .15) * .035 * roseIgn();
  } else if (id == 3) {
    float az = atan(n.z, n.x), side = p.x > 0. ? 1. : -1.;
    float drum = floor(p.y / 1.25);
    alb = vec3(.33, .32, .36) * (.88 + .24 * h21(vec2(drum, kb * 2. + side)));
    alb *= .82 + .18 * smoothstep(.5, .46 - aa, abs(fract(p.y / 1.25) - .5));
    alb *= .9 + .2 * vnoise(vec2(az * 3., p.y * 6.));
    if (p.y > 4.5 || p.y < .3) {
      alb = capStone(p, n, nn) * (.9 + .2 * vnoise(p.xz * 9. + p.y * 3.));
      // The underside of the bell, where it leaves the pier, is in shadow; so is the foot of the base.
      vec2 cc = vec2(sign(p.x) * WN, floor(p.z / BAY + .5) * BAY);
      ao = p.y > 4.5 && p.y < 4.97 ? mix(.45, 1., smoothstep(0., .12, length(p.xz - cc) - .34)) : p.y < .3 ? mix(.6, 1., smoothstep(0., .12, p.y)) : 1.;
    } else {
      ao = 1. - .45 * smoothstep(.4, 0., HCAP - .5 - p.y);
      // Far off, the shafts of the pier are narrower than a few pixels: their relief fades into the
      // round of the whole pier, instead of breaking into a dashed line of highlights.
      vec2 cc = vec2(sign(p.x) * WN, floor(p.z / BAY + .5) * BAY);
      nn = normalize(mix(n, normalize(vec3(p.x - cc.x, 0., p.z - cc.y)), smoothstep(.008, .05, aa)));
      // The grooves between the shafts are in shadow.
      mul = mix(.3, 1., smoothstep(0., .07, pierGroove(p.xz - cc)));
    }
    mul *= .45 + .55 * smoothstep(0., .9, p.y);
  } else if (id == 4) {
    vec3 ash = ashlar(p.zy, aa);
    alb = vec3(.3, .29, .33) * ash.x;
    vec2 tilt = ash.yz;
    ao = mix(.55, 1., smoothstep(0., 1.4, p.y));
    if (p.y < HAISLE) {
      float sd = arcadeHole(p.zy);
      float band = smoothstep(.34, .3, sd);
      alb = mix(alb, vec3(.43, .41, .45) * (.62 + .38 * smoothstep(.02, .06, abs(sd - .17))), band);
      // The archivolt: a roll and a hollow turning round the arch.
      vec2 gs = vec2(arcadeHole(p.zy + vec2(.01, 0.)) - sd, arcadeHole(p.zy + vec2(0., .01)) - sd) / .01;
      tilt = mix(tilt, -gs * cos(sd * 18.48) * .45, band);
      em = bayTint(kb, sx) * smoothstep(.3, 0., sd) * .05;
      alb = mix(alb, vec3(.46, .44, .47), smoothstep(.12, .07, abs(p.y - HAISLE + .12)));
    } else if (p.y < HCL0 - .12) {
      // The triforium: a moulding round each small arch.
      float sdT = trifHole(p.zy);
      float ring = smoothstep(.12, .0, abs(sdT - .06));
      alb = mix(alb, vec3(.44, .42, .46), ring * .55);
      vec2 gt2 = vec2(trifHole(p.zy + vec2(.01, 0.)) - sdT, trifHole(p.zy + vec2(0., .01)) - sdT) / .01;
      tilt = mix(tilt, -gt2 * cos(sdT * 26.) * .4, ring);
    } else {
      float sdC = clerHole(p.zy);
      em = bayTint(kb, sx) * exp(-max(sdC, 0.) * 2.3) * .1;
      alb = mix(alb, vec3(.45, .43, .47), smoothstep(.1, .05, abs(sdC - .08)) * .6);
    }
    nn = normalize(n + vec3(0., tilt.y, tilt.x));
  } else if (id == 7) {
    float side = p.x > 0. ? 1. : -1.;
    float dep = clamp((abs(p.x) - WN + WT) / (2. * WT), 0., 1.);
    alb = vec3(.4, .38, .42) * (.82 + .3 * vnoise(p.zy * 7. + p.x * 3.));
    em = alb * bayTint(kb, side) * (p.y > HCL0 ? .3 : p.y > HAISLE ? 0. : .05) * dep * dep;
    ao = mix(1., .55, dep);
  } else if (id == 8) {
    float zc = abs(zl) - .98;
    gq = vec2(zc, p.y); gt = bayTint(kb, sx); gseed = kb * 7. + sx;
    gsd = min(clerHole(p.zy), -1e-4);
  } else if (id >= 10) {
    if (id == 12) {
      vec3 tint; float lid;
      vec2 q = (p.xy - vec2(0., HROSE)) / RROSE;
      float d = roseShape(q, tint, lid);
      gq = q * RROSE * 1.25; gseed = lid; gk = 1.05;
      gt = tint * roseIgn() * (.86 + .14 * vnoise(vec2(uTime * .22 + lid * 1.7, lid)));
      gsd = min(d * RROSE, -1e-4);
    } else { own = roseStone(p, n, id); unlit = true; }
  } else if (id == 9) {
    // The passage behind the triforium: dark, lit only by what comes through its arches.
    alb = vec3(.2, .19, .22) * (n.x != 0. ? ashlar(p.zy, aa).x : 1.);
    ao = .3;
  } else if (id == 5) {
    float sdL = max(sdArch(vec2(zl, p.y - 5.5), .9, 2.), 2. - p.y);
    vec3 tint = bayTint(kb, sx);
    gq = vec2(zl, p.y); gt = tint; gsd = sdL; gseed = kb * 3. + sx; gk = mix(.42, 1., smoothstep(4., 16., t));
    vec3 ash = ashlar(p.zy, aa);
    alb = vec3(.28, .27, .31) * ash.x;
    alb = mix(alb, vec3(.44, .42, .46), smoothstep(.1, .05, abs(sdL - .09)) * .6);
    float a5 = mix(.5, 1., smoothstep(0., 1.2, p.y)) * mix(.55, 1., smoothstep(0., 1., HAISLE - p.y));
    own = alb * (vec3(.012, .012, .018) * a5 + tint * exp(-sdL * 1.7) * .5 + bayTint(kb, -sx) * .03) * (1. - ash.z * .5);
    unlit = true;
  } else {
    float rib = smoothstep(.16, .1, BAY * .5 - abs(zl));
    own = mix(vec3(.02, .019, .025), vec3(.045, .042, .05), rib) * (.5 + (bayTint(kb, sx) + .2));
    unlit = true;
  }

  if (gsd < 0.) return glass(gq, gt, gsd, aa, gseed) * gk;
  if (unlit) return own;
  return lit(p, nn, alb, ao, aa) * mul + em;
}

void main() {
  vec2 px = gl_FragCoord.xy;
  vec3 acc = vec3(0.);
  float tC = 0.;
  for (int s = 0; s < uSS; s++) {
    vec2 off = uSS >= 8 ? SS8[s] : uSS >= 4 ? SS4[s] : uSS == 2 ? vec2(s == 0 ? -.25 : .25) : vec2(0.);
    vec2 uv = ((px + off) * 2. - uRes) / uRes.y;
    vec3 rd = normalize(uBasis * vec3(uv, uFocal));
    vec2 jit = vec2(h21(px + off * 7.13), h21(px.yx + off * 3.71 + 9.2)) - .5;
    vec3 ro = uCam, c0 = vec3(0.);
    float t0 = 0., w = 0.;
    for (int b = 0; b < uBounces; b++) {
      int id; vec3 n, nr; float refl;
      gCheap = b > 0;
      float t = trace(ro, rd, id, n);
      vec3 p = ro + rd * t;
      // A reflection is filtered by the whole length of its path, so far glass does not sparkle in it.
      vec3 c = shade(p, rd, b > 0 ? t + t0 : t, id, n, jit, nr, refl);
      if (b == 0) { c0 = c; t0 = t; w = refl; }
      else c0 += fog(c, t) * w;
      if (b > 0 || refl <= 0.) break;
      ro = p + vec3(0., 1e-3, 0.);
      rd = reflect(rd, nr);
      rd.y = abs(rd.y) + 2e-3;
    }
    vec3 c = fog(c0, t0);
    if (s == 0) tC = t0;
    acc += c / (1. + max(c.r, max(c.g, c.b)));
  }
  acc /= float(uSS);
  acc /= max(1. - max(acc.r, max(acc.g, acc.b)), 1e-3);
  acc += roseGlow((px * 2. - uRes) / uRes.y);
  outColor = vec4(min(acc, vec3(64.)), tC);
}
`;

const SHAFT_FRAG = HQ_HEAD + `
// Light scattered by the dust in the air where the sun crosses it, marched once per pixel. Sunlit
// air can only lie between two planes parallel to the sun (y + SK x within the height of the glass):
// one pair for the clerestory, one for the aisle windows. The samples go to those stretches alone.
vec2 band(vec3 ro, vec3 rd, float lo, float hi, float tmax) {
  float f0 = ro.y + SK * ro.x, df = rd.y + SK * rd.x;
  if (abs(df) < 1e-5) return f0 < lo || f0 > hi ? vec2(1., 0.) : vec2(0., tmax);
  float t1 = (lo - f0) / df, t2 = (hi - f0) / df;
  return vec2(max(min(t1, t2), 0.), min(max(t1, t2), tmax));
}

vec3 shafts(vec3 ro, vec3 rd, float tmax, float jt) {
  tmax = min(tmax, 70.);
  vec2 r1 = band(ro, rd, HCL0 + .1 - SK * (WN + WT), HCLS + 1.2 - SK * (WN + WT), tmax);
  vec2 r2 = band(ro, rd, 2. - SK * WA, 7.2 - SK * WA, tmax);
  int n1 = uSteps, n2 = max(uSteps / 3, 1);
  float d1 = (r1.y - r1.x) / float(n1), d2 = (r2.y - r2.x) / float(n2);
  vec3 acc = vec3(0.);
  for (int i = 0; i < n1 + n2; i++) {
    bool first = i < n1;
    float dt = first ? d1 : d2;
    if (dt <= 0.) continue;
    float t = first ? r1.x + dt * (float(i) + jt) : r2.x + dt * (float(i - n1) + jt);
    vec3 q = ro + rd * t;
    vec3 L = sunLight(q, .03 + t * .003);
    if (L.r + L.g + L.b > 0.) {
      float dens = .35 + vnoise(q.xz * .55 + q.y * .3 + vec2(uTime * .04, -uTime * .025));
      acc += L * (dens * exp(-t * .021) * smoothstep(1.5, 7., t) * dt);
    }
  }
  float mu = max(dot(rd, SUN), 0.);
  return acc * (.55 + 1.6 * mu * mu * mu) * SHAFTK;
}

// The light in the air, at half resolution: it is soft, and the costliest thing in the scene. The
// depth of every pixel comes from the alpha of the scene pass.
uniform sampler2D uDepth;
void main() {
  vec2 px = gl_FragCoord.xy;
  vec2 uv = (px * 2. - uRes) / uRes.y;
  float t = texture(uDepth, px / uRes).a;
  outColor = vec4(shafts(uCam, normalize(uBasis * vec3(uv, uFocal)), t, h21(px + fract(uTime * 7.31) * 113.)), 1.);
}
`;

// Bloom: a chain of half-size targets, filtered down (13 taps, the first one weighted against
// fireflies and cut at a soft threshold) and back up (a 3x3 tent, added onto the level above).
const DOWN_FRAG = `#version 300 es
precision highp float;
uniform sampler2D uSrc;
uniform vec2 uTexel, uDst;
uniform int uFirst;
uniform float uThresh;
out vec4 outColor;
float lum(vec3 c) { return dot(c, vec3(.2126, .7152, .0722)); }
void main() {
  vec2 st = gl_FragCoord.xy * uDst;
  #define T(x, y) texture(uSrc, st + vec2(x, y) * uTexel).rgb
  vec3 a = T(-2., 2.), b = T(0., 2.), c = T(2., 2.), d = T(-2., 0.), e = T(0., 0.), f = T(2., 0.);
  vec3 g = T(-2., -2.), h = T(0., -2.), i = T(2., -2.), j = T(-1., 1.), k = T(1., 1.), l = T(-1., -1.), m = T(1., -1.);
  vec3 o;
  if (uFirst == 1) {
    vec3 g0 = (j + k + l + m) * .25, g1 = (a + b + d + e) * .25, g2 = (b + c + e + f) * .25, g3 = (d + e + g + h) * .25, g4 = (e + f + h + i) * .25;
    float w0 = .5 / (1. + lum(g0)), w1 = .125 / (1. + lum(g1)), w2 = .125 / (1. + lum(g2)), w3 = .125 / (1. + lum(g3)), w4 = .125 / (1. + lum(g4));
    o = (g0 * w0 + g1 * w1 + g2 * w2 + g3 * w3 + g4 * w4) / (w0 + w1 + w2 + w3 + w4);
    float lu = lum(o), kn = uThresh * .5;
    float soft = clamp(lu - uThresh + kn, 0., 2. * kn);
    o *= max(soft * soft / (4. * kn + 1e-4), lu - uThresh) / max(lu, 1e-4);
  } else {
    o = e * .125 + (a + c + g + i) * .03125 + (b + d + f + h) * .0625 + (j + k + l + m) * .125;
  }
  outColor = vec4(o, 1.);
}`;

const UP_FRAG = `#version 300 es
precision highp float;
uniform sampler2D uSrc;
uniform vec2 uTexel, uDst;
out vec4 outColor;
void main() {
  vec2 st = gl_FragCoord.xy * uDst;
  vec4 d = vec4(uTexel, -uTexel.x, 0.);
  vec3 s = texture(uSrc, st - d.xy).rgb + texture(uSrc, st - d.wy).rgb * 2. + texture(uSrc, st - d.zy).rgb
         + texture(uSrc, st + d.zw).rgb * 2. + texture(uSrc, st).rgb * 4. + texture(uSrc, st + d.xw).rgb * 2.
         + texture(uSrc, st + d.zy).rgb + texture(uSrc, st + d.wy).rgb * 2. + texture(uSrc, st + d.xy).rgb;
  outColor = vec4(s / 16., 1.);
}`;

const COMP_FRAG = `#version 300 es
precision highp float;
uniform sampler2D uScene, uBloom, uShafts, uPrev;
uniform vec2 uRes, uShaftTexel;
uniform float uExpo, uBloomK, uTime, uFade;
out vec4 outColor;
float h21(vec2 p) { p = fract(p * vec2(123.34, 456.21)); p += dot(p, p + 45.32); return fract(p.x * p.y); }
void main() {
  vec2 st = gl_FragCoord.xy / uRes;
  // The half-size light in the air, read through a small tent to soften its grain.
  vec2 o = uShaftTexel * .75;
  vec3 air = texture(uShafts, st + o).rgb + texture(uShafts, st - o).rgb + texture(uShafts, st + vec2(o.x, -o.y)).rgb + texture(uShafts, st - vec2(o.x, -o.y)).rgb;
  vec3 col = texture(uScene, st).rgb + air * .25 + texture(uBloom, st).rgb * uBloomK;
  col *= uExpo;
  col = (col * (2.51 * col + .03)) / (col * (2.43 * col + .59) + .14);
  col = pow(clamp(col, 0., 1.), vec3(.4545));
  vec2 uv = (gl_FragCoord.xy * 2. - uRes) / uRes.y;
  col *= 1. - .3 * smoothstep(.5, 1.9, length(uv * vec2(.82, 1.)));
  col += (h21(gl_FragCoord.xy + fract(uTime)) - .5) / 160.;
  // The plain nave, while the full one fades in over it.
  if (uFade < 1.) col = mix(texture(uPrev, st).rgb, col, uFade);
  outColor = vec4(col, 1.);
}`;

const DUST_VERT = `#version 300 es
in vec3 aSeed;
uniform vec3 uCam;
uniform mat3 uBasis;
uniform float uFocal, uTime, uAspect, uSize, uIgnite;
out float vA;
void main() {
  vec3 p = vec3((aSeed.x - .5) * 5.8, aSeed.y * 13., aSeed.z * 30.);
  p.x += .4 * sin(uTime * .11 + aSeed.y * 40.);
  p.y = .15 + mod(p.y + uTime * (.02 + .05 * aSeed.x) + .25 * sin(uTime * .13 + aSeed.z * 50.), 13.);
  p.z = uCam.z + .5 + mod(p.z - uCam.z, 30.);
  vec3 c = (p - uCam) * uBasis;
  gl_Position = vec4(c.x * uFocal / uAspect, c.y * uFocal, 0., c.z);
  gl_PointSize = clamp(uSize * (.5 + aSeed.x) / c.z, 1., uSize * .9);
  float tw = .55 + .45 * sin(uTime * (.6 + aSeed.y * 2.) + aSeed.z * 90.);
  vA = smoothstep(.5, 2.2, c.z) * exp(-c.z * .075) * tw * uIgnite * (.35 + .65 * exp(-p.x * p.x * .22));
}`;

const DUST_FRAG = `#version 300 es
precision mediump float;
uniform float uGain;
in float vA;
out vec4 outColor;
void main() {
  float d = length(gl_PointCoord - .5);
  outColor = vec4(vec3(1., .72, .66) * smoothstep(.5, .05, d) * vA * .5 * uGain, 1.);
}`;

// Steps of the full nave, from the cheapest up: s scales the buffer against the device's pixel
// ratio, ss is the number of samples per pixel, steps the samples of the light in the air.
const LEVELS = [
  { s: 0.6, ss: 1, steps: 12 },
  { s: 0.8, ss: 1, steps: 16 },
  { s: 1, ss: 1, steps: 20 },
  { s: 1, ss: 2, steps: 24 },
  { s: 1, ss: 4, steps: 28 },
  { s: 1, ss: 8, steps: 32 },
];
// Milliseconds of GPU time a frame of the full nave may take.
const BUDGET = 9;

const ZEND = 39.6;
const HROSE = 11.3;
const RROSE = 2.8;

const lerp = (a, b, t) => a + (b - a) * t;
const clamp01 = (x) => Math.min(1, Math.max(0, x));
const smooth = (a, b, x) => { const t = clamp01((x - a) / (b - a)); return t * t * (3 - 2 * t); };
const norm = (v) => { const l = Math.hypot(v[0], v[1], v[2]) || 1; return [v[0] / l, v[1] / l, v[2] / l]; };
const cross = (a, b) => [a[1] * b[2] - a[2] * b[1], a[2] * b[0] - a[0] * b[2], a[0] * b[1] - a[1] * b[0]];

export const srgbToLinear = (hex) => {
  const n = parseInt(hex.slice(1), 16);
  return [(n >> 16) & 255, (n >> 8) & 255, n & 255].map((c) => Math.pow(c / 255, 2.2));
};

// palette: twelve hex colours, in the order the shader expects (ten bays, then crimson and bone).
// onReady is called once the first frame is on the canvas, onLost if the nave cannot be built.
export function createNave(canvas, palette, { still = false, onReady = () => {}, onLost = () => {} } = {}) {
  const gl = canvas.getContext("webgl2", { antialias: false, alpha: false, depth: false, stencil: false, powerPreference: "high-performance" });
  if (!gl) return null;

  // Every program is compiled in the background: through Direct3D a shader of this size takes
  // seconds, and the page must not wait for it. Until the plain nave is ready, the page keeps its
  // drawn rose.
  const parallel = gl.getExtension("KHR_parallel_shader_compile");
  const begin = (vs, fs) => {
    const pr = gl.createProgram();
    const shaders = [[gl.VERTEX_SHADER, vs], [gl.FRAGMENT_SHADER, fs]].map(([type, src]) => {
      const sh = gl.createShader(type);
      gl.shaderSource(sh, src);
      gl.compileShader(sh);
      gl.attachShader(pr, sh);
      return sh;
    });
    gl.bindAttribLocation(pr, 0, "aPos");
    gl.bindAttribLocation(pr, 1, "aSeed");
    gl.linkProgram(pr);
    return { pr, shaders };
  };
  const done = (jobs) => !parallel || jobs.every((j) => gl.getProgramParameter(j.pr, parallel.COMPLETION_STATUS_KHR));
  const linked = (job) => {
    if (gl.getProgramParameter(job.pr, gl.LINK_STATUS)) return true;
    console.warn("Cremisi nave: a shader failed to build", job.shaders.map((sh) => gl.getShaderInfoLog(sh)).join("\n"), gl.getProgramInfoLog(job.pr));
    return false;
  };
  const uniforms = (pr, names) => Object.fromEntries(names.map((n) => [n, gl.getUniformLocation(pr, n)]));
  const plain = { jobs: [begin(VERT, FRAG), begin(DUST_VERT, DUST_FRAG)], ready: false, lost: false };
  let prog = null, dust = null, U = null, D = null;

  const quad = gl.createVertexArray();
  gl.bindVertexArray(quad);
  gl.bindBuffer(gl.ARRAY_BUFFER, gl.createBuffer());
  gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 3, -1, -1, 3]), gl.STATIC_DRAW);
  gl.enableVertexAttribArray(0);
  gl.vertexAttribPointer(0, 2, gl.FLOAT, false, 0, 0);

  const MOTES = 280;
  const seeds = new Float32Array(MOTES * 3);
  let seed = 7;
  for (let i = 0; i < seeds.length; i++) { seed = (seed * 16807) % 2147483647; seeds[i] = seed / 2147483647; }
  const motes = gl.createVertexArray();
  gl.bindVertexArray(motes);
  gl.bindBuffer(gl.ARRAY_BUFFER, gl.createBuffer());
  gl.bufferData(gl.ARRAY_BUFFER, seeds, gl.STATIC_DRAW);
  gl.enableVertexAttribArray(1);
  gl.vertexAttribPointer(1, 3, gl.FLOAT, false, 0, 0);
  gl.blendFunc(gl.ONE, gl.ONE);

  // Glass is deeper than the flat swatches: raise the contrast between channels before it becomes light.
  const pal = new Float32Array(36);
  palette.forEach((hex, i) => {
    const c = srgbToLinear(hex).map((v) => Math.pow(v, 1.55));
    const peak = Math.max(...c, 1e-3);
    for (let j = 0; j < 3; j++) pal[i * 3 + j] = (c[j] / peak) * Math.pow(peak, 0.55);
  });
  const bays = new Float32Array(60);
  const setBays = (loc, time, ignite) => {
    for (let k = -1; k < 9; k++) for (let side = 0; side < 2; side++) {
      const i = ((k + side * 5 + 40) % 10) * 3, o = ((k + 1) * 2 + side) * 3;
      const lit = clamp01(ignite * 13 - (10 - k)), on = lit * lit * (3 - 2 * lit);
      const f = on * (0.9 + 0.1 * Math.sin(time * (1.1 + (((k + 2) * 7 + side * 3) % 5) * 0.38) + k * 2.1));
      bays[o] = pal[i] * f; bays[o + 1] = pal[i + 1] * f; bays[o + 2] = pal[i + 2] * f;
    }
    gl.uniform3fv(loc, bays);
  };

  const state = {
    progress: 0, // scroll flight, 0..1
    px: 0, py: 0, // pointer, -1..1, eased
    tx: 0, ty: 0,
    ignite: still ? 1 : 0,
    // A still frame is drawn once: at full size. A moving one starts small and finds its size.
    scale: still ? Math.min(window.devicePixelRatio || 1, 2) : 0.6, maxScale: Math.min(window.devicePixelRatio || 1, 2), cost: 0, full: 0, settle: 2, half: false, flip: 0,
    running: false, t0: performance.now(), last: 0, frames: 0, birth: still ? 9 : 0,
    w: 0, h: 0, hq: false, fast: false, shown: false, lqDts: [], lqMs: [], judged: 0,
  };

  const median = (xs) => [...xs].sort((x, y) => x - y)[xs.length >> 1];
  const push = (xs, x) => { xs.push(x); if (xs.length > 30) xs.shift(); };

  const plainReady = () => {
    if (plain.lost || !done(plain.jobs)) return false;
    if (!plain.jobs.every(linked)) { plain.lost = true; state.running = false; onLost(); return false; }
    [prog, dust] = plain.jobs.map((j) => j.pr);
    U = uniforms(prog, ["uRes", "uTime", "uFocal", "uIgnite", "uExpo", "uPix", "uCam", "uBasis", "uPal", "uBay", "uRose", "uMarch", "uBounces"]);
    D = uniforms(dust, ["uCam", "uBasis", "uFocal", "uTime", "uAspect", "uSize", "uIgnite", "uGain"]);
    gl.useProgram(prog);
    gl.uniform3fv(U.uPal, pal);
    plain.ready = true;
    return true;
  };

  // ── The full nave. Its programs are compiled in the background from the start too, unless the
  // context is a software rasteriser, cannot render to half-float targets, or cannot compile in the
  // background at all (checking a shader that size would then stall the page); it takes over once
  // the plain nave has shown that the GPU is a real one.
  const renderer = (() => {
    const info = gl.getExtension("WEBGL_debug_renderer_info");
    return String(gl.getParameter(info ? info.UNMASKED_RENDERER_WEBGL : gl.RENDERER) || "");
  })();
  const software = /swiftshader|llvmpipe|softpipe|software|basic render/i.test(renderer);
  const hq = { phase: "off", level: 2, ceiling: LEVELS.length - 1, jobs: null, P: null, U: null, rt: null, samples: [], dts: [], calm: 0, capUntil: 0, capMs: 15000, fade: 1, base: 1000 / 60, retryAt: 0, left: 0 };
  if (!software && parallel && gl.getExtension("EXT_color_buffer_float")) {
    hq.phase = "compiling";
    hq.jobs = {
      scene: begin(VERT, HQ_FRAG),
      shaft: begin(VERT, SHAFT_FRAG),
      down: begin(VERT, DOWN_FRAG),
      up: begin(VERT, UP_FRAG),
      comp: begin(VERT, COMP_FRAG),
    };
  }
  canvas.dataset.tier = "lq";

  const target = (w, h) => {
    const tex = gl.createTexture();
    gl.bindTexture(gl.TEXTURE_2D, tex);
    gl.texStorage2D(gl.TEXTURE_2D, 1, gl.RGBA16F, w, h);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.LINEAR);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
    const fb = gl.createFramebuffer();
    gl.bindFramebuffer(gl.FRAMEBUFFER, fb);
    gl.framebufferTexture2D(gl.FRAMEBUFFER, gl.COLOR_ATTACHMENT0, gl.TEXTURE_2D, tex, 0);
    const ok = gl.checkFramebufferStatus(gl.FRAMEBUFFER) === gl.FRAMEBUFFER_COMPLETE;
    return { tex, fb, w, h, ok };
  };
  const freeTargets = () => {
    if (!hq.rt) return;
    for (const t of [hq.rt.scene, hq.rt.shaft, hq.rt.prev, ...hq.rt.mips]) { if (t) { gl.deleteTexture(t.tex); gl.deleteFramebuffer(t.fb); } }
    hq.rt = null;
  };
  const allocTargets = (w, h) => {
    freeTargets();
    const scene = target(w, h), shaft = target(Math.max(1, w >> 1), Math.max(1, h >> 1)), mips = [];
    for (let mw = w, mh = h; mips.length < 7 && Math.min(mw, mh) > 8; ) {
      mw = Math.max(1, mw >> 1); mh = Math.max(1, mh >> 1);
      mips.push(target(mw, mh));
    }
    gl.bindFramebuffer(gl.FRAMEBUFFER, null);
    hq.rt = { scene, shaft, mips, prev: null };
    return mips.length > 0 && [scene, shaft, ...mips].every((t) => t.ok);
  };

  const setLevel = (i) => {
    hq.level = i;
    state.scale = state.maxScale * LEVELS[i].s;
    hq.samples = []; hq.dts = []; hq.calm = 0;
    canvas.dataset.tier = `hq${i}`;
  };
  const enterHQ = (level) => {
    const J = hq.jobs;
    const P = (hq.P = { scene: J.scene.pr, shaft: J.shaft.pr, down: J.down.pr, up: J.up.pr, comp: J.comp.pr });
    hq.U = {
      scene: uniforms(P.scene, ["uRes", "uTime", "uFocal", "uIgnite", "uPix", "uCam", "uBasis", "uPal", "uBay", "uRose", "uSS", "uSteps", "uMarch", "uBounces", "uAAk"]),
      down: uniforms(P.down, ["uSrc", "uTexel", "uDst", "uFirst", "uThresh"]),
      up: uniforms(P.up, ["uSrc", "uTexel", "uDst"]),
      shaft: uniforms(P.shaft, ["uRes", "uTime", "uFocal", "uIgnite", "uPix", "uCam", "uBasis", "uPal", "uBay", "uRose", "uSteps", "uDepth"]),
      comp: uniforms(P.comp, ["uScene", "uBloom", "uShafts", "uPrev", "uRes", "uShaftTexel", "uExpo", "uBloomK", "uTime", "uFade"]),
    };
    gl.useProgram(P.scene); gl.uniform3fv(hq.U.scene.uPal, pal);
    gl.useProgram(P.down); gl.uniform1i(hq.U.down.uSrc, 0);
    gl.useProgram(P.up); gl.uniform1i(hq.U.up.uSrc, 0);
    gl.useProgram(P.shaft); gl.uniform3fv(hq.U.shaft.uPal, pal); gl.uniform1i(hq.U.shaft.uDepth, 0);
    gl.useProgram(P.comp); gl.uniform1i(hq.U.comp.uScene, 0); gl.uniform1i(hq.U.comp.uBloom, 1); gl.uniform1i(hq.U.comp.uShafts, 2); gl.uniform1i(hq.U.comp.uPrev, 3);
    hq.phase = "on";
    hq.fade = still ? 1 : 0;
    // How fast the page ran with the plain nave: what the full one is held against.
    hq.base = state.lqDts.length >= 20 ? median(state.lqDts) : 1000 / 60;
    state.hq = true; state.half = false;
    setLevel(level);
  };
  // Back to the plain nave, for a while: the full one is tried again later, once.
  const leaveHQ = () => {
    freeTargets();
    hq.phase = ++hq.left < 2 ? "ready" : "off";
    hq.retryAt = performance.now() + hq.capMs;
    hq.capMs *= 2;
    state.hq = false;
    state.lqDts = [];
    state.scale = 0.6; state.cost = 0; state.settle = 2; state.frames = 0;
    canvas.dataset.tier = "lq";
  };
  const pollHQ = () => {
    const jobs = Object.values(hq.jobs);
    if (!done(jobs)) return;
    hq.phase = jobs.every(linked) ? "ready" : "off";
  };
  // The first level to try: where the plain nave's own cost says the full one should fit, from the
  // lowest up to native resolution with one sample. Without a timer, one step below that.
  const firstLevel = () => {
    if (!timer || !state.full) return 1;
    const ssCost = { 1: 1, 2: 1.5, 4: 2.4, 8: 4 };
    let pick = 0;
    LEVELS.forEach((L, i) => {
      const est = state.full * (state.maxScale * L.s) ** 2 * 3 * ssCost[L.ss];
      if (i <= 2 && est < BUDGET * 0.6) pick = i;
    });
    return pick;
  };

  const resize = () => {
    const w = Math.max(2, Math.round(canvas.clientWidth * state.scale));
    const h = Math.max(2, Math.round(canvas.clientHeight * state.scale));
    if (w === state.w && h === state.h && (!state.hq || hq.rt)) return;
    if (w !== state.w || h !== state.h) {
      state.w = canvas.width = w;
      state.h = canvas.height = h;
    }
    if (state.hq && !allocTargets(w, h)) leaveHQ();
  };

  const view = (time) => {
    const aspect = state.w / state.h;
    const p = state.progress;
    const e = p * p * (3 - 2 * p);
    // Field of view: wide enough to hold both arcades, even in portrait.
    const base = aspect >= 1.2 ? 62 : Math.min(96, (2 * Math.atan(Math.tan((29 * Math.PI) / 180) / aspect) * 180) / Math.PI);
    const vfov = ((base + 14 * Math.sin(Math.PI * p)) * Math.PI) / 180;
    const focal = 1 / Math.tan(vfov / 2);

    const settle = 1 - Math.pow(1 - clamp01(state.birth / 5.5), 3);
    const z = lerp(lerp(-7.5, -1.2, settle), ZEND - 1.5, e);
    const sway = 1 - smooth(0, 0.5, p);
    const cam = [
      (0.2 * Math.sin(time * 0.13) + state.px * 0.5) * sway,
      lerp(1.72 + 0.05 * Math.sin(time * 0.21), HROSE, smooth(0.12, 0.96, p)) - state.py * 0.12 * sway,
      z,
    ];
    // At rest the rose sits in the upper third, clear of the title; in flight the eye locks onto it.
    const elev = Math.atan((HROSE - cam[1]) / (ZEND - cam[2]));
    const want = Math.atan((1 - 2 * 0.2) * Math.tan(vfov / 2));
    const pitch = lerp(elev - want, elev, smooth(0.02, 0.55, p)) + state.py * 0.02 * sway;
    const yaw = state.px * 0.045 * sway + 0.006 * Math.sin(time * 0.17) * sway;
    const fwd = norm([Math.sin(yaw) * Math.cos(pitch), Math.sin(pitch), Math.cos(yaw) * Math.cos(pitch)]);
    const roll = (0.006 * Math.sin(time * 0.11) + state.px * 0.008) * sway;
    const right = norm(cross([Math.sin(roll), Math.cos(roll), 0], fwd));
    const up = cross(fwd, right);

    const v = [0 - cam[0], HROSE - cam[1], ZEND - cam[2]];
    const depth = v[0] * fwd[0] + v[1] * fwd[1] + v[2] * fwd[2];
    const rose = depth > 0.2
      ? [((v[0] * right[0] + v[1] * right[1] + v[2] * right[2]) / depth) * focal, ((v[0] * up[0] + v[1] * up[1] + v[2] * up[2]) / depth) * focal, (RROSE / depth) * focal]
      : [0, 0, -1];
    return {
      aspect, focal, cam, rose,
      basis: [...right, ...up, ...fwd],
      expo: 1.3 - 0.25 * smooth(0.55, 1, p),
      dust: state.ignite * (1 - smooth(0.6, 0.95, p)),
    };
  };

  const setScene = (u, v, time) => {
    gl.uniform2f(u.uRes, state.w, state.h);
    setBays(u.uBay, time, state.ignite);
    gl.uniform1f(u.uTime, time);
    gl.uniform1f(u.uFocal, v.focal);
    gl.uniform1f(u.uIgnite, state.ignite);
    if (u.uExpo) gl.uniform1f(u.uExpo, v.expo);
    gl.uniform1f(u.uPix, 2 / (state.h * v.focal));
    gl.uniform3f(u.uCam, v.cam[0], v.cam[1], v.cam[2]);
    gl.uniformMatrix3fv(u.uBasis, false, v.basis);
    gl.uniform3f(u.uRose, v.rose[0], v.rose[1], v.rose[2]);
  };

  const drawDust = (v, time, gain) => {
    gl.useProgram(dust);
    gl.uniform3f(D.uCam, v.cam[0], v.cam[1], v.cam[2]);
    gl.uniformMatrix3fv(D.uBasis, false, v.basis);
    gl.uniform1f(D.uFocal, v.focal);
    gl.uniform1f(D.uTime, time);
    gl.uniform1f(D.uAspect, v.aspect);
    gl.uniform1f(D.uSize, state.h * 0.02);
    gl.uniform1f(D.uIgnite, v.dust);
    gl.uniform1f(D.uGain, gain);
    gl.bindVertexArray(motes);
    gl.enable(gl.BLEND);
    gl.drawArrays(gl.POINTS, 0, MOTES);
    gl.disable(gl.BLEND);
  };

  const drawPlain = (v, time) => {
    gl.useProgram(prog);
    setScene(U, v, time);
    gl.uniform1i(U.uMarch, 12);
    gl.uniform1i(U.uBounces, 2);
    gl.bindVertexArray(quad);
    gl.drawArrays(gl.TRIANGLES, 0, 3);
    drawDust(v, time, 1);
  };

  const drawFull = (v, time) => {
    const { P, U: Q, rt } = hq, L = LEVELS[hq.level];
    if (hq.fade < 1) {
      if (!rt.prev) rt.prev = target(state.w, state.h);
      gl.bindFramebuffer(gl.FRAMEBUFFER, rt.prev.fb);
      gl.viewport(0, 0, state.w, state.h);
      drawPlain(v, time);
    } else if (rt.prev) {
      gl.deleteTexture(rt.prev.tex); gl.deleteFramebuffer(rt.prev.fb);
      rt.prev = null;
    }
    gl.bindFramebuffer(gl.FRAMEBUFFER, rt.scene.fb);
    gl.viewport(0, 0, state.w, state.h);
    gl.useProgram(P.scene);
    setScene(Q.scene, v, time);
    gl.uniform1i(Q.scene.uSS, L.ss);
    gl.uniform1i(Q.scene.uSteps, L.steps);
    gl.uniform1i(Q.scene.uMarch, 16);
    gl.uniform1i(Q.scene.uBounces, 2);
    gl.uniform1f(Q.scene.uAAk, 1 / Math.sqrt(L.ss));
    gl.bindVertexArray(quad);
    gl.drawArrays(gl.TRIANGLES, 0, 3);
    // The motes go into colour only: the alpha of the scene holds its depth.
    gl.colorMask(true, true, true, false);
    drawDust(v, time, 0.45);
    gl.colorMask(true, true, true, true);

    gl.bindFramebuffer(gl.FRAMEBUFFER, rt.shaft.fb);
    gl.viewport(0, 0, rt.shaft.w, rt.shaft.h);
    gl.useProgram(P.shaft);
    const sw = state.w, sh = state.h;
    state.w = rt.shaft.w; state.h = rt.shaft.h;
    setScene(Q.shaft, v, time);
    state.w = sw; state.h = sh;
    gl.uniform1i(Q.shaft.uSteps, L.steps);
    gl.activeTexture(gl.TEXTURE0);
    gl.bindTexture(gl.TEXTURE_2D, rt.scene.tex);
    // The motes left their own vertex array bound: every pass from here on draws the full-screen triangle.
    gl.bindVertexArray(quad);
    gl.drawArrays(gl.TRIANGLES, 0, 3);

    gl.useProgram(P.down);
    gl.uniform1f(Q.down.uThresh, 0.85);
    let src = rt.scene;
    rt.mips.forEach((m, i) => {
      gl.bindFramebuffer(gl.FRAMEBUFFER, m.fb);
      gl.viewport(0, 0, m.w, m.h);
      gl.bindTexture(gl.TEXTURE_2D, src.tex);
      gl.uniform2f(Q.down.uTexel, 1 / src.w, 1 / src.h);
      gl.uniform2f(Q.down.uDst, 1 / m.w, 1 / m.h);
      gl.uniform1i(Q.down.uFirst, i === 0 ? 1 : 0);
      gl.drawArrays(gl.TRIANGLES, 0, 3);
      src = m;
    });
    gl.useProgram(P.up);
    gl.enable(gl.BLEND);
    for (let i = rt.mips.length - 2; i >= 0; i--) {
      const m = rt.mips[i], s = rt.mips[i + 1];
      gl.bindFramebuffer(gl.FRAMEBUFFER, m.fb);
      gl.viewport(0, 0, m.w, m.h);
      gl.bindTexture(gl.TEXTURE_2D, s.tex);
      gl.uniform2f(Q.up.uTexel, 1 / s.w, 1 / s.h);
      gl.uniform2f(Q.up.uDst, 1 / m.w, 1 / m.h);
      gl.drawArrays(gl.TRIANGLES, 0, 3);
    }
    gl.disable(gl.BLEND);

    gl.bindFramebuffer(gl.FRAMEBUFFER, null);
    gl.viewport(0, 0, state.w, state.h);
    gl.useProgram(P.comp);
    gl.bindTexture(gl.TEXTURE_2D, rt.scene.tex);
    gl.activeTexture(gl.TEXTURE1);
    gl.bindTexture(gl.TEXTURE_2D, rt.mips[0].tex);
    gl.activeTexture(gl.TEXTURE2);
    gl.bindTexture(gl.TEXTURE_2D, rt.shaft.tex);
    gl.uniform2f(Q.comp.uShaftTexel, 1 / rt.shaft.w, 1 / rt.shaft.h);
    gl.uniform1f(Q.comp.uFade, smooth(0, 1, hq.fade));
    if (rt.prev) { gl.activeTexture(gl.TEXTURE3); gl.bindTexture(gl.TEXTURE_2D, rt.prev.tex); }
    gl.uniform2f(Q.comp.uRes, state.w, state.h);
    gl.uniform1f(Q.comp.uExpo, v.expo);
    gl.uniform1f(Q.comp.uBloomK, 0.1);
    gl.uniform1f(Q.comp.uTime, time);
    gl.drawArrays(gl.TRIANGLES, 0, 3);
    for (const unit of [3, 2, 1]) { gl.activeTexture(gl.TEXTURE0 + unit); gl.bindTexture(gl.TEXTURE_2D, null); }
    gl.activeTexture(gl.TEXTURE0);
  };

  // Timing. Where the browser has GPU timer queries, a frame is timed on the GPU itself and read back
  // a few frames later, without stalling anything. One query is in flight at a time, tagged with
  // what it measured, so that a result arriving after a change is dropped.
  const timer = gl.getExtension("EXT_disjoint_timer_query_webgl2");
  const clock = { q: null, tag: "" };
  const config = () => (state.hq ? `hq${hq.level}` : `lq${state.w}x${state.h}`);
  const clockRead = () => {
    if (!clock.q) return null;
    const ready = gl.getQueryParameter(clock.q, gl.QUERY_RESULT_AVAILABLE);
    const disjoint = gl.getParameter(timer.GPU_DISJOINT_EXT);
    if (!ready && !disjoint) return null;
    const ms = ready && !disjoint ? gl.getQueryParameter(clock.q, gl.QUERY_RESULT) / 1e6 : -1;
    gl.deleteQuery(clock.q);
    clock.q = null;
    return ms >= 0 && clock.tag === config() ? ms : null;
  };

  const draw = (time) => {
    if (!plain.ready) return;
    resize();
    gl.viewport(0, 0, state.w, state.h);
    const v = view(time);
    // The frames of the fade draw both naves: they are not timed.
    const timed = timer && !clock.q && !(state.hq && hq.fade < 1);
    if (timed) { clock.q = gl.createQuery(); clock.tag = config(); gl.beginQuery(timer.TIME_ELAPSED_EXT, clock.q); }
    if (state.hq) drawFull(v, time);
    else drawPlain(v, time);
    if (timed) gl.endQuery(timer.TIME_ELAPSED_EXT);
    state.rose = v.rose;
  };

  // The plain nave follows the cost of a frame, resizing its buffer to land near a budget: full size
  // on a GPU; on a software rasteriser a smaller buffer, redrawn every other frame so that it does not
  // have to be smaller still. The same cost tells a GPU from a software rasteriser, and on a GPU the
  // full nave takes over as soon as it is built. Without timer queries a draw is timed to completion
  // now and then, which also counts the wait for the pipeline: the thresholds allow for that.
  const judge = (cost) => {
    state.cost = state.cost ? state.cost * 0.5 + cost * 0.5 : cost;
    const full = Math.max(state.cost, 0.5) / (state.scale * state.scale);
    state.full = full;
    state.half = full > 28;
    // A GPU from a software rasteriser: timed on the GPU, by the cost of a megapixel (tens of
    // milliseconds on a CPU, a few on the weakest GPU even when it also composites the desktop);
    // timed to completion, by the cost of a frame, which then also counts the wait for the pipeline.
    state.fast = timer ? state.cost / Math.max(state.w * state.h / 1e6, 0.05) < 15 : full < 20;
    const want = Math.min(state.maxScale, Math.max(0.5, Math.sqrt((state.half ? 21 : 11.5) / full)));
    if (Math.abs(want - state.scale) / state.scale > 0.1) { state.scale = want; state.cost = 0; state.settle = 1; state.lqMs = []; }
  };
  const pixel = new Uint8Array(4);
  const probe = (time) => {
    const a = performance.now();
    draw(time);
    gl.readPixels(0, 0, 1, 1, gl.RGBA, gl.UNSIGNED_BYTE, pixel);
    const cost = performance.now() - a;
    // The first timing after a resize pays for reallocation: skip it.
    if (state.settle > 0) { state.settle--; return; }
    judge(cost);
  };

  // The full nave watches two things: the GPU time of its frames, where the browser can time them,
  // and the interval between frames, which also counts everything else the page and the browser do.
  // The median of the last frames decides: one level down when the GPU budget runs over, or when
  // frames come slower than about 50 a second and slower than they came with the plain nave, if the
  // nave's own share of the frame is large enough to be the cause; one up while the frame rate holds
  // and the next level should still fit. A level given up is not tried again for a while, and for
  // longer each time.
  const watch = (dt) => {
    // The shortest interval seen is the display's refresh; anything faster than 60 Hz is a bonus.
    state.refresh = Math.min(state.refresh || 1e3, Math.max(dt, 4));
    const frame = Math.max(state.refresh, 1000 / 60);
    push(hq.dts, dt);
    if (timer) { const ms = clockRead(); if (ms != null) push(hq.samples, ms); }
    if (hq.dts.length < 24 || (timer && hq.samples.length < 10)) return;
    const f = median(hq.dts), g = timer ? median(hq.samples) : 0;
    const slow = f > Math.max(frame * 1.2, hq.base * 1.15);
    // A GPU that also composites the desktop times the nave together with the rest of its work, so
    // GPU time alone brings the nave down only when it fills the frame; slow frames do, when the
    // nave's share of the frame is large enough to be their cause.
    if (g > frame || (slow && (!timer || g > frame * 0.25))) return stepDown();
    if (hq.level >= LEVELS.length - 1 || (hq.level >= hq.ceiling && performance.now() < hq.capUntil)) return;
    // The next level costs up to 1.8 times this one; without a timer it can only be tried.
    const room = timer ? g * 1.8 < BUDGET : ++hq.calm > 120;
    if (room && f < Math.max(frame, hq.base) * 1.06) setLevel(hq.level + 1);
  };
  const stepDown = () => {
    if (hq.level === 0) return leaveHQ();
    hq.ceiling = hq.level - 1;
    hq.capUntil = performance.now() + hq.capMs;
    hq.capMs *= 2;
    setLevel(hq.level - 1);
  };

  const tick = (now) => {
    if (!state.running) return;
    if (!plain.ready && !plainReady()) return;
    const dt = state.last ? now - state.last : 16;
    state.last = now;
    const step = Math.min(dt, 80) / 1000;
    state.birth += step;
    state.ignite = Math.min(1, state.ignite + step / 3.4);
    state.px += (state.tx - state.px) * Math.min(1, step * 3);
    state.py += (state.ty - state.py) * Math.min(1, step * 3);
    const time = (now - state.t0) / 1000;
    if (hq.phase === "compiling") pollHQ();
    // A still frame (reduced motion): the plain nave as soon as it is built, the full one at its
    // best once that is built too, and nothing more.
    if (still) {
      if (hq.phase === "ready") enterHQ(4);
      if (!state.shown || state.hq) draw(30);
      if (!state.shown) { state.shown = true; onReady(); }
      if (hq.phase !== "compiling") state.running = false;
      return;
    }
    if (hq.phase === "ready" && state.fast && performance.now() >= hq.retryAt) enterHQ(firstLevel());
    if (state.hq) {
      // A hidden tab or a long task says nothing about the GPU.
      if (hq.fade < 1) hq.fade = Math.min(1, hq.fade + step / 1.4);
      else if (dt < 250) watch(dt);
      draw(time);
      return;
    }
    if (dt < 250 && state.shown) push(state.lqDts, dt);
    if (timer) {
      // The median of a few frames: a GPU that also composites the desktop gives noisy timings.
      const ms = clockRead();
      if (ms != null) { push(state.lqMs, ms); if (state.lqMs.length >= 8 && ++state.judged % 4 === 0) judge(median(state.lqMs)); }
      if (!state.half || (state.flip ^= 1)) draw(time);
    } else if (state.frames++ % (state.frames < 90 ? 12 : 60) === 3) probe(time);
    else if (!state.half || (state.flip ^= 1)) draw(time);
    if (!state.shown) { state.shown = true; onReady(); }
  };

  return {
    canvas,
    state,
    tick,
    setProgress(p) { state.progress = clamp01(p); },
    setPointer(x, y) { state.tx = x; state.ty = y; },
    start() { if (!state.running) { state.running = true; state.last = 0; state.frames = 0; } },
    stop() { state.running = false; },
    render() { draw(still ? 30 : (performance.now() - state.t0) / 1000); },
  };
}
