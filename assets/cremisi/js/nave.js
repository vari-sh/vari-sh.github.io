// The nave: a gothic interior traced analytically in a single fragment shader. No marching, no
// meshes: every ray is intersected in closed form with the floor, the arcade walls, the columns,
// the pointed vault and the end wall, so the scene stays cheap enough for software rasterisers.
// The glass takes its colours from the palette in data/cremisi.yaml.

const VERT = `#version 300 es
in vec2 aPos;
void main() { gl_Position = vec4(aPos, 0., 1.); }`;

const FRAG = `#version 300 es
precision highp float;
uniform vec2 uRes;
uniform float uTime, uFocal, uIgnite, uExpo, uPix;
uniform vec3 uCam;
uniform mat3 uBasis;
uniform vec3 uPal[12];
uniform vec3 uBay[20];
uniform vec3 uRose;
out vec4 outColor;

#define TAU 6.2831853
const float WN = 3.2, WA = 6.8, BAY = 4.4, CR = .44, CAPR = .6, SHR = .19, HTOP = 5.14;
const float HCAP = 5., HS = 1.8, RAD = 3.4;
const float HAISLE = 8.9, HCL0 = 10.2, HCLS = 13.1, HV = 15.4, VC = 1.7, RV = WN + VC;
const float ZEND = 39.6, HROSE = 11.3, RROSE = 2.8;
const vec3 ROSECOL = vec3(1., .40, .44);
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

vec3 rose(vec2 q, float aa) {
  float r = length(q), a = atan(q.y, q.x);
  float sa = a / TAU * 12., id = floor(sa + .5);
  float la = (sa - id) * TAU / 12.;
  vec2 p = r * vec2(cos(la), sin(la));
  float la2 = (sa - floor(sa) - .5) * TAU / 12.;
  vec2 p2 = r * vec2(cos(la2), sin(la2));
  float s6 = a / TAU * 6., la6 = (s6 - floor(s6 + .5)) * TAU / 6.;
  vec2 p6 = r * vec2(cos(la6), sin(la6));
  float idm = mod(id + 12., 12.);

  float d = sdUCap(vec2(p.y, p.x - .25), .03, .105, .31);
  vec3 tint = mod(idm, 2.) < .5 ? uPal[10] : uPal[0];
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

  float e = aa * 1.3 + .003;
  float gl = smoothstep(e, -e, d);
  float life = .86 + .14 * vnoise(vec2(uTime * .22 + id * 1.7, id));
  vec3 g = glass(q * RROSE * 1.25, tint, d * RROSE, aa * RROSE, id) * life * 1.15;
  vec3 st = vec3(.012, .011, .014) + tint * exp(-max(d, 0.) * 34.) * .22;
  return mix(st, g, gl) * roseIgn();
}

float masonry(vec2 uv, float aa) {
  vec2 s = vec2(1.1, .55);
  float row = floor(uv.y / s.y), x = uv.x / s.x + .5 * mod(row, 2.);
  vec2 f = vec2(fract(x), fract(uv.y / s.y));
  float j = smoothstep(0., .028, min(f.x, 1. - f.x)) * smoothstep(0., .055, min(f.y, 1. - f.y));
  float tone = .8 + .4 * h21(vec2(floor(x), row));
  return mix(1., tone * (.5 + .5 * j), clamp(1. - aa * 5., 0., 1.));
}

vec3 stone(vec3 p, vec3 n, vec3 alb) {
  vec3 L = vec3(0., HROSE, ZEND - .4) - p;
  float d2 = dot(L, L); L *= inversesqrt(d2);
  float wrap = max((dot(n, L) + .55) / 1.55, 0.);
  vec3 key = ROSECOL * wrap * wrap * (.78 / (1.7 + d2 * .0042)) * roseIgn();
  float k = floor(p.z / BAY);
  float xl = p.x + WA, xr = WA - p.x;
  float wl = (max(-n.x, 0.) + .5 * max(n.y, 0.) + .1) / (1. + .07 * xl * xl);
  float wr = (max(n.x, 0.) + .5 * max(n.y, 0.) + .1) / (1. + .07 * xr * xr);
  vec3 side = (bayTint(k, -1.) * wl + bayTint(k, 1.) * wr) * .42;
  vec3 amb = vec3(.016, .016, .025) * (.65 + .35 * n.y) + vec3(.012, .014, .024) * max(-n.z, 0.);
  return alb * (amb + key + side);
}

// id: 0 floor · 1 end wall · 2 vault · 3 column · 4 nave wall · 5 aisle wall · 6 aisle ceiling
vec3 trace(vec3 ro, vec3 rd, out float tOut, out int idOut) {
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
    float zIn = ro.z + rd.z * (WN - CAPR - sx * ro.x) * irx;
    float k = ceil((zIn - CAPR) / BAY), a2 = dot(rd.xz, rd.xz);
    for (int i = 0; i < 3; i++) {
      float zk = (k + float(i)) * BAY;
      if (zk > ZEND + 1.) break;
      vec2 o = vec2(ro.x - sx * WN, ro.z - zk);
      float b = dot(o, rd.xz), oo = dot(o, o);
      float h = b * b - a2 * (oo - CAPR * CAPR);
      if (h <= 0.) continue;
      float r = CAPR, tt = (-b - sqrt(h)) / a2, y = ro.y + rd.y * tt;
      bool ok = tt > 0. && ((y > HCAP - .5 && y < HTOP) || y < .34);
      if (!ok) {
        h = b * b - a2 * (oo - CR * CR);
        if (h > 0.) { r = CR; tt = (-b - sqrt(h)) / a2; y = ro.y + rd.y * tt; ok = tt > 0. && y < HCAP - .4; }
      }
      if (!ok) {
        h = b * b - a2 * (oo - SHR * SHR);
        if (h > 0.) { r = SHR; tt = (-b - sqrt(h)) / a2; y = ro.y + rd.y * tt; ok = tt > 0. && y >= HCAP && y < HV + .4; }
      }
      if (ok) {
        if (tt < t) { t = tt; id = 3; vec2 q = o + rd.xz * tt; n = vec3(q.x, 0., q.y) / r; }
        break;
      }
    }
    if (rd.y < 0. && ro.y > HTOP) {
      float tt = (HTOP - ro.y) / rd.y;
      vec3 pt = ro + rd * tt;
      vec2 dq = vec2(abs(pt.x) - WN, pt.z - floor(pt.z / BAY + .5) * BAY);
      if (tt < t && dot(dq, dq) < CAPR * CAPR && abs(pt.x) < WN) { t = tt; id = 3; n = vec3(0., 1., 0.); }
    }
    float tW = (WN - sx * ro.x) * irx;
    if (tW < t) {
      vec3 p = ro + rd * tW;
      float zl = mod(p.z, BAY) - BAY * .5;
      if (sdArch(vec2(zl, p.y - HCAP), HS, RAD) > 0.) { t = tW; id = 4; n = vec3(-sx, 0., 0.); }
      else {
        if (tA < t) { t = tA; id = 5; n = vec3(-sx, 0., 0.); }
        if (tC < t && tC > tW) { t = tC; id = 6; n = vec3(0., -1., 0.); }
      }
    }
  } else {
    if (tA < t) { t = tA; id = 5; n = vec3(-sx, 0., 0.); }
    if (tC < t) { t = tC; id = 6; n = vec3(0., -1., 0.); }
  }

  vec3 p = ro + rd * t;
  float aa = t * uPix;
  float zl = mod(p.z, BAY) - BAY * .5, kb = floor(p.z / BAY);
  vec3 col;
  tOut = t; idOut = id;

  if (id == 0) {
    vec2 g = vec2(p.x + p.z, p.x - p.z) * .64;
    vec2 gi = floor(g), gf = abs(fract(g) - .5);
    float far = clamp(1. - aa * 3.2, 0., 1.);
    vec3 alb = mix(vec3(.105, .048, .06), mix(vec3(.05, .046, .056), vec3(.16, .05, .065), mod(gi.x + gi.y, 2.)), far);
    alb *= mix(1., (.45 + .55 * smoothstep(.5, .468, max(gf.x, gf.y))) * (.78 + .44 * h21(gi)), far);
    col = stone(p, n, alb);
  } else if (id == 1) {
    vec2 q = p.xy;
    vec3 alb = vec3(.3, .29, .33) * masonry(q, aa), em = vec3(0.);
    if (abs(q.x) < WN) {
      vec2 rq = (q - vec2(0., HROSE)) / RROSE;
      float rr = length(rq);
      if (rr < 1.) { return rose(rq, aa / RROSE); }
      float li = clamp(floor(q.x / 1.22 + .5), -2., 2.);
      float sdL = max(sdArch(vec2(q.x - li * 1.22, q.y - 6.1), .42, 1.), 2.4 - q.y);
      vec3 tint = uPal[ENDL[int(li) + 2]] * ign(8.5);
      if (sdL < 0.) return glass(q * 1.4, tint, sdL, aa, li * 3.) * .62;
      em = tint * exp(-sdL * 3.2) * .11 + ROSECOL * exp(-(rr - 1.) * 1.5) * .22 * roseIgn();
      alb = mix(alb, vec3(.46, .44, .47), smoothstep(.09, .04, abs(rr - 1.07)) + smoothstep(.07, .03, abs(sdL - .07)) * .7);
      alb *= .55 + .45 * smoothstep(1., 1.2, rr);
    } else {
      float sdL = max(sdArch(vec2(abs(q.x) - 5., q.y - 5.4), .72, 1.6), 2.2 - q.y);
      vec3 tint = bayTint(8., q.x) * 1.;
      if (sdL < 0. && q.y < HAISLE) return glass(q, tint, sdL, aa, 5.);
      em = tint * exp(-max(sdL, 0.) * 2.4) * .12;
      alb *= step(q.y, HAISLE) * .8 + .2;
    }
    col = alb * (vec3(.011, .011, .017) + em * 2.4) + em * .4;
  } else if (id == 2) {
    float th = atan(p.y - HV, abs(p.x) + VC), u = th / 1.2165;
    float rib = smoothstep(.17 + aa, .1, BAY * .5 - abs(zl));
    rib = max(rib, smoothstep(.17 + aa, .1, (1. - u) * 1.2165 * RV));
    rib = max(rib, smoothstep(.13 + aa, .07, abs(abs(zl) - BAY * .5 * (1. - u)) * .8));
    vec3 alb = mix(vec3(.17, .165, .2) * (.86 + .14 * sin(p.z * 5.3 + th * 23.) * sin(th * 31. - p.z * 2.9)), vec3(.4, .38, .42), rib);
    col = stone(p, n, alb) * (.5 + .5 * (1. - u));
  } else if (id == 3) {
    float az = atan(n.z, n.x);
    vec3 alb = vec3(.33, .32, .36) * (.86 + .14 * cos(az * 10.));
    alb *= .8 + .2 * smoothstep(.5, .47, abs(fract(p.y / 1.25) - .5));
    if (p.y > HCAP - .5) {
      float cap = step(p.y, HTOP + .01);
      alb = mix(vec3(.37, .355, .395), vec3(.47, .45, .48) * (.72 + .28 * smoothstep(0., .05, abs(p.y - HCAP + .2))), cap);
      alb *= .86 + .14 * cos(az * 16.) * cap;
    } else if (p.y < .34) alb = vec3(.44, .42, .45) * (.75 + .25 * smoothstep(0., .04, abs(p.y - .2)));
    col = stone(p, n, alb) * (.45 + .55 * smoothstep(0., .9, p.y));
  } else if (id == 4) {
    vec3 alb = vec3(.3, .29, .33) * masonry(p.zy, aa), em = vec3(0.);
    if (p.y < HAISLE) {
      float sd = sdArch(vec2(zl, p.y - HCAP), HS, RAD);
      alb = mix(alb, vec3(.43, .41, .45) * (.62 + .38 * smoothstep(.02, .06, abs(sd - .17))), smoothstep(.34, .3, sd));
      em = bayTint(kb, sx) * smoothstep(.3, 0., sd) * .05;
      alb = mix(alb, vec3(.46, .44, .47), smoothstep(.12, .07, abs(p.y - HAISLE + .12)));
    } else if (p.y < HCL0 - .12) {
      float zt = mod(p.z, BAY * .25) - BAY * .125;
      float sdT = max(sdArch(vec2(zt, p.y - HAISLE - .68), .34, .7), HAISLE + .2 - p.y);
      alb *= mix(.2, 1., smoothstep(-.02, .03 + aa, sdT));
      alb = mix(alb, vec3(.44, .42, .46), smoothstep(.08, .04, abs(sdT - .06)) * .55);
    } else {
      float zc = abs(zl) - .98;
      float sdC = max(sdArch(vec2(zc, p.y - HCLS), .6, 1.3), HCL0 + .1 - p.y);
      vec3 tint = bayTint(kb, sx);
      if (sdC < 0.) return glass(vec2(zc, p.y), tint, sdC, aa, kb * 7. + sx);
      em = tint * exp(-sdC * 2.3) * .1;
      alb = mix(alb, vec3(.45, .43, .47), smoothstep(.1, .05, abs(sdC - .08)) * .6);
    }
    col = stone(p, n, alb) + em;
  } else if (id == 5) {
    float sdL = max(sdArch(vec2(zl, p.y - 5.5), .9, 2.), 2. - p.y);
    vec3 tint = bayTint(kb, sx);
    if (sdL < 0.) return glass(vec2(zl, p.y), tint, sdL, aa, kb * 3. + sx) * mix(.42, 1., smoothstep(4., 16., t));
    vec3 alb = vec3(.28, .27, .31) * masonry(p.zy, aa);
    alb = mix(alb, vec3(.44, .42, .46), smoothstep(.1, .05, abs(sdL - .09)) * .6);
    col = alb * (vec3(.012, .012, .018) + tint * exp(-sdL * 1.7) * .5 + bayTint(kb, -sx) * .03);
  } else {
    float rib = smoothstep(.16, .1, BAY * .5 - abs(zl));
    col = mix(vec3(.02, .019, .025), vec3(.045, .042, .05), rib) * (.5 + (bayTint(kb, sx) + .2));
  }
  return col;
}

vec3 fog(vec3 col, float t) {
  float f = exp(-t * .021);
  return mix(vec3(.02, .008, .012) * (.4 + .6 * roseIgn()), col, f);
}

void main() {
  vec2 uv = (gl_FragCoord.xy * 2. - uRes) / uRes.y;
  vec3 rd = normalize(uBasis * vec3(uv, uFocal));
  float t, t2; int id, id2;
  vec3 col = trace(uCam, rd, t, id);
  if (id == 0) {
    vec3 p = uCam + rd * t;
    float nz = .5 + .5 * sin(p.x * 1.3 + 1.7 * sin(p.z * .9)) * sin(p.z * 1.1 + 1.3 * sin(p.x * .7));
    vec3 n = normalize(vec3((nz - .5) * .011, 1., (fract(nz * 7.3) - .5) * .011));
    vec3 rr = reflect(rd, n);
    rr.y = abs(rr.y) + 2e-3;
    float F = .045 + .955 * pow(1. - max(dot(-rd, n), 0.), 5.);
    vec3 rc = trace(p + vec3(0., 1e-3, 0.), rr, t2, id2);
    col += fog(rc, t2) * F * (.62 + .3 * nz);
  }
  col = fog(col, t);

  if (uRose.z > 0.) {
    vec2 dv = uv - uRose.xy;
    float dist = length(dv), ang = atan(dv.y, dv.x), rr = uRose.z;
    float beams = pow(.5 + .5 * cos(ang * 12.), 4.) * .35 + .65 * (.5 + .3 * cos(ang * 7. + uTime * .11) + .2 * cos(ang * 19. - uTime * .07));
    beams *= .4 + .6 * (.5 + .3 * cos(ang * 31. + uTime * .23) + .2 * cos(ang * 53. - uTime * .17));
    col += ROSECOL * beams * exp(-dist * 2.6) * smoothstep(rr * .8, rr * 2.6, dist) * (.3 / (1. + rr * rr * 6.)) * roseIgn();
    col += ROSECOL * exp(-dist * dist / (rr * rr * 7. + .02)) * (.2 / (1. + rr * rr * 30.)) * roseIgn();
  }

  col *= uExpo;
  col = (col * (2.51 * col + .03)) / (col * (2.43 * col + .59) + .14);
  col = pow(clamp(col, 0., 1.), vec3(.4545));
  col *= 1. - .3 * smoothstep(.5, 1.9, length(uv * vec2(.82, 1.)));
  col += (h21(gl_FragCoord.xy + fract(uTime)) - .5) / 160.;
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
in float vA;
out vec4 outColor;
void main() {
  float d = length(gl_PointCoord - .5);
  outColor = vec4(vec3(1., .72, .66) * smoothstep(.5, .05, d) * vA * .5, 1.);
}`;

const ZEND = 39.6;
const HROSE = 11.3;
const RROSE = 2.8;

const lerp = (a, b, t) => a + (b - a) * t;
const clamp01 = (x) => Math.min(1, Math.max(0, x));
const smooth = (a, b, x) => { const t = clamp01((x - a) / (b - a)); return t * t * (3 - 2 * t); };
const norm = (v) => { const l = Math.hypot(v[0], v[1], v[2]) || 1; return [v[0] / l, v[1] / l, v[2] / l]; };
const cross = (a, b) => [a[1] * b[2] - a[2] * b[1], a[2] * b[0] - a[0] * b[2], a[0] * b[1] - a[1] * b[0]];

const compile = (gl, type, src) => {
  const s = gl.createShader(type);
  gl.shaderSource(s, src);
  gl.compileShader(s);
  if (!gl.getShaderParameter(s, gl.COMPILE_STATUS)) throw new Error(gl.getShaderInfoLog(s));
  return s;
};

export const srgbToLinear = (hex) => {
  const n = parseInt(hex.slice(1), 16);
  return [(n >> 16) & 255, (n >> 8) & 255, n & 255].map((c) => Math.pow(c / 255, 2.2));
};

// palette: twelve hex colours, in the order the shader expects (ten bays, then crimson and bone).
export function createNave(canvas, palette, { still = false } = {}) {
  const gl = canvas.getContext("webgl2", { antialias: false, alpha: false, depth: false, stencil: false, powerPreference: "high-performance" });
  if (!gl) return null;
  const link = (vs, fs) => {
    const pr = gl.createProgram();
    gl.attachShader(pr, compile(gl, gl.VERTEX_SHADER, vs));
    gl.attachShader(pr, compile(gl, gl.FRAGMENT_SHADER, fs));
    gl.linkProgram(pr);
    if (!gl.getProgramParameter(pr, gl.LINK_STATUS)) throw new Error(gl.getProgramInfoLog(pr));
    return pr;
  };
  let prog, dust;
  try {
    prog = link(VERT, FRAG);
    dust = link(DUST_VERT, DUST_FRAG);
  } catch (err) {
    console.warn("Cremisi nave: shader failed", err);
    return null;
  }
  const uniforms = (pr, names) => Object.fromEntries(names.map((n) => [n, gl.getUniformLocation(pr, n)]));
  const quad = gl.createVertexArray();
  gl.bindVertexArray(quad);
  gl.bindBuffer(gl.ARRAY_BUFFER, gl.createBuffer());
  gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 3, -1, -1, 3]), gl.STATIC_DRAW);
  const posLoc = gl.getAttribLocation(prog, "aPos");
  gl.enableVertexAttribArray(posLoc);
  gl.vertexAttribPointer(posLoc, 2, gl.FLOAT, false, 0, 0);
  const U = uniforms(prog, ["uRes", "uTime", "uFocal", "uIgnite", "uExpo", "uPix", "uCam", "uBasis", "uPal", "uBay", "uRose"]);

  const MOTES = 280;
  const seeds = new Float32Array(MOTES * 3);
  let seed = 7;
  for (let i = 0; i < seeds.length; i++) { seed = (seed * 16807) % 2147483647; seeds[i] = seed / 2147483647; }
  const motes = gl.createVertexArray();
  gl.bindVertexArray(motes);
  gl.bindBuffer(gl.ARRAY_BUFFER, gl.createBuffer());
  gl.bufferData(gl.ARRAY_BUFFER, seeds, gl.STATIC_DRAW);
  const seedLoc = gl.getAttribLocation(dust, "aSeed");
  gl.enableVertexAttribArray(seedLoc);
  gl.vertexAttribPointer(seedLoc, 3, gl.FLOAT, false, 0, 0);
  const D = uniforms(dust, ["uCam", "uBasis", "uFocal", "uTime", "uAspect", "uSize", "uIgnite"]);
  gl.blendFunc(gl.ONE, gl.ONE);
  gl.useProgram(prog);

  // Glass is deeper than the flat swatches: raise the contrast between channels before it becomes light.
  const pal = new Float32Array(36);
  palette.forEach((hex, i) => {
    const c = srgbToLinear(hex).map((v) => Math.pow(v, 1.55));
    const peak = Math.max(...c, 1e-3);
    for (let j = 0; j < 3; j++) pal[i * 3 + j] = (c[j] / peak) * Math.pow(peak, 0.55);
  });
  gl.uniform3fv(U.uPal, pal);
  const bays = new Float32Array(60);
  const setBays = (time, ignite) => {
    for (let k = -1; k < 9; k++) for (let side = 0; side < 2; side++) {
      const i = ((k + side * 5 + 40) % 10) * 3, o = ((k + 1) * 2 + side) * 3;
      const lit = clamp01(ignite * 13 - (10 - k)), on = lit * lit * (3 - 2 * lit);
      const f = on * (0.9 + 0.1 * Math.sin(time * (1.1 + (((k + 2) * 7 + side * 3) % 5) * 0.38) + k * 2.1));
      bays[o] = pal[i] * f; bays[o + 1] = pal[i + 1] * f; bays[o + 2] = pal[i + 2] * f;
    }
    gl.uniform3fv(U.uBay, bays);
  };

  const state = {
    progress: 0, // scroll flight, 0..1
    px: 0, py: 0, // pointer, -1..1, eased
    tx: 0, ty: 0,
    ignite: still ? 1 : 0,
    scale: 0.6, maxScale: Math.min(window.devicePixelRatio || 1, 2), cost: 0, full: 0, settle: 2, half: false, flip: 0,
    running: false, t0: performance.now(), last: 0, frames: 0, birth: still ? 9 : 0,
    w: 0, h: 0, frozen: null,
  };

  const resize = () => {
    const w = Math.max(2, Math.round(canvas.clientWidth * state.scale));
    const h = Math.max(2, Math.round(canvas.clientHeight * state.scale));
    if (w === state.w && h === state.h) return;
    state.w = canvas.width = w;
    state.h = canvas.height = h;
    gl.viewport(0, 0, w, h);
  };

  const draw = (time) => {
    resize();
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

    gl.uniform2f(U.uRes, state.w, state.h);
    setBays(time, state.ignite);
    gl.uniform1f(U.uTime, time);
    gl.uniform1f(U.uFocal, focal);
    gl.uniform1f(U.uIgnite, state.ignite);
    gl.uniform1f(U.uExpo, 1.3 - 0.25 * smooth(0.55, 1, p));
    gl.uniform1f(U.uPix, 2 / (state.h * focal));
    gl.uniform3f(U.uCam, cam[0], cam[1], cam[2]);
    const basis = [...right, ...up, ...fwd];
    gl.uniformMatrix3fv(U.uBasis, false, basis);
    gl.uniform3f(U.uRose, rose[0], rose[1], rose[2]);
    gl.bindVertexArray(quad);
    gl.drawArrays(gl.TRIANGLES, 0, 3);

    gl.useProgram(dust);
    gl.uniform3f(D.uCam, cam[0], cam[1], cam[2]);
    gl.uniformMatrix3fv(D.uBasis, false, basis);
    gl.uniform1f(D.uFocal, focal);
    gl.uniform1f(D.uTime, time);
    gl.uniform1f(D.uAspect, aspect);
    gl.uniform1f(D.uSize, state.h * 0.02);
    gl.uniform1f(D.uIgnite, state.ignite * (1 - smooth(0.6, 0.95, p)));
    gl.bindVertexArray(motes);
    gl.enable(gl.BLEND);
    gl.drawArrays(gl.POINTS, 0, MOTES);
    gl.disable(gl.BLEND);
    gl.useProgram(prog);
    state.rose = rose;
  };

  // Resolution follows the real cost of a frame. Now and then one draw is timed to completion and the
  // buffer is resized to land near the budget: full size at every frame on a GPU; on a software
  // rasteriser a smaller buffer, redrawn every other frame so that it does not have to be smaller still.
  const pixel = new Uint8Array(4);
  const probe = (time) => {
    const a = performance.now();
    draw(time);
    gl.readPixels(0, 0, 1, 1, gl.RGBA, gl.UNSIGNED_BYTE, pixel);
    const cost = performance.now() - a;
    // The first timing after a resize pays for reallocation: skip it.
    if (state.settle > 0) { state.settle--; return; }
    state.cost = state.cost ? state.cost * 0.5 + cost * 0.5 : cost;
    const full = Math.max(state.cost, 0.5) / (state.scale * state.scale);
    state.full = full;
    state.half = full > 28;
    const want = Math.min(state.maxScale, Math.max(0.5, Math.sqrt((state.half ? 21 : 11.5) / full)));
    if (Math.abs(want - state.scale) / state.scale > 0.1) { state.scale = want; state.cost = 0; state.settle = 1; }
  };

  const tick = (now) => {
    if (!state.running) return;
    const dt = state.last ? now - state.last : 16;
    state.last = now;
    const step = Math.min(dt, 80) / 1000;
    state.birth += step;
    state.ignite = Math.min(1, state.ignite + step / 3.4);
    state.px += (state.tx - state.px) * Math.min(1, step * 3);
    state.py += (state.ty - state.py) * Math.min(1, step * 3);
    const time = (now - state.t0) / 1000;
    if (state.frames++ % (state.frames < 90 ? 12 : 60) === 3) probe(time);
    else if (!state.half || (state.flip ^= 1)) draw(time);
  };

  return {
    canvas,
    state,
    tick,
    setProgress(p) { state.progress = clamp01(p); },
    setPointer(x, y) { state.tx = x; state.ty = y; },
    start() { if (still) { draw(30); return; } if (!state.running) { state.running = true; state.last = 0; state.frames = 0; } },
    stop() { state.running = false; },
    render() { draw(still ? 30 : (performance.now() - state.t0) / 1000); },
  };
}
