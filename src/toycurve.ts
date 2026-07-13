/**
 * A tiny ILLUSTRATIVE elliptic curve over a small prime field, used only to
 * give newcomers a *picture* of what "public = scalar · G" means. This is NOT
 * cryptography — the field is 23 elements wide, so the discrete log is trivial
 * to brute-force. Its sole job is to turn scalar multiplication from algebra
 * into a sequence of hops between visible points, alongside the real X448
 * output which stays 448 bits and spec-accurate.
 *
 * Curve: y^2 = x^3 + a·x + b  (mod p), a short-Weierstrass form chosen because
 * its point-addition geometry (chord-and-tangent) is the textbook picture.
 * Parameters below give a curve of order 28 with a generator of large order, so
 * incrementing the scalar visibly walks around the whole point set.
 */

export interface ToyPoint {
  x: number;
  y: number;
  /** The point at infinity (identity element) has no affine coordinates. */
  inf: boolean;
}

export interface ToyCurve {
  p: number;
  a: number;
  b: number;
  /** Base point G. */
  G: ToyPoint;
  /** Every affine point (x, y) satisfying the curve equation, for the backdrop. */
  points: ToyPoint[];
  /** Order of G (smallest n > 0 with n·G = O). */
  order: number;
}

const INF: ToyPoint = { x: 0, y: 0, inf: true };

function mod(n: number, p: number): number {
  return ((n % p) + p) % p;
}

/** Modular inverse via extended Euclid (p is a small prime here). */
function inv(n: number, p: number): number {
  let [old_r, r] = [mod(n, p), p];
  let [old_s, s] = [1, 0];
  while (r !== 0) {
    const q = Math.floor(old_r / r);
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }
  return mod(old_s, p);
}

function eq(a: ToyPoint, b: ToyPoint): boolean {
  if (a.inf || b.inf) return a.inf === b.inf;
  return a.x === b.x && a.y === b.y;
}

/**
 * Group addition on the short-Weierstrass curve. This is the exact same
 * chord-and-tangent rule the real curves use — only the field is small.
 */
export function add(P: ToyPoint, Q: ToyPoint, c: ToyCurve): ToyPoint {
  if (P.inf) return Q;
  if (Q.inf) return P;
  // P + (−P) = O
  if (P.x === Q.x && mod(P.y + Q.y, c.p) === 0) return INF;

  let m: number;
  if (eq(P, Q)) {
    // Tangent slope for doubling: (3x² + a) / (2y).
    m = mod((3 * P.x * P.x + c.a) * inv(2 * P.y, c.p), c.p);
  } else {
    // Chord slope through two distinct points: (y2 − y1) / (x2 − x1).
    m = mod((Q.y - P.y) * inv(Q.x - P.x, c.p), c.p);
  }
  const x = mod(m * m - P.x - Q.x, c.p);
  const y = mod(m * (P.x - x) - P.y, c.p);
  return { x, y, inf: false };
}

/** Scalar multiplication k·P by repeated addition (visible, not optimized). */
export function mul(k: number, P: ToyPoint, c: ToyCurve): ToyPoint {
  let R = INF;
  for (let i = 0; i < k; i += 1) R = add(R, P, c);
  return R;
}

/** Build the illustrative curve and enumerate all its points once. */
export function makeToyCurve(): ToyCurve {
  const p = 23;
  const a = 1;
  const b = 4;
  // Precompute the quadratic residues so we can list every (x, y) on the curve.
  const points: ToyPoint[] = [];
  for (let x = 0; x < p; x += 1) {
    const rhs = mod(x * x * x + a * x + b, p);
    for (let y = 0; y < p; y += 1) {
      if (mod(y * y, p) === rhs) points.push({ x, y, inf: false });
    }
  }
  // G = (1, 3): check 1³ + 1·1 + 4 = 6, and 3² = 9 ≡ 9; pick a real point.
  const G = points.find((pt) => pt.x === 1) ?? points[0];

  const c: ToyCurve = { p, a, b, G, points, order: 0 };

  // Order of G: keep hopping until we return to the identity.
  let R: ToyPoint = { ...G };
  let n = 1;
  while (!R.inf && n < 200) {
    R = add(R, G, c);
    n += 1;
  }
  c.order = n;
  return c;
}
