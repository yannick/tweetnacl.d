/*
 * Contributors (alphabetical order)
 *  Daniel J. Bernstein, University of Illinois at Chicago and Technische Universiteit Eindhoven 
 *  Wesley Janssen, Radboud Universiteit Nijmegen 
 *  Tanja Lange, Technische Universiteit Eindhoven 
 *  Peter Schwabe, Radboud Universiteit Nijmegen
 *
 * Ported by Ketmar // Invisible Vector ( ketmar@ketmar.no-ip.org )
 *
 * Public Domain (or WTFPL).
 */
module tweetNaCl;

// define tweetnacl_enable_inlining to speed up tweetNaCl on GDC
version(GNU) {
  version(tweetnacl_enable_inlining) version=tweetnacl_enable_inlining_on_;
  else version=tweetnacl_enable_inlining_off_;
} else {
  version=tweetnacl_enable_inlining_off_;
}

version(tweetnacl_enable_inlining_off_) {
  private struct tweetNaCl_gdc_Attribute(A...) {
    A args;
  }
  auto tweetNaCl_gdc_attribute(A...)(A args) if(A.length > 0 && is(A[0] == string)) {
    return tweetNaCl_gdc_Attribute!A(args);
  }
} else {
  import gcc.attribute;
  alias tweetNaCl_gdc_attribute = attribute;
}


enum {
  crypto_auth_BYTES = 32,
  crypto_auth_KEYBYTES = 32,

  crypto_box_PUBLICKEYBYTES = 32,
  crypto_box_SECRETKEYBYTES = 32,
  crypto_box_BEFORENMBYTES = 32,
  crypto_box_NONCEBYTES = 24,
  crypto_box_ZEROBYTES = 32,
  crypto_box_BOXZEROBYTES = 16,

  crypto_core_salsa20_OUTPUTBYTES = 64,
  crypto_core_salsa20_INPUTBYTES = 16,
  crypto_core_salsa20_KEYBYTES = 32,
  crypto_core_salsa20_CONSTBYTES = 16,

  crypto_core_hsalsa20_OUTPUTBYTES = 32,
  crypto_core_hsalsa20_INPUTBYTES = 16,
  crypto_core_hsalsa20_KEYBYTES = 32,
  crypto_core_hsalsa20_CONSTBYTES = 16,

  crypto_hash_BYTES = 64,

  crypto_onetimeauth_BYTES = 16,
  crypto_onetimeauth_KEYBYTES = 32,

  crypto_scalarmult_BYTES = 32,
  crypto_scalarmult_SCALARBYTES = 32,

  crypto_secretbox_KEYBYTES = 32,
  crypto_secretbox_NONCEBYTES = 24,
  crypto_secretbox_ZEROBYTES = 32,
  crypto_secretbox_BOXZEROBYTES = 16,

  crypto_sign_BYTES = 64,
  crypto_sign_PUBLICKEYBYTES = 32,
  crypto_sign_SECRETKEYBYTES = 64,

  crypto_stream_xsalsa20_KEYBYTES = 32,
  crypto_stream_xsalsa20_NONCEBYTES = 24,

  crypto_stream_salsa20_KEYBYTES = 32,
  crypto_stream_salsa20_NONCEBYTES = 8,

  crypto_stream_KEYBYTES = 32,
  crypto_stream_NONCEBYTES = 24,

  crypto_verify_16_BYTES = 16,
  crypto_verify_32_BYTES = 32,
}


void function (ubyte[] dest, size_t len) randombytes = null;


private static immutable ubyte[16] _0 = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
private static immutable ubyte[32] _9 = [9,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];

private static immutable long[16]
  gf0 = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
  gf1 = [1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
  _121665 = [0xDB41,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
  D = [0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070, 0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203],
  D2 = [0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0, 0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406],
  X = [0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c, 0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169],
  Y = [0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666],
  I = [0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43, 0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83];

private @tweetNaCl_gdc_attribute("forceinline") uint L32() (uint x, int c) { return (x<<c)|((x&0xffffffff)>>(32-c)); }

private @tweetNaCl_gdc_attribute("forceinline") uint ld32() (const(ubyte)[] x) {
  uint u = x[3];
  u = (u<<8)|x[2];
  u = (u<<8)|x[1];
  return (u<<8)|x[0];
}

private @tweetNaCl_gdc_attribute("forceinline") ulong dl64() (const(ubyte)[] x) {
  ulong u = 0;
  for (auto i = 0; i < 8; ++i) u = (u<<8)|x[i];
  return u;
}

private @tweetNaCl_gdc_attribute("forceinline") void st32() (ubyte[] x, uint u) {
  for (auto i = 0; i < 4; ++i) { x[i] = cast(ubyte)(u&0xff); u >>= 8; }
}

private @tweetNaCl_gdc_attribute("forceinline") void ts64() (ubyte[] x, ulong u) {
  for (auto i = 7; i >= 0; --i) { x[i] = cast(ubyte)(u&0xff); u >>= 8; }
}

private @tweetNaCl_gdc_attribute("forceinline") int vn() (const(ubyte)[] x, const(ubyte)[] y, int n) {
  uint d = 0;
  for (auto i = 0; i < n; ++i) d |= x[i]^y[i];
  return (1&((d-1)>>8))-1;
}

/**
 * The crypto_verify_16() function checks that strings 'x' and 'y' has same content.
 *
 * Params:
 *  x = first string, slice length must be at least crypto_verify_16_BYTES, extra ignored
 *  y = second string, slice length must be at least crypto_verify_16_BYTES, extra ignored
 *
 * Returns:
 *  success flag
 */
@tweetNaCl_gdc_attribute("forceinline") bool crypto_verify_16() (const(ubyte)[] x, const(ubyte)[] y) {
  return (vn(x, y, 16) == 0);
}

/**
 * The crypto_verify_32() function checks that strings 'x' and 'y' has same content.
 *
 * Params:
 *  x = first string, slice length must be at least crypto_verify_32_BYTES, extra ignored
 *  y = second string, slice length must be at least crypto_verify_32_BYTES, extra ignored
 *
 * Returns:
 *  success flag
 */
@tweetNaCl_gdc_attribute("forceinline") bool crypto_verify_32() (const(ubyte)[] x, const(ubyte)[] y) {
  return (vn(x, y, 32) == 0);
}


private void core (ubyte[] out_, const(ubyte)[] in_, const(ubyte)[] k, const(ubyte)[] c, int h) {
  uint[16] w, x, y;
  uint[4] t;

  for (auto i = 0; i < 4; ++i) {
    x[5*i] = ld32(c[4*i..$]);
    x[1+i] = ld32(k[4*i..$]);
    x[6+i] = ld32(in_[4*i..$]);
    x[11+i] = ld32(k[16+4*i..$]);
  }

  for (auto i = 0; i < 16; ++i) y[i] = x[i];

  for (auto i = 0; i < 20; ++i) {
    for (auto j = 0; j < 4; ++j) {
      for (auto m = 0; m < 4; ++m) t[m] = x[(5*j+4*m)%16];
      t[1] ^= L32(t[0]+t[3], 7);
      t[2] ^= L32(t[1]+t[0], 9);
      t[3] ^= L32(t[2]+t[1], 13);
      t[0] ^= L32(t[3]+t[2], 18);
      for (auto m = 0; m < 4; ++m) w[4*j+(j+m)%4] = t[m];
    }
    for (auto m = 0; m < 16; ++m) x[m] = w[m];
  }

  if (h) {
    for (auto i = 0; i < 16; ++i) x[i] += y[i];
    for (auto i = 0; i < 4; ++i) {
      x[5*i] -= ld32(c[4*i..$]);
      x[6+i] -= ld32(in_[4*i..$]);
    }
    for (auto i = 0; i < 4; ++i) {
      st32(out_[4*i..$], x[5*i]);
      st32(out_[16+4*i..$], x[6+i]);
    }
  } else {
    for (auto i = 0; i < 16; ++i) st32(out_[4*i..$], x[i]+y[i]);
  }
}

@tweetNaCl_gdc_attribute("forceinline") void crypto_core_salsa20() (ubyte[] out_, const(ubyte)[] in_, const(ubyte)[] k, const(ubyte)[] c) {
  core(out_, in_, k, c, 0);
}

@tweetNaCl_gdc_attribute("forceinline") void crypto_core_hsalsa20() (ubyte[] out_, const(ubyte)[] in_, const(ubyte)[] k, const(ubyte)[] c) {
  core(out_, in_, k, c, 1);
}

private static immutable ubyte[16] sigma = ['e','x','p','a','n','d',' ','3','2','-','b','y','t','e',' ','k'];

/**
 * The crypto_stream_salsa20_xor() function encrypts a message 'm' using a secret key 'k'
 * and a nonce 'n'. The crypto_stream_salsa20_xor() function returns the ciphertext 'c'.
 *
 * Params:
 *  c = resulting ciphertext
 *  m = message
 *  n = nonce
 *  k = secret key
 *
 * Returns:
 *  ciphertext in 'c'
 */
void crypto_stream_salsa20_xor (ubyte[] c, const(ubyte)[] m, const(ubyte)[] n, const(ubyte)[] k) {
  assert(n.length == crypto_stream_salsa20_NONCEBYTES);
  assert(k.length == crypto_stream_salsa20_KEYBYTES);
  ubyte[16] z;
  ubyte[64] x;
  uint u;
  uint cpos = 0, mpos = 0;
  size_t b = c.length;
  if (!b) return;
  for (auto i = 0; i < 16; ++i) z[i] = 0; //FIXME
  for (auto i = 0; i < 8; ++i) z[i] = n[i];
  while (b >= 64) {
    crypto_core_salsa20(x, z, k, sigma);
    for (auto i = 0; i < 64; ++i) c[cpos+i] = (m !is null ? m[mpos+i] : 0)^x[i];
    u = 1;
    for (auto i = 8; i < 16; ++i) {
      u += cast(uint)z[i];
      z[i] = cast(ubyte)(u&0xff);
      u >>= 8;
    }
    b -= 64;
    cpos += 64;
    mpos += 64;
  }
  if (b) {
    crypto_core_salsa20(x, z, k, sigma);
    for (auto i = 0; i < b; ++i) c[cpos+i] = (m !is null ? m[mpos+i] : 0)^x[i];
  }
}

/**
 * The crypto_stream_salsa20() function produces a stream 'c'
 * as a function of a secret key 'k' and a nonce 'n'.
 *
 * Params:
 *  c = resulting stream
 *  n = nonce
 *  k = secret key
 *
 * Returns:
 *  ciphertext in 'c'
 */
void crypto_stream_salsa20() (ubyte[] c, const(ubyte)[] n, const(ubyte)[] k) {
  assert(n.length == crypto_stream_salsa20_NONCEBYTES);
  assert(k.length == crypto_stream_salsa20_KEYBYTES);
  crypto_stream_salsa20_xor(c, null, n, k);
}

/**
 * The crypto_stream() function produces a stream 'c'
 * as a function of a secret key 'k' and a nonce 'n'.
 *
 * Params:
 *  c = output slice
 *  n = nonce
 *  k = secret key
 *
 * Returns:
 *  stream in 'c'
 */
void crypto_stream() (ubyte[] c, const(ubyte)[] n, const(ubyte)[] k) {
  assert(c !is null);
  assert(n.length == crypto_stream_NONCEBYTES);
  assert(k.length == crypto_stream_KEYBYTES);
  ubyte[32] s;
  crypto_core_hsalsa20(s, n, k, sigma);
  crypto_stream_salsa20(c, n[16..$], s);
}

/**
 * The crypto_stream_xor() function encrypts a message 'm' using a secret key 'k'
 * and a nonce 'n'. The crypto_stream_xor() function returns the ciphertext 'c'.
 *
 * Params:
 *  c = output slice
 *  n = nonce
 *  k = secret key
 *
 * Returns:
 *  ciphertext in 'c'
 */
void crypto_stream_xor() (ubyte[] c, const(ubyte)[] m, const(ubyte)[] n, const(ubyte)[] k) {
  assert(c !is null);
  assert(m.length >= c.length);
  assert(n.length == crypto_stream_NONCEBYTES);
  assert(k.length == crypto_stream_KEYBYTES);
  ubyte s[32];
  crypto_core_hsalsa20(s, n, k, sigma);
  crypto_stream_salsa20_xor(c, m, n[16..$], s);
}

private @tweetNaCl_gdc_attribute("forceinline") void add1305() (uint[] h, const(uint)[] c) {
  uint u = 0;
  for (auto j = 0; j < 17; ++j) {
    u += h[j]+c[j];
    h[j] = u&255;
    u >>= 8;
  }
}

private static immutable uint[17] minusp = [5,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,252];

/**
 * The crypto_onetimeauth() function authenticates a message 'm'
 * using a secret key 'k'. The function returns an authenticator 'out_'.
 *
 * Params:
 *  out_ = authenticator, slice size must be at least crypto_onetimeauth_BYTES, extra ignored
 *  m == message
 *  k == secret key, slice size must be at least crypto_onetimeauth_KEYBYTES, extra ignored
 *
 * Returns:
 *  authenticator in 'out_'
 */
void crypto_onetimeauth() (ubyte[] out_, const(ubyte)[] m, const(ubyte)[] k) {
  assert(k.length >= crypto_onetimeauth_KEYBYTES);
  assert(out_.length >= crypto_onetimeauth_BYTES);
  uint s, i, j, u;
  uint[17] x, r, h, c, g;
  uint mpos = 0;
  size_t n = m.length;

  for (j = 0; j < 17; ++j) r[j] = h[j] = 0;
  for (j = 0; j < 16; ++j) r[j] = k[j];
  r[3]&=15;
  r[4]&=252;
  r[7]&=15;
  r[8]&=252;
  r[11]&=15;
  r[12]&=252;
  r[15]&=15;

  while (n > 0) {
    for (j = 0; j < 17; ++j) c[j] = 0;
    for (j = 0; j < 16 && j < n; ++j) c[j] = m[mpos+j];
    c[j] = 1;
    mpos += j;
    n -= j;
    add1305(h, c);
    for (i = 0; i < 17; ++i) {
      x[i] = 0;
      for (j = 0; j < 17; ++j) x[i] += h[j]*(j <= i ? r[i-j] : 320*r[i+17-j]);
    }
    for (i = 0; i < 17; ++i) h[i] = x[i];
    u = 0;
    for (j = 0; j < 16; ++j) {
      u += h[j];
      h[j] = u&255;
      u >>= 8;
    }
    u += h[16];
    h[16] = u&3;
    u = 5*(u>>2);
    for (j = 0; j < 16; ++j) {
      u += h[j];
      h[j] = u&255;
      u >>= 8;
    }
    u += h[16]; h[16] = u;
  }

  for (j = 0; j < 17; ++j) g[j] = h[j];
  add1305(h, minusp);
  s = -(h[16]>>7);
  for (j = 0; j < 17; ++j) h[j] ^= s&(g[j]^h[j]);

  for (j = 0; j < 16; ++j) c[j] = k[j+16];
  c[16] = 0;
  add1305(h, c);
  for (j = 0; j < 16; ++j) out_[j] = cast(ubyte)(h[j]&0xff);
}

/**
 * The crypto_onetimeauth_verify() function checks that
 * 'h' is a correct authenticator of a message 'm' under the secret key 'k'.
 *
 * Params:
 *  h = authenticator, slice size must be at least crypto_onetimeauth_BYTES, extra ignored
 *  m == message
 *  k == secret key, slice size must be at least crypto_onetimeauth_KEYBYTES, extra ignored
 *
 * Returns:
 *  success flag
 */
bool crypto_onetimeauth_verify() (const(ubyte)[] h, const(ubyte)[] m, const(ubyte)[] k) {
  assert(h.length >= crypto_onetimeauth_BYTES);
  assert(k.length >= crypto_onetimeauth_KEYBYTES);
  ubyte x[16];
  crypto_onetimeauth(x, m, k);
  return crypto_verify_16(h, x);
}

/**
 * The crypto_secretbox() function encrypts and authenticates
 * a message 'm' using a secret key 'k' and a nonce 'n'.
 * The crypto_secretbox() function returns the resulting ciphertext 'c'.
 *
 * Params:
 *  c = resulting cyphertext
 *  k = secret key
 *  n = nonce
 *
 * Returns:
 *  success flag and cyphertext in 'c'
 */
bool crypto_secretbox() (ubyte[] c, const(ubyte)[] m, const(ubyte)[] n, const(ubyte)[] k) {
  assert(k.length >= crypto_secretbox_KEYBYTES);
  assert(n.length >= crypto_secretbox_NONCEBYTES);
  //c.length = m.length+crypto_secretbox_ZEROBYTES;
  if (c is null || c.length < 32) return false;
  //assert(m.length >= c.length);
  crypto_stream_xor(c, m, n, k);
  crypto_onetimeauth(c[16..$], c[32..$], c);
  for (auto i = 0; i < 16; ++i) c[i] = 0;
  //return c[crypto_secretbox_BOXZEROBYTES..$];
  return true;
}

/**
 * The crypto_secretbox_open() function verifies and decrypts
 * a ciphertext 'c' using a secret key 'k' and a nonce 'n'.
 * The crypto_secretbox_open() function returns the resulting plaintext 'm'.
 *
 * Params:
 *  m = resulting message
 *  c = cyphertext
 *  k = secret key
 *  n = nonce
 *
 * Returns:
 *  success flag and message in 'm'
 */
bool crypto_secretbox_open() (ubyte[] m, const(ubyte)[] c, const(ubyte)[] n, const(ubyte)[] k) {
  assert(k.length >= crypto_secretbox_KEYBYTES);
  assert(n.length >= crypto_secretbox_NONCEBYTES);
  ubyte x[32];
  if (m is null || m.length < 32) return false;
  crypto_stream(x, n, k);
  if (!crypto_onetimeauth_verify(c[16..$], c[32../*$*/32+(m.length-32)], x)) return false;
  crypto_stream_xor(m, c, n, k);
  for (auto i = 0; i < 32; ++i) m[i] = 0;
  return true;
}

private @tweetNaCl_gdc_attribute("forceinline") void set25519() (long[/*16*/] r, const(long)[/*16*/] a) {
  for (auto i = 0; i < 16; ++i) r[i] = a[i];
}

private @tweetNaCl_gdc_attribute("forceinline") void car25519() (long[] o) {
  long c;
  for (auto i = 0; i < 16; ++i) {
    o[i]+=(1<<16);
    c = o[i]>>16;
    o[(i+1)*(i<15)]+=c-1+37*(c-1)*(i==15);
    o[i]-=c<<16;
  }
}

private @tweetNaCl_gdc_attribute("forceinline") void sel25519() (long[] p,long[] q, int b) {
  long t, c = ~(b-1);
  for (auto i = 0; i < 16; ++i) {
    t= c&(p[i]^q[i]);
    p[i]^=t;
    q[i]^=t;
  }
}

private @tweetNaCl_gdc_attribute("forceinline") void pack25519() (ubyte[] o, const(long)[] n) {
  int b;
  long[16] m, t;
  for (auto i = 0; i < 16; ++i) t[i] = n[i];
  car25519(t);
  car25519(t);
  car25519(t);
  for (auto j = 0; j < 2; ++j) {
    m[0] = t[0]-0xffed;
    for(auto i = 1; i < 15; ++i) {
      m[i] = t[i]-0xffff-((m[i-1]>>16)&1);
      m[i-1]&=0xffff;
    }
    m[15] = t[15]-0x7fff-((m[14]>>16)&1);
    b = (m[15]>>16)&1;
    m[14]&=0xffff;
    sel25519(t, m, 1-b);
  }
  for (auto i = 0; i < 16; ++i) {
    o[2*i] = t[i]&0xff;
    o[2*i+1] = (t[i]>>8)&0xff;
  }
}

private @tweetNaCl_gdc_attribute("forceinline") bool neq25519() (const(long)[] a, const(long)[] b) {
  ubyte[32] c, d;
  pack25519(c, a);
  pack25519(d, b);
  return crypto_verify_32(c, d);
}

private @tweetNaCl_gdc_attribute("forceinline") ubyte par25519() (const(long)[] a) {
  ubyte d[32];
  pack25519(d, a);
  return d[0]&1;
}

private @tweetNaCl_gdc_attribute("forceinline") void unpack25519() (long[] o, const(ubyte)[] n) {
  for (auto i = 0; i < 16; ++i) o[i] = n[2*i]+(cast(long)n[2*i+1]<<8);
  o[15]&=0x7fff;
}

private @tweetNaCl_gdc_attribute("forceinline") void A() (long[] o, const(long)[] a, const(long)[] b) {
  for (auto i = 0; i < 16; ++i) o[i] = a[i]+b[i];
}

private @tweetNaCl_gdc_attribute("forceinline") void Z() (long[] o, const(long)[] a, const(long)[] b) {
  for (auto i = 0; i < 16; ++i) o[i] = a[i]-b[i];
}

private @tweetNaCl_gdc_attribute("forceinline") void M() (long[] o, const(long)[] a, const(long)[] b) {
  long[31] t;
  for (auto i = 0; i < 31; ++i) t[i] = 0;
  for (auto i = 0; i < 16; ++i) for (auto j = 0; j < 16; ++j) t[i+j]+=a[i]*b[j];
  for (auto i = 0; i < 15; ++i) t[i]+=38*t[i+16];
  for (auto i = 0; i < 16; ++i) o[i] = t[i];
  car25519(o);
  car25519(o);
}

private @tweetNaCl_gdc_attribute("forceinline") void S() (long[] o, const(long)[] a) {
  M(o, a, a);
}

private @tweetNaCl_gdc_attribute("forceinline") void inv25519() (long[] o, const(long)[] i) {
  long[16] c;
  for (auto a = 0; a < 16; ++a) c[a] = i[a];
  for(auto a = 253; a >= 0; --a) {
    S(c, c);
    if (a !=2 && a != 4) M(c, c, i);
  }
  for (auto a = 0; a < 16; ++a) o[a] = c[a];
}

private @tweetNaCl_gdc_attribute("forceinline") void pow2523() (long[] o, const(long)[] i) {
  long[16] c;
  for (auto a = 0; a < 16; ++a) c[a] = i[a];
  for(auto a = 250; a >= 0; --a) {
    S(c, c);
    if (a != 1) M(c, c, i);
  }
  for (auto a = 0; a < 16; ++a) o[a] = c[a];
}

/* FIXME!
 * This function multiplies a group element 'p' by an integer 'n'.
 *
 * Params:
 *  p = group element
 *  n = number
 *
 * Returns:
 *  resulting group element 'q' of length crypto_scalarmult_BYTES.
 */
void crypto_scalarmult (ubyte[] q, const(ubyte)[] n, const(ubyte)[] p) {
  assert(q.length == crypto_scalarmult_BYTES);
  assert(n.length == crypto_scalarmult_BYTES);
  assert(p.length == crypto_scalarmult_BYTES);
  int i;
  ubyte z[32];
  long[80] x;
  long r;
  long[16] a, b, c, d, e, f;
  for (i = 0; i < 31; ++i) z[i] = n[i];
  z[31] = (n[31]&127)|64;
  z[0]&=248;
  unpack25519(x, p);
  for (i = 0; i < 16; ++i) {
    b[i] = x[i];
    d[i] = a[i] = c[i] = 0;
  }
  a[0] = d[0] = 1;
  for (i = 254; i >= 0; --i) {
    r = (z[i>>3]>>(i&7))&1;
    sel25519(a, b, cast(int)r);
    sel25519(c, d, cast(int)r);
    A(e, a, c);
    Z(a, a, c);
    A(c, b, d);
    Z(b, b, d);
    S(d, e);
    S(f, a);
    M(a, c, a);
    M(c, b, e);
    A(e, a, c);
    Z(a, a, c);
    S(b, a);
    Z(c, d, f);
    M(a, c, _121665);
    A(a, a, d);
    M(c, c, a);
    M(a, d, f);
    M(d, b, x);
    S(b, e);
    sel25519(a, b, cast(int)r);
    sel25519(c, d, cast(int)r);
  }
  for (i = 0; i < 16; ++i) {
    x[i+16] = a[i];
    x[i+32] = c[i];
    x[i+48] = b[i];
    x[i+64] = d[i];
  }
  inv25519(x[32..$], x[32..$]);
  M(x[16..$], x[16..$], x[32..$]);
  pack25519(q, x[16..$]);
}

/* FIXME!
 * The crypto_scalarmult_base() function computes
 * the scalar product of a standard group element and an integer 'n'.
 *
 * Params:
 *  n = number
 *
 * Returns:
 *  resulting group element 'q' of length crypto_scalarmult_BYTES.
 */
void crypto_scalarmult_base() (ubyte[] q, const(ubyte)[] n) {
  assert(q.length == crypto_scalarmult_BYTES);
  assert(n.length == crypto_scalarmult_SCALARBYTES);
  crypto_scalarmult(q, n, _9);
}

/**
 * The crypto_box_keypair() function randomly generates a secret key and
 * a corresponding public key.
 *
 * Params:
 *  pk = slice to put generated public key into
 *  sk = slice to put generated secret key into
 *
 * Returns:
 *  pair of new keys
 */
void crypto_box_keypair() (ubyte[] pk, ubyte[] sk) {
  assert(pk.length >= crypto_box_PUBLICKEYBYTES);
  assert(sk.length >= crypto_box_SECRETKEYBYTES);
  randombytes(sk, 32);
  crypto_scalarmult_base(pk, sk);
}

/**
 * Function crypto_box_beforenm() computes a shared secret 's' from
 * public key 'pk' and secret key 'sk'.
 *
 * Params:
 *  k = slice to put secret into
 *  pk = public
 *  sk = secret
 *
 * Returns:
 *  generated secret
 */
void crypto_box_beforenm() (ubyte[] k, const(ubyte)[] pk, const(ubyte)[] sk) {
  assert(pk.length >= crypto_box_PUBLICKEYBYTES);
  assert(sk.length >= crypto_box_SECRETKEYBYTES);
  assert(k.length >= crypto_box_BEFORENMBYTES);
  ubyte s[32];
  crypto_scalarmult(s, sk, pk);
  crypto_core_hsalsa20(k, _0, s, sigma);
}

/**
 * The crypto_box_afternm() function encrypts and authenticates
 * a message 'm' using a secret key 'k' and a nonce 'n'.
 * The crypto_box_afternm() function returns the resulting ciphertext 'c'.
 *
 * Params:
 *  c = resulting cyphertext
 *  m = message
 *  n = nonce
 *  k = secret
 *
 * Returns:
 *  success flag and cyphertext in 'c'
 */
bool crypto_box_afternm() (ubyte[] c, const(ubyte)[] m, const(ubyte)[] n, const(ubyte)[] k) {
  assert(n.length >= crypto_box_NONCEBYTES);
  assert(k.length >= crypto_box_BEFORENMBYTES);
  return crypto_secretbox(c, m, n, k);
}

/**
 * The crypto_box_open_afternm() function verifies and decrypts
 * a ciphertext 'c' using a secret key 'k' and a nonce 'n'.
 * The crypto_box_open_afternm() function returns the resulting message 'm'.
 *
 * Params:
 *  m = resulting message
 *  c = cyphertext
 *  n = nonce
 *  k = secret
 *
 * Returns:
 *  success flag and resulting message in 'm'
 */
bool crypto_box_open_afternm() (ubyte[] m, const(ubyte)[] c, const(ubyte)[] n, const(ubyte)[] k) {
  assert(n.length >= crypto_box_NONCEBYTES);
  assert(k.length >= crypto_box_BEFORENMBYTES);
  return crypto_secretbox_open(m, c, n, k);
}

/**
 * The crypto_box() function encrypts and authenticates a message 'm'
 * using the sender's secret key 'sk', the receiver's public key 'pk',
 * and a nonce 'n'. The crypto_box() function returns the resulting ciphertext 'c'.
 *
 * Params:
 *  c = resulting cyphertext
 *  m = message
 *  n = nonce
 *  pk = receiver's public key
 *  sk = sender's secret key
 *
 * Returns:
 *  success flag and cyphertext in 'c'
 */
bool crypto_box() (ubyte[] c, const(ubyte)[] m, const(ubyte)[] n, const(ubyte)[] pk, const(ubyte)[] sk) {
  assert(n.length >= crypto_box_NONCEBYTES);
  assert(pk.length >= crypto_box_PUBLICKEYBYTES);
  assert(sk.length >= crypto_box_SECRETKEYBYTES);
  ubyte k[32];
  crypto_box_beforenm(k, pk, sk);
  return crypto_box_afternm(c, m, n, k);
}

/**
 * The crypto_box_open() function verifies and decrypts
 * a ciphertext 'c' using the receiver's secret key 'sk',
 * the sender's public key 'pk', and a nonce 'n'.
 * The crypto_box_open() function returns the resulting message 'm'.
 *
 * Params:
 *  m = resulting message
 *  c = cyphertext
 *  n = nonce
 *  pk = receiver's public key
 *  sk = sender's secret key
 *
 * Returns:
 *  success flag and message in 'm'
 */
bool crypto_box_open() (ubyte[] m, const(ubyte)[] c, const(ubyte)[] n, const(ubyte)[] pk, const(ubyte)[] sk) {
  assert(n.length >= crypto_box_NONCEBYTES);
  assert(pk.length >= crypto_box_PUBLICKEYBYTES);
  assert(sk.length >= crypto_box_SECRETKEYBYTES);
  ubyte k[32];
  crypto_box_beforenm(k, pk, sk);
  return crypto_box_open_afternm(m, c, n, k);
}

private @tweetNaCl_gdc_attribute("forceinline") ulong R() (ulong x, int c) { return (x>>c)|(x<<(64-c)); }
private @tweetNaCl_gdc_attribute("forceinline") ulong Ch() (ulong x, ulong y, ulong z) { return (x&y)^(~x&z); }
private @tweetNaCl_gdc_attribute("forceinline") ulong Maj() (ulong x, ulong y, ulong z) { return (x&y)^(x&z)^(y&z); }
private @tweetNaCl_gdc_attribute("forceinline") ulong Sigma0() (ulong x) { return R(x, 28)^R(x, 34)^R(x, 39); }
private @tweetNaCl_gdc_attribute("forceinline") ulong Sigma1() (ulong x) { return R(x, 14)^R(x, 18)^R(x, 41); }
private @tweetNaCl_gdc_attribute("forceinline") ulong sigma0() (ulong x) { return R(x, 1)^R(x, 8)^(x>>7); }
private @tweetNaCl_gdc_attribute("forceinline") ulong sigma1() (ulong x) { return R(x, 19)^R(x, 61)^(x>>6); }

private static immutable ulong[80] K = [
  0x428a2f98d728ae22UL, 0x7137449123ef65cdUL, 0xb5c0fbcfec4d3b2fUL, 0xe9b5dba58189dbbcUL,
  0x3956c25bf348b538UL, 0x59f111f1b605d019UL, 0x923f82a4af194f9bUL, 0xab1c5ed5da6d8118UL,
  0xd807aa98a3030242UL, 0x12835b0145706fbeUL, 0x243185be4ee4b28cUL, 0x550c7dc3d5ffb4e2UL,
  0x72be5d74f27b896fUL, 0x80deb1fe3b1696b1UL, 0x9bdc06a725c71235UL, 0xc19bf174cf692694UL,
  0xe49b69c19ef14ad2UL, 0xefbe4786384f25e3UL, 0x0fc19dc68b8cd5b5UL, 0x240ca1cc77ac9c65UL,
  0x2de92c6f592b0275UL, 0x4a7484aa6ea6e483UL, 0x5cb0a9dcbd41fbd4UL, 0x76f988da831153b5UL,
  0x983e5152ee66dfabUL, 0xa831c66d2db43210UL, 0xb00327c898fb213fUL, 0xbf597fc7beef0ee4UL,
  0xc6e00bf33da88fc2UL, 0xd5a79147930aa725UL, 0x06ca6351e003826fUL, 0x142929670a0e6e70UL,
  0x27b70a8546d22ffcUL, 0x2e1b21385c26c926UL, 0x4d2c6dfc5ac42aedUL, 0x53380d139d95b3dfUL,
  0x650a73548baf63deUL, 0x766a0abb3c77b2a8UL, 0x81c2c92e47edaee6UL, 0x92722c851482353bUL,
  0xa2bfe8a14cf10364UL, 0xa81a664bbc423001UL, 0xc24b8b70d0f89791UL, 0xc76c51a30654be30UL,
  0xd192e819d6ef5218UL, 0xd69906245565a910UL, 0xf40e35855771202aUL, 0x106aa07032bbd1b8UL,
  0x19a4c116b8d2d0c8UL, 0x1e376c085141ab53UL, 0x2748774cdf8eeb99UL, 0x34b0bcb5e19b48a8UL,
  0x391c0cb3c5c95a63UL, 0x4ed8aa4ae3418acbUL, 0x5b9cca4f7763e373UL, 0x682e6ff3d6b2b8a3UL,
  0x748f82ee5defb2fcUL, 0x78a5636f43172f60UL, 0x84c87814a1f0ab72UL, 0x8cc702081a6439ecUL,
  0x90befffa23631e28UL, 0xa4506cebde82bde9UL, 0xbef9a3f7b2c67915UL, 0xc67178f2e372532bUL,
  0xca273eceea26619cUL, 0xd186b8c721c0c207UL, 0xeada7dd6cde0eb1eUL, 0xf57d4f7fee6ed178UL,
  0x06f067aa72176fbaUL, 0x0a637dc5a2c898a6UL, 0x113f9804bef90daeUL, 0x1b710b35131c471bUL,
  0x28db77f523047d84UL, 0x32caab7b40c72493UL, 0x3c9ebe0a15c9bebcUL, 0x431d67c49c100d4cUL,
  0x4cc5d4becb3e42b6UL, 0x597f299cfc657e2aUL, 0x5fcb6fab3ad6faecUL, 0x6c44198c4a475817UL
];

private void crypto_hashblocks (ubyte[] x, const(ubyte)[] m, ulong n) {
  ulong[8] z, b, a;
  ulong[16] w;
  ulong t;
  uint mpos = 0;

  for (auto i = 0; i < 8; ++i) z[i] = a[i] = dl64(x[8*i..$]);

  while (n >= 128) {
    for (auto i = 0; i < 16; ++i) w[i] = dl64(m[mpos+8*i..$]);

    for (auto i = 0; i < 80; ++i) {
      for (auto j = 0; j < 8; ++j) b[j] = a[j];
      t = a[7]+Sigma1(a[4])+Ch(a[4], a[5], a[6])+K[i]+w[i%16];
      b[7] = t+Sigma0(a[0])+Maj(a[0], a[1], a[2]);
      b[3] += t;
      for (auto j = 0; j < 8; ++j) a[(j+1)%8] = b[j];
      if (i%16 == 15) {
        for (auto j = 0; j < 16; ++j) w[j] += w[(j+9)%16]+sigma0(w[(j+1)%16])+sigma1(w[(j+14)%16]);
      }
    }

    for (auto i = 0; i < 8; ++i) { a[i] += z[i]; z[i] = a[i]; }

    mpos += 128;
    n -= 128;
  }

  for (auto i = 0; i < 8; ++i) ts64(x[8*i..$], z[i]);

  //return cast(int)n;
}

private static immutable ubyte[64] iv = [
  0x6a, 0x09, 0xe6, 0x67, 0xf3, 0xbc, 0xc9, 0x08,
  0xbb, 0x67, 0xae, 0x85, 0x84, 0xca, 0xa7, 0x3b,
  0x3c, 0x6e, 0xf3, 0x72, 0xfe, 0x94, 0xf8, 0x2b,
  0xa5, 0x4f, 0xf5, 0x3a, 0x5f, 0x1d, 0x36, 0xf1,
  0x51, 0x0e, 0x52, 0x7f, 0xad, 0xe6, 0x82, 0xd1,
  0x9b, 0x05, 0x68, 0x8c, 0x2b, 0x3e, 0x6c, 0x1f,
  0x1f, 0x83, 0xd9, 0xab, 0xfb, 0x41, 0xbd, 0x6b,
  0x5b, 0xe0, 0xcd, 0x19, 0x13, 0x7e, 0x21, 0x79
];

/**
 * The crypto_hash() function hashes a message 'm'.
 * It returns a hash 'out_'. The output length of 'out_' should be at least crypto_hash_BYTES.
 *
 * Params:
 *  out_ = resulting hash
 *  m = message
 *
 * Returns:
 *  sha512 hash
 */
void crypto_hash() (ubyte[] out_, const(ubyte)[] m) {
  assert(out_.length >= crypto_hash_BYTES);
  ubyte[64] h;
  ubyte[256] x;
  size_t n = m.length;
  ulong b = n;
  uint mpos = 0;

  for (auto i = 0; i < 64; ++i) h[i] = iv[i];

  crypto_hashblocks(h, m, n);
  mpos += n;
  n &= 127;
  mpos -= n;

  for (auto i = 0; i < 256; ++i) x[i] = 0;
  for (auto i = 0; i < n; ++i) x[i] = m[mpos+i];
  x[cast(uint)n] = 128;

  n = 256-128*(n<112);
  x[cast(uint)(n-9)] = b>>61;
  ts64(x[cast(uint)(n-8)..$], b<<3);
  crypto_hashblocks(h, x, n);

  for (auto i = 0; i < 64; ++i) out_[i] = h[i];
}

private @tweetNaCl_gdc_attribute("forceinline") void add() (ref long[16][4] p, ref long[16][4] q) {
  long[16] a, b, c, d, t, e, f, g, h;

  Z(a, p[1], p[0]);
  Z(t, q[1], q[0]);
  M(a, a, t);
  A(b, p[0], p[1]);
  A(t, q[0], q[1]);
  M(b, b, t);
  M(c, p[3], q[3]);
  M(c, c, D2);
  M(d, p[2], q[2]);
  A(d, d, d);
  Z(e, b, a);
  Z(f, d, c);
  A(g, d, c);
  A(h, b, a);

  M(p[0], e, f);
  M(p[1], h, g);
  M(p[2], g, f);
  M(p[3], e, h);
}

private @tweetNaCl_gdc_attribute("forceinline") void cswap() (ref long[16][4] p, ref long[16][4] q, ubyte b) {
  for (auto i = 0; i < 4; ++i) sel25519(p[i], q[i], b);
}

private @tweetNaCl_gdc_attribute("forceinline") void pack() (ubyte[] r, ref long[16][4] p) {
  long[16] tx, ty, zi;
  inv25519(zi, p[2]);
  M(tx, p[0], zi);
  M(ty, p[1], zi);
  pack25519(r, ty);
  r[31] ^= par25519(tx)<<7;
}

private @tweetNaCl_gdc_attribute("forceinline") void scalarmult() (ref long[16][4] p, ref long[16][4] q, const(ubyte)[] s) {
  set25519(p[0], gf0);
  set25519(p[1], gf1);
  set25519(p[2], gf1);
  set25519(p[3], gf0);
  for (auto i = 255; i >= 0; --i) {
    ubyte b = (s[i/8]>>(i&7))&1;
    cswap(p, q, b);
    add(q, p);
    add(p, p);
    cswap(p, q, b);
  }
}

private @tweetNaCl_gdc_attribute("forceinline") void scalarbase() (ref long[16][4] p, const(ubyte)[] s) {
  long[16][4] q;
  set25519(q[0], X);
  set25519(q[1], Y);
  set25519(q[2], gf1);
  M(q[3], X, Y);
  scalarmult(p, q, s);
}

/**
 * The crypto_sign_keypair() function randomly generates a secret key and
 * a corresponding public key.
 *
 * Params:
 *  pk = slice to put generated public key into
 *  sk = slice to put generated secret key into
 *
 * Returns:
 *  pair of new keys
 */
void crypto_sign_keypair() (ubyte[] pk, ubyte[] sk) {
  assert(pk.length >= crypto_sign_PUBLICKEYBYTES);
  assert(sk.length >= crypto_sign_SECRETKEYBYTES);
  ubyte d[64];
  long[16][4] p;

  randombytes(sk, 32);
  crypto_hash(d, sk[0..32]);
  d[0] &= 248;
  d[31] &= 127;
  d[31] |= 64;

  scalarbase(p, d);
  pack(pk, p);

  for (auto i = 0; i < 32; ++i) sk[32+i] = pk[i];
}

private static immutable ulong[32] L = [0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10];

private @tweetNaCl_gdc_attribute("forceinline") void modL() (ubyte[] r, long[] x) {
  long carry;
  for (auto i = 63; i >= 32; --i) {
    int j;
    carry = 0;
    for (j = i-32; j < i-12; ++j) {
      x[j] += carry-16*x[i]*L[j-(i-32)];
      carry = (x[j]+128)>>8;
      x[j] -= carry<<8;
    }
    x[j] += carry;
    x[i] = 0;
  }
  carry = 0;
  for (auto j = 0; j < 32; ++j) {
    x[j] += carry-(x[31]>>4)*L[j];
    carry = x[j]>>8;
    x[j] &= 255;
  }
  for (auto j = 0; j < 32; ++j) x[j] -= carry*L[j];
  for (auto i = 0; i < 32; ++i) {
    x[i+1] += x[i]>>8;
    r[i] = x[i]&255;
  }
}

private @tweetNaCl_gdc_attribute("forceinline") void reduce() (ubyte[] r) {
  long[64] x;
  for (auto i = 0; i < 64; ++i) x[i] = cast(ulong) r[i];
  for (auto i = 0; i < 64; ++i) r[i] = 0;
  modL(r, x);
}

/**
 * The crypto_sign() function signs a message 'm' using the sender's secret key 'sk'.
 * The crypto_sign() function returns the resulting signed message.
 *
 * Params:
 *  sm = buffer to receive signed message, must be of size at least m.length+64
 *  m == message
 *  sk == secret key, slice size must be at least crypto_sign_SECRETKEYBYTES, extra ignored
 *
 * Returns:
 *  signed message
 */
void crypto_sign() (ubyte[] sm, const(ubyte)[] m, const(ubyte)[] sk) {
  assert(sk.length >= crypto_sign_SECRETKEYBYTES);
  ubyte[64] d, h, r;
  ulong[64] x;
  long[16][4] p;
  size_t n = m.length;
  size_t smlen = n+64;
  assert(sm.length >= smlen);

  crypto_hash(d, sk[0..32]);
  d[0] &= 248;
  d[31] &= 127;
  d[31] |= 64;

  for (auto i = 0; i < n; ++i) sm[64+i] = m[i];
  for (auto i = 0; i < 32; ++i) sm[32+i] = d[32+i];

  crypto_hash(r, sm[32../*$*/32+n+32]/*, n+32*/);
  reduce(r);
  scalarbase(p, r);
  pack(sm, p);

  for (auto i = 0; i < 32; ++i) sm[i+32] = sk[i+32];
  crypto_hash(h, sm[0..n+64]);
  reduce(h);

  for (auto i = 0; i < 64; ++i) x[i] = 0;
  for (auto i = 0; i < 32; ++i) x[i] = cast(ulong)r[i];
  for (auto i = 0; i < 32; ++i) for (auto j = 0; j < 32; ++j) x[i+j] += h[i]*cast(ulong)d[j];
  modL(sm[32..$], cast(long[])x);
}

/**
 * The crypto_sign() function signs a message 'm' using the sender's secret key 'sk'.
 * The crypto_sign() function returns the resulting signed message.
 *
 * WARNING! This function allocates!
 *
 * Params:
 *  m == message
 *  sk == secret key, slice size must be at least crypto_sign_SECRETKEYBYTES, extra ignored
 *
 * Returns:
 *  signed message
 */
ubyte[] crypto_sign() (const(ubyte)[] m, const(ubyte)[] sk) {
  assert(sk.length >= crypto_sign_SECRETKEYBYTES);
  ubyte[] sm;
  size_t n = m.length;
  size_t smlen = n+64;
  sm.length = smlen;
  crypto_sign(sm, m, sk);
  return sm;
}

private @tweetNaCl_gdc_attribute("forceinline") bool unpackneg() (ref long[16][4] r, const(ubyte)[] p) {
  long[16] t, chk, num, den, den2, den4, den6;
  set25519(r[2], gf1);
  unpack25519(r[1], p);
  S(num, r[1]);
  M(den, num, D);
  Z(num, num, r[2]);
  A(den, r[2], den);

  S(den2, den);
  S(den4, den2);
  M(den6, den4, den2);
  M(t, den6, num);
  M(t, t, den);

  pow2523(t, t);
  M(t, t, num);
  M(t, t, den);
  M(t, t, den);
  M(r[0], t, den);

  S(chk, r[0]);
  M(chk, chk, den);
  if (!neq25519(chk, num)) M(r[0], r[0], I);

  S(chk, r[0]);
  M(chk, chk, den);
  if (!neq25519(chk, num)) return false;

  if (par25519(r[0]) == (p[31]>>7)) Z(r[0], gf0, r[0]);

  M(r[3], r[0], r[1]);
  return true;
}

/**
 * The crypto_sign_open() function verifies the signature in
 * 'sm' using the receiver's public key 'pk'.
 *
 * Params:
 *  m = decrypted message, last 64 bytes are useless zeroes, must be of size at least sm.length
 *  sm == signed message
 *  pk == public key, slice size must be at least crypto_sign_PUBLICKEYBYTES, extra ignored
 *
 * Returns:
 *  success flag
 */
bool crypto_sign_open() (ubyte[] m, const(ubyte)[] sm, const(ubyte)[] pk) {
  assert(pk.length >= crypto_sign_PUBLICKEYBYTES);
  ubyte[32] t;
  ubyte[64] h;
  long[16][4] p, q;
  size_t n = sm.length;
  assert(m.length >= n);

  if (n < 64) return false;

  if (!unpackneg(q, pk)) return false;
  for (auto i = 0; i < n; ++i) m[i] = sm[i];
  for (auto i = 0; i < 32; ++i) m[i+32] = pk[i];
  crypto_hash(h, m/*, n*/);
  reduce(h);
  scalarmult(p, q, h);

  scalarbase(q, sm[32..$]);
  add(p, q);
  pack(t, p);

  n -= 64;
  if (!crypto_verify_32(sm, t)) {
    for (auto i = 0; i < n; ++i) m[i] = 0;
    return false;
  }

  for (auto i = 0; i < n; ++i) m[i] = sm[i+64];
  for (auto i = n; i < n+64; ++i) m[i] = 0;

  return true;
}


/**
 * The crypto_sign_open() function verifies the signature in
 * 'sm' using the receiver's public key 'pk'.
 * The crypto_sign_open() function returns the message.
 *
 * WARNING! This function allocates!
 *
 * Params:
 *  sm == signed message
 *  pk == public key, slice size must be at least crypto_sign_PUBLICKEYBYTES, extra ignored
 *
 * Returns:
 *  decrypted message or null on error
 */
ubyte[] crypto_sign_open() (const(ubyte)[] sm, const(ubyte)[] pk) {
  ubyte[] m;
  m.length = sm.length;
  if (!crypto_sign_open(m, sm, pk)) return null;
  return m[0..sm.length-64]; // remove signature
}


unittest {
  import std.exception;
  import std.random;
  import std.range;
  import std.stdio;

  /+
  private extern(C) int open(const(char)* filename, int flags, ...);
  void randombytes (ubyte[] dest, size_t len) {
    import core.sys.posix.unistd;
    static int fd = -1;
    if (fd == -1) {
      for (;;) {
        fd = open("/dev/urandom", /*O_RDONLY*/0);
        if (fd != -1) break;
        sleep(1);
      }
    }
    size_t pos = 0;
    while (len > 0) {
      ssize_t i = read(fd, cast(void*)(&dest[pos]), (len < 1048576 ? len : 1048576));
      if (i < 1) {
        sleep(1);
        continue;
      }
      pos += i;
      len -= i;
    }
  }
  +/
  /+
  static void rnd (ubyte[] dest, size_t len) {
    for (size_t f = 0; f < len; ++f) dest[f] = cast(ubyte)uniform(0, 256);
  }
  randombytes = &rnd;
  +/

  randombytes = (ubyte[] dest, size_t len) {
    for (size_t f = 0; f < len; ++f) dest[f] = cast(ubyte)uniform(0, 256);
  };

  void dumpArray(T) (T[] arr) @trusted {
    writefln("============================= (%s)", arr.length);
    for (auto f = 0; f < arr.length; ++f) {
      if (f && f%16 == 0) writeln();
      static if (T.sizeof == 1) writef(" 0x%02x", arr[f]);
      else static if (T.sizeof == 2) writef(" 0x%04x", arr[f]);
      else static if (T.sizeof == 4) writef(" 0x%08x", arr[f]);
      else writef(" 0x%08x", arr[f]);
    }
    writeln();
    writeln("-----------------------------");
  }

  string hashToString (const(ubyte)[] hash) {
    char[] s;
    s.length = hash.length*2;
    char toHex(int a) { return cast(char)(a < 10 ? a+'0' : a+'a'-10); }
    for (int a = 0; a < hash.length; ++a) {
      s[a*2] = toHex(hash[a]>>4);
      s[a*2+1] = toHex(hash[a]&0x0f);
    }
    return assumeUnique(s);
  }

  static immutable ubyte[crypto_sign_PUBLICKEYBYTES] pk = [0x8f,0x58,0xd8,0xbf,0xb1,0x92,0xd1,0xd7,0xe0,0xc3,0x99,0x8a,0x8d,0x5c,0xb5,0xef,0xfc,0x92,0x2a,0x0d,0x70,0x80,0xe8,0x3b,0xe0,0x27,0xeb,0xf6,0x14,0x95,0xfd,0x16];
  static immutable ubyte[crypto_sign_SECRETKEYBYTES] sk = [0x78,0x34,0x09,0x59,0x54,0xaa,0xa9,0x2c,0x52,0x3a,0x41,0x3f,0xb6,0xfa,0x6b,0xe1,0xd7,0x0f,0x39,0x30,0x5a,0xe1,0x70,0x12,0x59,0x7d,0x32,0x59,0x9b,0x8b,0x6b,0x2f, 0x8f,0x58,0xd8,0xbf,0xb1,0x92,0xd1,0xd7,0xe0,0xc3,0x99,0x8a,0x8d,0x5c,0xb5,0xef,0xfc,0x92,0x2a,0x0d,0x70,0x80,0xe8,0x3b,0xe0,0x27,0xeb,0xf6,0x14,0x95,0xfd,0x16];
  static immutable ubyte[5] m = [0x61,0x68,0x6f,0x6a,0x0a];
  static immutable ubyte[69] sm = [0xce,0x1e,0x15,0xad,0xc3,0x17,0x47,0x15,0x7d,0x44,0x60,0xc1,0x7f,0xb8,0xba,0x45,0xf3,0x6d,0x0b,0xbf,0x51,0xf9,0xbb,0x6b,0xb9,0xa1,0xd2,0x4e,0x44,0x8d,0x9e,0x8c,0x36,0x6f,0x7a,0x8b,0x5e,0x2c,0x69,0xba,0x90,0x2e,0x95,0x46,0x19,0xd8,0xc1,0x8a,0x47,0xc5,0x6e,0x4a,0x28,0x9e,0x81,0x17,0xae,0x90,0x69,0x71,0x7d,0x84,0x6a,0x01,0x61,0x68,0x6f,0x6a,0x0a];
  ubyte[] smres, t;

  writeln("crypto_sign");
  smres = crypto_sign(m, sk);
  assert(smres.length == sm.length);
  assert(smres == sm);

  writeln("crypto_sign_open");
  t = crypto_sign_open(smres, pk);
  assert(t !is null);
  assert(t.length == m.length);
  assert(t == m);


  // based on the code by Adam D. Ruppe
  // This does the preprocessing of input data, fetching one byte at a time of the data until it is empty, then the padding and length at the end
  template SHARange(T) if (isInputRange!(T)) {
    struct SHARange {
      T r;

      bool empty () { return state == 5; }

      void popFront () {
        if (state == 0) {
          r.popFront;
          ++length; // FIXME
          if (r.empty) {
            state = 1;
            position = 2;
            current = 0x80;
          }
        } else {
          bool hackforward = false;
          if (state == 1) {
            current = 0x0;
            state = 2;
            if (((position+length+8)*8)%512 == 8) {
              --position;
              hackforward = true;
            }
            goto proceed;
            //++position;
          } else if (state == 2) {
          proceed:
            if (!(((position+length+8)*8)%512)) {
              state = 3;
              position = 7;
              length *= 8;
              if (hackforward) goto proceedmoar;
            } else {
              ++position;
            }
          } else if (state == 3) {
          proceedmoar:
            current = (length>>(position*8))&0xff;
            if (position == 0) state = 4; else --position;
          } else if (state == 4) {
            current = 0xff;
            state = 5;
          }
        }
      }

      ubyte front () {
        if (state == 0) return cast(ubyte)r.front();
        assert(state != 5);
        //writefln("%x", current);
        return current;
      }

      ubyte current;
      uint position;
      ulong length;
      int state = 0; // reading range, reading appended bit, reading padding, reading length, done
    }
  }


  immutable(ubyte)[] SHA256(T) (T data) if (isInputRange!(T)) {
    uint[8] h = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    static immutable(uint[64]) k = [
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];


    SHARange!(T) range;
    static if (is(data == SHARange)) range = data; else range.r = data;


    while(!range.empty) {
      uint[64] words;

      for(int a = 0; a < 16; ++a) {
        for(int b = 3; b >= 0; --b) {
          words[a] |= cast(uint)(range.front())<<(b*8);
          range.popFront;
        }
      }

      uint ror (uint n, int cnt) {
        return cast(uint)(n>>cnt)|cast(uint)(n<<(32-(cnt)));
      }

      uint xrot00 (uint reax, int r0, int r1, int r2) {
        uint rebx = reax, recx = reax;
        reax = ror(reax, r0);
        rebx = ror(rebx, r1);
        recx >>= r2;
        reax ^= rebx;
        reax ^= recx;
        return reax;
      }

      for(int a = 16; a < 64; ++a) {
        uint t1 = xrot00(words[a-15], 7, 18, 3);
        uint t2 = xrot00(words[a-2], 17, 19, 10);
        words[a] = words[a-16]+t1+words[a-7]+t2;
      }

      uint A = h[0];
      uint B = h[1];
      uint C = h[2];
      uint D = h[3];
      uint E = h[4];
      uint F = h[5];
      uint G = h[6];
      uint H = h[7];

      uint xrot01 (uint reax, int r0, int r1, int r2) {
        uint rebx = reax, recx = reax;
        reax = ror(reax, r0);
        rebx = ror(rebx, r1);
        recx = ror(recx, r2);
        reax ^= rebx;
        reax ^= recx;
        return reax;
      }

      for(int i = 0; i < 64; ++i) {
        uint s0 = xrot01(A, 2, 13, 22);
        uint maj = (A&B)^(A&C)^(B&C);
        uint t2 = s0+maj;
        uint s1 = xrot01(E, 6, 11, 25);
        uint ch = (E&F)^((~E)&G);
        uint t1 = H+s1+ch+k[i]+words[i];

        H = G;
        G = F;
        F = E;
        E = D+t1;
        D = C;
        C = B;
        B = A;
        A = t1+t2;
      }

      h[0] += A;
      h[1] += B;
      h[2] += C;
      h[3] += D;
      h[4] += E;
      h[5] += F;
      h[6] += G;
      h[7] += H;
    }

    ubyte[] hash;
    for(int j = 0; j < 8; ++j)
    for(int i = 3; i >= 0; --i) {
      hash ~= cast(ubyte)(h[j]>>(i*8))&0xff;
    }

    return hash.idup;
  }


  void box () {
    writeln("box");

    static immutable ubyte[32] alicesk = [
     0x77,0x07,0x6d,0x0a,0x73,0x18,0xa5,0x7d
    ,0x3c,0x16,0xc1,0x72,0x51,0xb2,0x66,0x45
    ,0xdf,0x4c,0x2f,0x87,0xeb,0xc0,0x99,0x2a
    ,0xb1,0x77,0xfb,0xa5,0x1d,0xb9,0x2c,0x2a
    ] ;

    static immutable ubyte[32] bobpk = [
     0xde,0x9e,0xdb,0x7d,0x7b,0x7d,0xc1,0xb4
    ,0xd3,0x5b,0x61,0xc2,0xec,0xe4,0x35,0x37
    ,0x3f,0x83,0x43,0xc8,0x5b,0x78,0x67,0x4d
    ,0xad,0xfc,0x7e,0x14,0x6f,0x88,0x2b,0x4f
    ] ;

    static immutable ubyte[24] nonce = [
     0x69,0x69,0x6e,0xe9,0x55,0xb6,0x2b,0x73
    ,0xcd,0x62,0xbd,0xa8,0x75,0xfc,0x73,0xd6
    ,0x82,0x19,0xe0,0x03,0x6b,0x7a,0x0b,0x37
    ] ;

    // API requires first 32 bytes to be 0
    static immutable ubyte[163] m = [
        0,   0,   0,   0,   0,   0,   0,   0
    ,   0,   0,   0,   0,   0,   0,   0,   0
    ,   0,   0,   0,   0,   0,   0,   0,   0
    ,   0,   0,   0,   0,   0,   0,   0,   0
    ,0xbe,0x07,0x5f,0xc5,0x3c,0x81,0xf2,0xd5
    ,0xcf,0x14,0x13,0x16,0xeb,0xeb,0x0c,0x7b
    ,0x52,0x28,0xc5,0x2a,0x4c,0x62,0xcb,0xd4
    ,0x4b,0x66,0x84,0x9b,0x64,0x24,0x4f,0xfc
    ,0xe5,0xec,0xba,0xaf,0x33,0xbd,0x75,0x1a
    ,0x1a,0xc7,0x28,0xd4,0x5e,0x6c,0x61,0x29
    ,0x6c,0xdc,0x3c,0x01,0x23,0x35,0x61,0xf4
    ,0x1d,0xb6,0x6c,0xce,0x31,0x4a,0xdb,0x31
    ,0x0e,0x3b,0xe8,0x25,0x0c,0x46,0xf0,0x6d
    ,0xce,0xea,0x3a,0x7f,0xa1,0x34,0x80,0x57
    ,0xe2,0xf6,0x55,0x6a,0xd6,0xb1,0x31,0x8a
    ,0x02,0x4a,0x83,0x8f,0x21,0xaf,0x1f,0xde
    ,0x04,0x89,0x77,0xeb,0x48,0xf5,0x9f,0xfd
    ,0x49,0x24,0xca,0x1c,0x60,0x90,0x2e,0x52
    ,0xf0,0xa0,0x89,0xbc,0x76,0x89,0x70,0x40
    ,0xe0,0x82,0xf9,0x37,0x76,0x38,0x48,0x64
    ,0x5e,0x07,0x05
    ] ;

    ubyte[163] c;


    static immutable ubyte[] res = [
     0xf3,0xff,0xc7,0x70,0x3f,0x94,0x00,0xe5
    ,0x2a,0x7d,0xfb,0x4b,0x3d,0x33,0x05,0xd9
    ,0x8e,0x99,0x3b,0x9f,0x48,0x68,0x12,0x73
    ,0xc2,0x96,0x50,0xba,0x32,0xfc,0x76,0xce
    ,0x48,0x33,0x2e,0xa7,0x16,0x4d,0x96,0xa4
    ,0x47,0x6f,0xb8,0xc5,0x31,0xa1,0x18,0x6a
    ,0xc0,0xdf,0xc1,0x7c,0x98,0xdc,0xe8,0x7b
    ,0x4d,0xa7,0xf0,0x11,0xec,0x48,0xc9,0x72
    ,0x71,0xd2,0xc2,0x0f,0x9b,0x92,0x8f,0xe2
    ,0x27,0x0d,0x6f,0xb8,0x63,0xd5,0x17,0x38
    ,0xb4,0x8e,0xee,0xe3,0x14,0xa7,0xcc,0x8a
    ,0xb9,0x32,0x16,0x45,0x48,0xe5,0x26,0xae
    ,0x90,0x22,0x43,0x68,0x51,0x7a,0xcf,0xea
    ,0xbd,0x6b,0xb3,0x73,0x2b,0xc0,0xe9,0xda
    ,0x99,0x83,0x2b,0x61,0xca,0x01,0xb6,0xde
    ,0x56,0x24,0x4a,0x9e,0x88,0xd5,0xf9,0xb3
    ,0x79,0x73,0xf6,0x22,0xa4,0x3d,0x14,0xa6
    ,0x59,0x9b,0x1f,0x65,0x4c,0xb4,0x5a,0x74
    ,0xe3,0x55,0xa5];
    /*crypto_box_curve25519xsalsa20poly1305*/crypto_box(c,m,nonce,bobpk,alicesk);
    for (auto f = 16; f < 163; ++f) assert(c[f] == res[f-16]);
  }
  box();

  void box2 () {
    writeln("box2");
    static immutable ubyte[32] bobsk = [
     0x5d,0xab,0x08,0x7e,0x62,0x4a,0x8a,0x4b
    ,0x79,0xe1,0x7f,0x8b,0x83,0x80,0x0e,0xe6
    ,0x6f,0x3b,0xb1,0x29,0x26,0x18,0xb6,0xfd
    ,0x1c,0x2f,0x8b,0x27,0xff,0x88,0xe0,0xeb
    ] ;

    static immutable ubyte[32] alicepk = [
     0x85,0x20,0xf0,0x09,0x89,0x30,0xa7,0x54
    ,0x74,0x8b,0x7d,0xdc,0xb4,0x3e,0xf7,0x5a
    ,0x0d,0xbf,0x3a,0x0d,0x26,0x38,0x1a,0xf4
    ,0xeb,0xa4,0xa9,0x8e,0xaa,0x9b,0x4e,0x6a
    ] ;

    static immutable ubyte[24] nonce = [
     0x69,0x69,0x6e,0xe9,0x55,0xb6,0x2b,0x73
    ,0xcd,0x62,0xbd,0xa8,0x75,0xfc,0x73,0xd6
    ,0x82,0x19,0xe0,0x03,0x6b,0x7a,0x0b,0x37
    ] ;

    // API requires first 16 bytes to be 0
    static immutable ubyte[163] c = [
        0,   0,   0,   0,   0,   0,   0,   0
    ,   0,   0,   0,   0,   0,   0,   0,   0
    ,0xf3,0xff,0xc7,0x70,0x3f,0x94,0x00,0xe5
    ,0x2a,0x7d,0xfb,0x4b,0x3d,0x33,0x05,0xd9
    ,0x8e,0x99,0x3b,0x9f,0x48,0x68,0x12,0x73
    ,0xc2,0x96,0x50,0xba,0x32,0xfc,0x76,0xce
    ,0x48,0x33,0x2e,0xa7,0x16,0x4d,0x96,0xa4
    ,0x47,0x6f,0xb8,0xc5,0x31,0xa1,0x18,0x6a
    ,0xc0,0xdf,0xc1,0x7c,0x98,0xdc,0xe8,0x7b
    ,0x4d,0xa7,0xf0,0x11,0xec,0x48,0xc9,0x72
    ,0x71,0xd2,0xc2,0x0f,0x9b,0x92,0x8f,0xe2
    ,0x27,0x0d,0x6f,0xb8,0x63,0xd5,0x17,0x38
    ,0xb4,0x8e,0xee,0xe3,0x14,0xa7,0xcc,0x8a
    ,0xb9,0x32,0x16,0x45,0x48,0xe5,0x26,0xae
    ,0x90,0x22,0x43,0x68,0x51,0x7a,0xcf,0xea
    ,0xbd,0x6b,0xb3,0x73,0x2b,0xc0,0xe9,0xda
    ,0x99,0x83,0x2b,0x61,0xca,0x01,0xb6,0xde
    ,0x56,0x24,0x4a,0x9e,0x88,0xd5,0xf9,0xb3
    ,0x79,0x73,0xf6,0x22,0xa4,0x3d,0x14,0xa6
    ,0x59,0x9b,0x1f,0x65,0x4c,0xb4,0x5a,0x74
    ,0xe3,0x55,0xa5
    ] ;

    ubyte m[163];

    static immutable ubyte[] res = [
     0xbe,0x07,0x5f,0xc5,0x3c,0x81,0xf2,0xd5
    ,0xcf,0x14,0x13,0x16,0xeb,0xeb,0x0c,0x7b
    ,0x52,0x28,0xc5,0x2a,0x4c,0x62,0xcb,0xd4
    ,0x4b,0x66,0x84,0x9b,0x64,0x24,0x4f,0xfc
    ,0xe5,0xec,0xba,0xaf,0x33,0xbd,0x75,0x1a
    ,0x1a,0xc7,0x28,0xd4,0x5e,0x6c,0x61,0x29
    ,0x6c,0xdc,0x3c,0x01,0x23,0x35,0x61,0xf4
    ,0x1d,0xb6,0x6c,0xce,0x31,0x4a,0xdb,0x31
    ,0x0e,0x3b,0xe8,0x25,0x0c,0x46,0xf0,0x6d
    ,0xce,0xea,0x3a,0x7f,0xa1,0x34,0x80,0x57
    ,0xe2,0xf6,0x55,0x6a,0xd6,0xb1,0x31,0x8a
    ,0x02,0x4a,0x83,0x8f,0x21,0xaf,0x1f,0xde
    ,0x04,0x89,0x77,0xeb,0x48,0xf5,0x9f,0xfd
    ,0x49,0x24,0xca,0x1c,0x60,0x90,0x2e,0x52
    ,0xf0,0xa0,0x89,0xbc,0x76,0x89,0x70,0x40
    ,0xe0,0x82,0xf9,0x37,0x76,0x38,0x48,0x64
    ,0x5e,0x07,0x05
    ];

    assert(/*crypto_box_curve25519xsalsa20poly1305_open*/crypto_box_open(m,c,nonce,alicepk,bobsk));
    for (auto f = 32; f < 163; ++f) assert(m[f] == res[f-32]);
  }
  box2();

  void box7 () {
    writeln("box7");
    ubyte[crypto_box_SECRETKEYBYTES] alicesk;
    ubyte[crypto_box_PUBLICKEYBYTES] alicepk;
    ubyte[crypto_box_SECRETKEYBYTES] bobsk;
    ubyte[crypto_box_PUBLICKEYBYTES] bobpk;
    ubyte[crypto_box_NONCEBYTES] n;
    ubyte[10000] m, c, m2;
    for (auto mlen = 0; mlen < 1000 && mlen+crypto_box_ZEROBYTES < m.length; ++mlen) {
      crypto_box_keypair(alicepk,alicesk);
      crypto_box_keypair(bobpk,bobsk);
      randombytes(n,crypto_box_NONCEBYTES);
      randombytes(m[crypto_box_ZEROBYTES..$],mlen);
      crypto_box(c[0..mlen+crypto_box_ZEROBYTES],m,n,bobpk,alicesk);
      assert(crypto_box_open(m2[0..mlen+crypto_box_ZEROBYTES],c,n,alicepk,bobsk));
      for (auto i = 0; i < mlen+crypto_box_ZEROBYTES; ++i) assert(m2[i] == m[i]);
    }
  }
  version(unittest_full) box7(); // it's slow

  void box8 () {
    writeln("box8");
    ubyte[crypto_box_SECRETKEYBYTES] alicesk;
    ubyte[crypto_box_PUBLICKEYBYTES] alicepk;
    ubyte[crypto_box_SECRETKEYBYTES] bobsk;
    ubyte[crypto_box_PUBLICKEYBYTES] bobpk;
    ubyte[crypto_box_NONCEBYTES] n;
    ubyte[10000] m, c, m2;
    for (auto mlen = 0; mlen < 1000 && mlen+crypto_box_ZEROBYTES < m.length; ++mlen) {
      crypto_box_keypair(alicepk,alicesk);
      crypto_box_keypair(bobpk,bobsk);
      randombytes(n,crypto_box_NONCEBYTES);
      randombytes(m[crypto_box_ZEROBYTES..$],mlen);
      crypto_box(c[0..mlen+crypto_box_ZEROBYTES],m,n,bobpk,alicesk);
      int caught = 0;
      while (caught < 10) {
        c[uniform(0, mlen+crypto_box_ZEROBYTES)] = cast(ubyte)uniform(0, 256);
        if (crypto_box_open(m2[0..mlen+crypto_box_ZEROBYTES],c,n,alicepk,bobsk)) {
          for (auto i = 0; i < mlen+crypto_box_ZEROBYTES; ++i) assert(m2[i] == m[i]);
        } else {
          ++caught;
        }
      }
      assert(caught == 10);
    }
  }
  version(unittest_full) box8(); // it's slow

  void core1 () {
    writeln("core1");
    static immutable ubyte[32] shared_ = [
     0x4a,0x5d,0x9d,0x5b,0xa4,0xce,0x2d,0xe1
    ,0x72,0x8e,0x3b,0xf4,0x80,0x35,0x0f,0x25
    ,0xe0,0x7e,0x21,0xc9,0x47,0xd1,0x9e,0x33
    ,0x76,0xf0,0x9b,0x3c,0x1e,0x16,0x17,0x42
    ] ;

    static immutable ubyte[32] zero = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];

    static immutable ubyte[16] c = [
     0x65,0x78,0x70,0x61,0x6e,0x64,0x20,0x33
    ,0x32,0x2d,0x62,0x79,0x74,0x65,0x20,0x6b
    ] ;

    ubyte[32] firstkey;

    static immutable ubyte[32] res = [
     0x1b,0x27,0x55,0x64,0x73,0xe9,0x85,0xd4
    ,0x62,0xcd,0x51,0x19,0x7a,0x9a,0x46,0xc7
    ,0x60,0x09,0x54,0x9e,0xac,0x64,0x74,0xf2
    ,0x06,0xc4,0xee,0x08,0x44,0xf6,0x83,0x89
    ];

    crypto_core_hsalsa20(firstkey,zero,shared_,c);
    assert(firstkey == res);
  }
  core1();

  void core2 () {
    writeln("core2");
    static immutable ubyte[32]firstkey = [
     0x1b,0x27,0x55,0x64,0x73,0xe9,0x85,0xd4
    ,0x62,0xcd,0x51,0x19,0x7a,0x9a,0x46,0xc7
    ,0x60,0x09,0x54,0x9e,0xac,0x64,0x74,0xf2
    ,0x06,0xc4,0xee,0x08,0x44,0xf6,0x83,0x89
    ] ;

    static immutable ubyte[16]nonceprefix = [
     0x69,0x69,0x6e,0xe9,0x55,0xb6,0x2b,0x73
    ,0xcd,0x62,0xbd,0xa8,0x75,0xfc,0x73,0xd6
    ] ;

    static immutable ubyte[16] c = [
     0x65,0x78,0x70,0x61,0x6e,0x64,0x20,0x33
    ,0x32,0x2d,0x62,0x79,0x74,0x65,0x20,0x6b
    ] ;

    ubyte[32] secondkey;

    static immutable ubyte[32] res = [
     0xdc,0x90,0x8d,0xda,0x0b,0x93,0x44,0xa9
    ,0x53,0x62,0x9b,0x73,0x38,0x20,0x77,0x88
    ,0x80,0xf3,0xce,0xb4,0x21,0xbb,0x61,0xb9
    ,0x1c,0xbd,0x4c,0x3e,0x66,0x25,0x6c,0xe4
    ];

    crypto_core_hsalsa20(secondkey,nonceprefix,firstkey,c);
    assert(secondkey == res);
  }
  core2();

  void core3 () {
    writeln("core3");
    static immutable ubyte[32] secondkey = [
     0xdc,0x90,0x8d,0xda,0x0b,0x93,0x44,0xa9
    ,0x53,0x62,0x9b,0x73,0x38,0x20,0x77,0x88
    ,0x80,0xf3,0xce,0xb4,0x21,0xbb,0x61,0xb9
    ,0x1c,0xbd,0x4c,0x3e,0x66,0x25,0x6c,0xe4
    ] ;

    static immutable ubyte[8] noncesuffix = [
     0x82,0x19,0xe0,0x03,0x6b,0x7a,0x0b,0x37
    ] ;

    static immutable ubyte[16] c = [
     0x65,0x78,0x70,0x61,0x6e,0x64,0x20,0x33
    ,0x32,0x2d,0x62,0x79,0x74,0x65,0x20,0x6b
    ] ;

    static ubyte[16] in_ = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0] ;

    static ubyte output[64*256*256];

    static ubyte[64] h;

    static immutable ubyte[64] res = [0x2b,0xd8,0xe7,0xdb,0x68,0x77,0x53,0x9e,0x4f,0x2b,0x29,0x5e,0xe4,0x15,0xcd,0x37,0x8a,0xe2,0x14,0xaa,0x3b,0xeb,0x3e,0x08,0xe9,0x11,0xa5,0xbd,0x4a,0x25,0xe6,0xac,0x16,0xca,0x28,0x3c,0x79,0xc3,0x4c,0x08,0xc9,0x9f,0x7b,0xdb,0x56,0x01,0x11,0xe8,0xca,0xc1,0xae,0x65,0xee,0xa0,0x8a,0xc3,0x84,0xd7,0xa5,0x91,0x46,0x1a,0xb6,0xe3];

    int pos = 0;
    for (auto i = 0; i < 8; ++i) in_[i] = noncesuffix[i];
    do {
      do {
        crypto_core_salsa20(output[pos..$],in_,secondkey,c);
        pos += 64;
      } while (++in_[8]);
    } while (++in_[9]);
    crypto_hash(h,output);
    assert(h == res);
  }
  version(unittest_full) core3(); // it's slow

  void core4 () {
    writeln("core4");
    static immutable ubyte[32] k = [
       1,  2,  3,  4,  5,  6,  7,  8
    ,  9, 10, 11, 12, 13, 14, 15, 16
    ,201,202,203,204,205,206,207,208
    ,209,210,211,212,213,214,215,216
    ] ;

    static immutable ubyte[16] in_ = [
     101,102,103,104,105,106,107,108
    ,109,110,111,112,113,114,115,116
    ] ;

    static immutable ubyte[16] c = [
     101,120,112, 97,110,100, 32, 51
    , 50, 45, 98,121,116,101, 32,107
    ] ;

    ubyte[64] out_;

    static immutable ubyte[64] res = [
      69, 37, 68, 39, 41, 15,107,193
    ,255,139,122,  6,170,233,217, 98
    , 89,144,182,106, 21, 51,200, 65
    ,239, 49,222, 34,215,114, 40,126
    ,104,197,  7,225,197,153, 31,  2
    ,102, 78, 76,176, 84,245,246,184
    ,177,160,133,130,  6, 72,149,119
    ,192,195,132,236,234,103,246, 74
    ];

    crypto_core_salsa20(out_,in_,k,c);
    assert(out_ == res);
  }
  core4();

  void core5 () {
    writeln("core5");
    static immutable ubyte[32] k = [
     0xee,0x30,0x4f,0xca,0x27,0x00,0x8d,0x8c
    ,0x12,0x6f,0x90,0x02,0x79,0x01,0xd8,0x0f
    ,0x7f,0x1d,0x8b,0x8d,0xc9,0x36,0xcf,0x3b
    ,0x9f,0x81,0x96,0x92,0x82,0x7e,0x57,0x77
    ] ;

    static immutable ubyte[16] in_ = [
     0x81,0x91,0x8e,0xf2,0xa5,0xe0,0xda,0x9b
    ,0x3e,0x90,0x60,0x52,0x1e,0x4b,0xb3,0x52
    ] ;

    static immutable ubyte[16] c = [
     101,120,112, 97,110,100, 32, 51
    , 50, 45, 98,121,116,101, 32,107
    ] ;

    ubyte out_[32];

    static immutable ubyte[32] res = [
     0xbc,0x1b,0x30,0xfc,0x07,0x2c,0xc1,0x40
    ,0x75,0xe4,0xba,0xa7,0x31,0xb5,0xa8,0x45
    ,0xea,0x9b,0x11,0xe9,0xa5,0x19,0x1f,0x94
    ,0xe1,0x8c,0xba,0x8f,0xd8,0x21,0xa7,0xcd
    ];

    crypto_core_hsalsa20(out_,in_,k,c);
    assert(out_ == res);
  }
  core5();

  void core6 () {
    writeln("core6");
    static immutable ubyte[32] k = [
     0xee,0x30,0x4f,0xca,0x27,0x00,0x8d,0x8c
    ,0x12,0x6f,0x90,0x02,0x79,0x01,0xd8,0x0f
    ,0x7f,0x1d,0x8b,0x8d,0xc9,0x36,0xcf,0x3b
    ,0x9f,0x81,0x96,0x92,0x82,0x7e,0x57,0x77
    ] ;

    static immutable ubyte[16] in_ = [
     0x81,0x91,0x8e,0xf2,0xa5,0xe0,0xda,0x9b
    ,0x3e,0x90,0x60,0x52,0x1e,0x4b,0xb3,0x52
    ] ;

    static immutable ubyte[16] c = [
     101,120,112, 97,110,100, 32, 51
    , 50, 45, 98,121,116,101, 32,107
    ] ;

    ubyte out_[64];

    static immutable ubyte[32] res = [
     0xbc,0x1b,0x30,0xfc,0x07,0x2c,0xc1,0x40
    ,0x75,0xe4,0xba,0xa7,0x31,0xb5,0xa8,0x45
    ,0xea,0x9b,0x11,0xe9,0xa5,0x19,0x1f,0x94
    ,0xe1,0x8c,0xba,0x8f,0xd8,0x21,0xa7,0xcd
    ];

    ubyte[32] pp;
    uint pppos = 0;

    void print(const(ubyte)[] x, const(ubyte)[] y)
    {
      uint borrow = 0;
      for (auto i = 0; i < 4; ++i) {
        uint xi = x[i];
        uint yi = y[i];
        //printf(",0x%02x",255&(xi-yi-borrow));
        pp[pppos++] = cast(ubyte)(255&(xi-yi-borrow));
        borrow = (xi < yi+borrow);
      }
    }

    crypto_core_salsa20(out_,in_,k,c);
    print(out_,c);
    print(out_[20..$],c[4..$]);
    print(out_[40..$],c[8..$]);
    print(out_[60..$],c[12..$]);
    print(out_[24..$],in_);
    print(out_[28..$],in_[4..$]);
    print(out_[32..$],in_[8..$]);
    print(out_[36..$],in_[12..$]);
    assert(pp == res);
  }
  core6();

  void hash () {
    writeln("hash");
    static immutable ubyte x[8] = ['t','e','s','t','i','n','g','\n'];
    static ubyte[crypto_hash_BYTES] h;
    static immutable ubyte[crypto_hash_BYTES] res = [0x24,0xf9,0x50,0xaa,0xc7,0xb9,0xea,0x9b,0x3c,0xb7,0x28,0x22,0x8a,0x0c,0x82,0xb6,0x7c,0x39,0xe9,0x6b,0x4b,0x34,0x47,0x98,0x87,0x0d,0x5d,0xae,0xe9,0x3e,0x3a,0xe5,0x93,0x1b,0xaa,0xe8,0xc7,0xca,0xcf,0xea,0x4b,0x62,0x94,0x52,0xc3,0x80,0x26,0xa8,0x1d,0x13,0x8b,0xc7,0xaa,0xd1,0xaf,0x3e,0xf7,0xbf,0xd5,0xec,0x64,0x6d,0x6c,0x28];
    crypto_hash(h,x);
    //for (auto f = 0; f < crypto_hash_BYTES; ++f) assert(h[f] == res[f]);
    assert(h == res);
  }
  hash();

  void onetimeauth () {
    writeln("onetimeauth");
    static immutable ubyte rs[32] = [
     0xee,0xa6,0xa7,0x25,0x1c,0x1e,0x72,0x91
    ,0x6d,0x11,0xc2,0xcb,0x21,0x4d,0x3c,0x25
    ,0x25,0x39,0x12,0x1d,0x8e,0x23,0x4e,0x65
    ,0x2d,0x65,0x1f,0xa4,0xc8,0xcf,0xf8,0x80
    ] ;

    static immutable ubyte c[131] = [
     0x8e,0x99,0x3b,0x9f,0x48,0x68,0x12,0x73
    ,0xc2,0x96,0x50,0xba,0x32,0xfc,0x76,0xce
    ,0x48,0x33,0x2e,0xa7,0x16,0x4d,0x96,0xa4
    ,0x47,0x6f,0xb8,0xc5,0x31,0xa1,0x18,0x6a
    ,0xc0,0xdf,0xc1,0x7c,0x98,0xdc,0xe8,0x7b
    ,0x4d,0xa7,0xf0,0x11,0xec,0x48,0xc9,0x72
    ,0x71,0xd2,0xc2,0x0f,0x9b,0x92,0x8f,0xe2
    ,0x27,0x0d,0x6f,0xb8,0x63,0xd5,0x17,0x38
    ,0xb4,0x8e,0xee,0xe3,0x14,0xa7,0xcc,0x8a
    ,0xb9,0x32,0x16,0x45,0x48,0xe5,0x26,0xae
    ,0x90,0x22,0x43,0x68,0x51,0x7a,0xcf,0xea
    ,0xbd,0x6b,0xb3,0x73,0x2b,0xc0,0xe9,0xda
    ,0x99,0x83,0x2b,0x61,0xca,0x01,0xb6,0xde
    ,0x56,0x24,0x4a,0x9e,0x88,0xd5,0xf9,0xb3
    ,0x79,0x73,0xf6,0x22,0xa4,0x3d,0x14,0xa6
    ,0x59,0x9b,0x1f,0x65,0x4c,0xb4,0x5a,0x74
    ,0xe3,0x55,0xa5
    ] ;

    ubyte a[16];

    static immutable ubyte[16] res = [0xf3,0xff,0xc7,0x70,0x3f,0x94,0x00,0xe5,0x2a,0x7d,0xfb,0x4b,0x3d,0x33,0x05,0xd9];

    /*crypto_onetimeauth_poly1305*/crypto_onetimeauth(a,c,rs);
    assert(a == res);
  }
  onetimeauth();

  void onetimeauth2 () {
    writeln("onetimeauth2");
    static immutable ubyte[32] rs = [
     0xee,0xa6,0xa7,0x25,0x1c,0x1e,0x72,0x91
    ,0x6d,0x11,0xc2,0xcb,0x21,0x4d,0x3c,0x25
    ,0x25,0x39,0x12,0x1d,0x8e,0x23,0x4e,0x65
    ,0x2d,0x65,0x1f,0xa4,0xc8,0xcf,0xf8,0x80
    ] ;

    static immutable ubyte[131] c = [
     0x8e,0x99,0x3b,0x9f,0x48,0x68,0x12,0x73
    ,0xc2,0x96,0x50,0xba,0x32,0xfc,0x76,0xce
    ,0x48,0x33,0x2e,0xa7,0x16,0x4d,0x96,0xa4
    ,0x47,0x6f,0xb8,0xc5,0x31,0xa1,0x18,0x6a
    ,0xc0,0xdf,0xc1,0x7c,0x98,0xdc,0xe8,0x7b
    ,0x4d,0xa7,0xf0,0x11,0xec,0x48,0xc9,0x72
    ,0x71,0xd2,0xc2,0x0f,0x9b,0x92,0x8f,0xe2
    ,0x27,0x0d,0x6f,0xb8,0x63,0xd5,0x17,0x38
    ,0xb4,0x8e,0xee,0xe3,0x14,0xa7,0xcc,0x8a
    ,0xb9,0x32,0x16,0x45,0x48,0xe5,0x26,0xae
    ,0x90,0x22,0x43,0x68,0x51,0x7a,0xcf,0xea
    ,0xbd,0x6b,0xb3,0x73,0x2b,0xc0,0xe9,0xda
    ,0x99,0x83,0x2b,0x61,0xca,0x01,0xb6,0xde
    ,0x56,0x24,0x4a,0x9e,0x88,0xd5,0xf9,0xb3
    ,0x79,0x73,0xf6,0x22,0xa4,0x3d,0x14,0xa6
    ,0x59,0x9b,0x1f,0x65,0x4c,0xb4,0x5a,0x74
    ,0xe3,0x55,0xa5
    ] ;

    static immutable ubyte[16] a = [
     0xf3,0xff,0xc7,0x70,0x3f,0x94,0x00,0xe5
    ,0x2a,0x7d,0xfb,0x4b,0x3d,0x33,0x05,0xd9
    ] ;

    assert(/*crypto_onetimeauth_poly1305_verify*/crypto_onetimeauth_verify(a,c,rs));
  }
  onetimeauth2();

  void onetimeauth7 () {
    writeln("onetimeauth7");
    static ubyte[32] key;
    static ubyte[10000] c;
    static ubyte[16] a;

    for (auto clen = 0; clen < 10000; ++clen) {
      //if (clen%512 == 0) { writef("\r%s", clen); stdout.flush(); }
      randombytes(key, key.length);
      randombytes(c, clen);
      crypto_onetimeauth(a,c[0..clen],key);
      assert(crypto_onetimeauth_verify(a,c[0..clen],key));
      if (clen > 0) {
        c[uniform(0, clen)] += 1+(uniform(0, 255));
        assert(!crypto_onetimeauth_verify(a,c[0..clen],key));
        a[uniform(0, a.length)] += 1+(uniform(0, 255));
        assert(!crypto_onetimeauth_verify(a,c[0..clen],key));
      }
    }
  }
  version(unittest_full) onetimeauth7(); // it's slow

  void scalarmult () {
    writeln("scalarmult");
    static immutable ubyte[32] alicesk = [
     0x77,0x07,0x6d,0x0a,0x73,0x18,0xa5,0x7d
    ,0x3c,0x16,0xc1,0x72,0x51,0xb2,0x66,0x45
    ,0xdf,0x4c,0x2f,0x87,0xeb,0xc0,0x99,0x2a
    ,0xb1,0x77,0xfb,0xa5,0x1d,0xb9,0x2c,0x2a
    ] ;

    ubyte[32] alicepk;

    static immutable ubyte[32] res = [
     0x85,0x20,0xf0,0x09,0x89,0x30,0xa7,0x54
    ,0x74,0x8b,0x7d,0xdc,0xb4,0x3e,0xf7,0x5a
    ,0x0d,0xbf,0x3a,0x0d,0x26,0x38,0x1a,0xf4
    ,0xeb,0xa4,0xa9,0x8e,0xaa,0x9b,0x4e,0x6a
    ];

    /*crypto_scalarmult_curve25519_base*/crypto_scalarmult_base(alicepk,alicesk);
    assert(alicepk == res);
  }
  scalarmult();

  void scalarmult2 () {
    writeln("scalarmult2");
    static immutable ubyte[32] bobsk = [
     0x5d,0xab,0x08,0x7e,0x62,0x4a,0x8a,0x4b
    ,0x79,0xe1,0x7f,0x8b,0x83,0x80,0x0e,0xe6
    ,0x6f,0x3b,0xb1,0x29,0x26,0x18,0xb6,0xfd
    ,0x1c,0x2f,0x8b,0x27,0xff,0x88,0xe0,0xeb
    ] ;

    ubyte[32] bobpk;

    static immutable ubyte[32] res = [
     0xde,0x9e,0xdb,0x7d,0x7b,0x7d,0xc1,0xb4
    ,0xd3,0x5b,0x61,0xc2,0xec,0xe4,0x35,0x37
    ,0x3f,0x83,0x43,0xc8,0x5b,0x78,0x67,0x4d
    ,0xad,0xfc,0x7e,0x14,0x6f,0x88,0x2b,0x4f
    ];

    /*crypto_scalarmult_curve25519_base*/crypto_scalarmult_base(bobpk,bobsk);
    assert(bobpk == res);
  }
  scalarmult2();

  void scalarmult5 () {
    writeln("scalarmult5");
    static immutable ubyte[32] alicesk = [
     0x77,0x07,0x6d,0x0a,0x73,0x18,0xa5,0x7d
    ,0x3c,0x16,0xc1,0x72,0x51,0xb2,0x66,0x45
    ,0xdf,0x4c,0x2f,0x87,0xeb,0xc0,0x99,0x2a
    ,0xb1,0x77,0xfb,0xa5,0x1d,0xb9,0x2c,0x2a
    ] ;

    static immutable ubyte[32] bobpk = [
     0xde,0x9e,0xdb,0x7d,0x7b,0x7d,0xc1,0xb4
    ,0xd3,0x5b,0x61,0xc2,0xec,0xe4,0x35,0x37
    ,0x3f,0x83,0x43,0xc8,0x5b,0x78,0x67,0x4d
    ,0xad,0xfc,0x7e,0x14,0x6f,0x88,0x2b,0x4f
    ] ;

    ubyte[32] k;

    static immutable ubyte[32] res = [
     0x4a,0x5d,0x9d,0x5b,0xa4,0xce,0x2d,0xe1
    ,0x72,0x8e,0x3b,0xf4,0x80,0x35,0x0f,0x25
    ,0xe0,0x7e,0x21,0xc9,0x47,0xd1,0x9e,0x33
    ,0x76,0xf0,0x9b,0x3c,0x1e,0x16,0x17,0x42
    ];

    crypto_scalarmult(k,alicesk,bobpk);
    assert(k == res);
  }
  scalarmult5();

  void scalarmult6 () {
    writeln("scalarmult6");
    static immutable ubyte[32] bobsk = [
     0x5d,0xab,0x08,0x7e,0x62,0x4a,0x8a,0x4b
    ,0x79,0xe1,0x7f,0x8b,0x83,0x80,0x0e,0xe6
    ,0x6f,0x3b,0xb1,0x29,0x26,0x18,0xb6,0xfd
    ,0x1c,0x2f,0x8b,0x27,0xff,0x88,0xe0,0xeb
   ] ;

    static immutable ubyte[32] alicepk = [
     0x85,0x20,0xf0,0x09,0x89,0x30,0xa7,0x54
    ,0x74,0x8b,0x7d,0xdc,0xb4,0x3e,0xf7,0x5a
    ,0x0d,0xbf,0x3a,0x0d,0x26,0x38,0x1a,0xf4
    ,0xeb,0xa4,0xa9,0x8e,0xaa,0x9b,0x4e,0x6a
    ] ;

    ubyte[32] k;

    static immutable ubyte[32] res = [
     0x4a,0x5d,0x9d,0x5b,0xa4,0xce,0x2d,0xe1
    ,0x72,0x8e,0x3b,0xf4,0x80,0x35,0x0f,0x25
    ,0xe0,0x7e,0x21,0xc9,0x47,0xd1,0x9e,0x33
    ,0x76,0xf0,0x9b,0x3c,0x1e,0x16,0x17,0x42
    ];

    crypto_scalarmult(k,bobsk,alicepk);
    assert(k == res);
  }
  scalarmult6();

  void secretbox () {
    writeln("secretbox");
    static immutable ubyte[32] firstkey = [
     0x1b,0x27,0x55,0x64,0x73,0xe9,0x85,0xd4
    ,0x62,0xcd,0x51,0x19,0x7a,0x9a,0x46,0xc7
    ,0x60,0x09,0x54,0x9e,0xac,0x64,0x74,0xf2
    ,0x06,0xc4,0xee,0x08,0x44,0xf6,0x83,0x89
    ] ;

    static immutable ubyte[24] nonce = [
     0x69,0x69,0x6e,0xe9,0x55,0xb6,0x2b,0x73
    ,0xcd,0x62,0xbd,0xa8,0x75,0xfc,0x73,0xd6
    ,0x82,0x19,0xe0,0x03,0x6b,0x7a,0x0b,0x37
    ] ;

    // API requires first 32 bytes to be 0
    static immutable ubyte[163] m = [
        0,   0,   0,   0,   0,   0,   0,   0
    ,   0,   0,   0,   0,   0,   0,   0,   0
    ,   0,   0,   0,   0,   0,   0,   0,   0
    ,   0,   0,   0,   0,   0,   0,   0,   0
    ,0xbe,0x07,0x5f,0xc5,0x3c,0x81,0xf2,0xd5
    ,0xcf,0x14,0x13,0x16,0xeb,0xeb,0x0c,0x7b
    ,0x52,0x28,0xc5,0x2a,0x4c,0x62,0xcb,0xd4
    ,0x4b,0x66,0x84,0x9b,0x64,0x24,0x4f,0xfc
    ,0xe5,0xec,0xba,0xaf,0x33,0xbd,0x75,0x1a
    ,0x1a,0xc7,0x28,0xd4,0x5e,0x6c,0x61,0x29
    ,0x6c,0xdc,0x3c,0x01,0x23,0x35,0x61,0xf4
    ,0x1d,0xb6,0x6c,0xce,0x31,0x4a,0xdb,0x31
    ,0x0e,0x3b,0xe8,0x25,0x0c,0x46,0xf0,0x6d
    ,0xce,0xea,0x3a,0x7f,0xa1,0x34,0x80,0x57
    ,0xe2,0xf6,0x55,0x6a,0xd6,0xb1,0x31,0x8a
    ,0x02,0x4a,0x83,0x8f,0x21,0xaf,0x1f,0xde
    ,0x04,0x89,0x77,0xeb,0x48,0xf5,0x9f,0xfd
    ,0x49,0x24,0xca,0x1c,0x60,0x90,0x2e,0x52
    ,0xf0,0xa0,0x89,0xbc,0x76,0x89,0x70,0x40
    ,0xe0,0x82,0xf9,0x37,0x76,0x38,0x48,0x64
    ,0x5e,0x07,0x05
    ] ;

    static immutable ubyte[] res = [
     0xf3,0xff,0xc7,0x70,0x3f,0x94,0x00,0xe5
    ,0x2a,0x7d,0xfb,0x4b,0x3d,0x33,0x05,0xd9
    ,0x8e,0x99,0x3b,0x9f,0x48,0x68,0x12,0x73
    ,0xc2,0x96,0x50,0xba,0x32,0xfc,0x76,0xce
    ,0x48,0x33,0x2e,0xa7,0x16,0x4d,0x96,0xa4
    ,0x47,0x6f,0xb8,0xc5,0x31,0xa1,0x18,0x6a
    ,0xc0,0xdf,0xc1,0x7c,0x98,0xdc,0xe8,0x7b
    ,0x4d,0xa7,0xf0,0x11,0xec,0x48,0xc9,0x72
    ,0x71,0xd2,0xc2,0x0f,0x9b,0x92,0x8f,0xe2
    ,0x27,0x0d,0x6f,0xb8,0x63,0xd5,0x17,0x38
    ,0xb4,0x8e,0xee,0xe3,0x14,0xa7,0xcc,0x8a
    ,0xb9,0x32,0x16,0x45,0x48,0xe5,0x26,0xae
    ,0x90,0x22,0x43,0x68,0x51,0x7a,0xcf,0xea
    ,0xbd,0x6b,0xb3,0x73,0x2b,0xc0,0xe9,0xda
    ,0x99,0x83,0x2b,0x61,0xca,0x01,0xb6,0xde
    ,0x56,0x24,0x4a,0x9e,0x88,0xd5,0xf9,0xb3
    ,0x79,0x73,0xf6,0x22,0xa4,0x3d,0x14,0xa6
    ,0x59,0x9b,0x1f,0x65,0x4c,0xb4,0x5a,0x74
    ,0xe3,0x55,0xa5
    ];

    ubyte c[163];
    crypto_secretbox(c,m,nonce,firstkey);
    for (auto i = 16; i < 163; ++i) assert(c[i] == res[i-16]);
  }
  secretbox();

  void secretbox2 () {
    writeln("secretbox2");
    static immutable ubyte[32] firstkey = [
     0x1b,0x27,0x55,0x64,0x73,0xe9,0x85,0xd4
    ,0x62,0xcd,0x51,0x19,0x7a,0x9a,0x46,0xc7
    ,0x60,0x09,0x54,0x9e,0xac,0x64,0x74,0xf2
    ,0x06,0xc4,0xee,0x08,0x44,0xf6,0x83,0x89
    ] ;

    static immutable ubyte[24] nonce = [
     0x69,0x69,0x6e,0xe9,0x55,0xb6,0x2b,0x73
    ,0xcd,0x62,0xbd,0xa8,0x75,0xfc,0x73,0xd6
    ,0x82,0x19,0xe0,0x03,0x6b,0x7a,0x0b,0x37
    ] ;

    // API requires first 16 bytes to be 0
    static immutable ubyte[163] c = [
        0,   0,   0,   0,   0,   0,   0,   0
    ,   0,   0,   0,   0,   0,   0,   0,   0
    ,0xf3,0xff,0xc7,0x70,0x3f,0x94,0x00,0xe5
    ,0x2a,0x7d,0xfb,0x4b,0x3d,0x33,0x05,0xd9
    ,0x8e,0x99,0x3b,0x9f,0x48,0x68,0x12,0x73
    ,0xc2,0x96,0x50,0xba,0x32,0xfc,0x76,0xce
    ,0x48,0x33,0x2e,0xa7,0x16,0x4d,0x96,0xa4
    ,0x47,0x6f,0xb8,0xc5,0x31,0xa1,0x18,0x6a
    ,0xc0,0xdf,0xc1,0x7c,0x98,0xdc,0xe8,0x7b
    ,0x4d,0xa7,0xf0,0x11,0xec,0x48,0xc9,0x72
    ,0x71,0xd2,0xc2,0x0f,0x9b,0x92,0x8f,0xe2
    ,0x27,0x0d,0x6f,0xb8,0x63,0xd5,0x17,0x38
    ,0xb4,0x8e,0xee,0xe3,0x14,0xa7,0xcc,0x8a
    ,0xb9,0x32,0x16,0x45,0x48,0xe5,0x26,0xae
    ,0x90,0x22,0x43,0x68,0x51,0x7a,0xcf,0xea
    ,0xbd,0x6b,0xb3,0x73,0x2b,0xc0,0xe9,0xda
    ,0x99,0x83,0x2b,0x61,0xca,0x01,0xb6,0xde
    ,0x56,0x24,0x4a,0x9e,0x88,0xd5,0xf9,0xb3
    ,0x79,0x73,0xf6,0x22,0xa4,0x3d,0x14,0xa6
    ,0x59,0x9b,0x1f,0x65,0x4c,0xb4,0x5a,0x74
    ,0xe3,0x55,0xa5
    ] ;

    static immutable ubyte[] res = [
     0xbe,0x07,0x5f,0xc5,0x3c,0x81,0xf2,0xd5
    ,0xcf,0x14,0x13,0x16,0xeb,0xeb,0x0c,0x7b
    ,0x52,0x28,0xc5,0x2a,0x4c,0x62,0xcb,0xd4
    ,0x4b,0x66,0x84,0x9b,0x64,0x24,0x4f,0xfc
    ,0xe5,0xec,0xba,0xaf,0x33,0xbd,0x75,0x1a
    ,0x1a,0xc7,0x28,0xd4,0x5e,0x6c,0x61,0x29
    ,0x6c,0xdc,0x3c,0x01,0x23,0x35,0x61,0xf4
    ,0x1d,0xb6,0x6c,0xce,0x31,0x4a,0xdb,0x31
    ,0x0e,0x3b,0xe8,0x25,0x0c,0x46,0xf0,0x6d
    ,0xce,0xea,0x3a,0x7f,0xa1,0x34,0x80,0x57
    ,0xe2,0xf6,0x55,0x6a,0xd6,0xb1,0x31,0x8a
    ,0x02,0x4a,0x83,0x8f,0x21,0xaf,0x1f,0xde
    ,0x04,0x89,0x77,0xeb,0x48,0xf5,0x9f,0xfd
    ,0x49,0x24,0xca,0x1c,0x60,0x90,0x2e,0x52
    ,0xf0,0xa0,0x89,0xbc,0x76,0x89,0x70,0x40
    ,0xe0,0x82,0xf9,0x37,0x76,0x38,0x48,0x64
    ,0x5e,0x07,0x05
    ];

    ubyte m[163];

    assert(crypto_secretbox_open(m,c,nonce,firstkey));
    for (auto i = 32; i < 163; ++i) assert(m[i] == res[i-32]);
  }
  secretbox2();

  void secretbox7 () {
    writeln("secretbox7");
    static ubyte[crypto_secretbox_KEYBYTES] k;
    static ubyte[crypto_secretbox_NONCEBYTES] n;
    static ubyte[10000] m, c, m2;
    for (auto mlen = 0; mlen < 1000 && mlen+crypto_secretbox_ZEROBYTES < m.length; ++mlen) {
      randombytes(k,crypto_secretbox_KEYBYTES);
      randombytes(n,crypto_secretbox_NONCEBYTES);
      randombytes(m[crypto_secretbox_ZEROBYTES..$],mlen);
      crypto_secretbox(c[0..mlen+crypto_secretbox_ZEROBYTES],m,n,k);
      assert(crypto_secretbox_open(m2[0..mlen+crypto_secretbox_ZEROBYTES],c,n,k));
      for (auto i = 0; i < mlen+crypto_secretbox_ZEROBYTES; ++i) assert(m2[i] == m[i]);
    }
  }
  secretbox7();

  void secretbox8 () {
    writeln("secretbox8");
    static ubyte[crypto_secretbox_KEYBYTES] k;
    static ubyte[crypto_secretbox_NONCEBYTES] n;
    static ubyte[10000] m, c, m2;
    for (auto mlen = 0; mlen < 1000 && mlen+crypto_secretbox_ZEROBYTES < m.length; ++mlen) {
      randombytes(k,crypto_secretbox_KEYBYTES);
      randombytes(n,crypto_secretbox_NONCEBYTES);
      randombytes(m[crypto_secretbox_ZEROBYTES..$],mlen);
      crypto_secretbox(c[0..mlen+crypto_secretbox_ZEROBYTES],m,n,k);
      auto caught = 0;
      while (caught < 10) {
        c[uniform(0, mlen+crypto_secretbox_ZEROBYTES)] = cast(ubyte)uniform(0, 256);
        if (crypto_secretbox_open(m2[0..mlen+crypto_secretbox_ZEROBYTES],c,n,k)) {
          for (auto i = 0; i < mlen+crypto_secretbox_ZEROBYTES; ++i) assert(m2[i] == m[i]);
        }
        ++caught;
      }
      assert(caught == 10);
    }
  }
  version(unittest_full) secretbox8(); // it's slow

  void stream () {
    writeln("stream");
    static immutable ubyte[32] firstkey = [
     0x1b,0x27,0x55,0x64,0x73,0xe9,0x85,0xd4
    ,0x62,0xcd,0x51,0x19,0x7a,0x9a,0x46,0xc7
    ,0x60,0x09,0x54,0x9e,0xac,0x64,0x74,0xf2
    ,0x06,0xc4,0xee,0x08,0x44,0xf6,0x83,0x89
    ] ;

    static immutable ubyte[24] nonce = [
     0x69,0x69,0x6e,0xe9,0x55,0xb6,0x2b,0x73
    ,0xcd,0x62,0xbd,0xa8,0x75,0xfc,0x73,0xd6
    ,0x82,0x19,0xe0,0x03,0x6b,0x7a,0x0b,0x37
    ] ;

    static ubyte[4194304] output;

    //ubyte h[32];
    //static immutable ubyte[32] res = [0x66,0x2b,0x9d,0x0e,0x34,0x63,0x02,0x91,0x56,0x06,0x9b,0x12,0xf9,0x18,0x69,0x1a,0x98,0xf7,0xdf,0xb2,0xca,0x03,0x93,0xc9,0x6b,0xbf,0xc6,0xb1,0xfb,0xd6,0x30,0xa2];

    crypto_stream(output,nonce,firstkey);
    //crypto_hash_sha256(h,output,sizeof output);
    assert(hashToString(SHA256(output[0..$])) == "662b9d0e3463029156069b12f918691a98f7dfb2ca0393c96bbfc6b1fbd630a2");
  }
  stream();

  void stream2 () {
    writeln("stream2");
    static immutable ubyte[32] secondkey = [
     0xdc,0x90,0x8d,0xda,0x0b,0x93,0x44,0xa9
    ,0x53,0x62,0x9b,0x73,0x38,0x20,0x77,0x88
    ,0x80,0xf3,0xce,0xb4,0x21,0xbb,0x61,0xb9
    ,0x1c,0xbd,0x4c,0x3e,0x66,0x25,0x6c,0xe4
    ] ;

    static immutable ubyte[8] noncesuffix = [
     0x82,0x19,0xe0,0x03,0x6b,0x7a,0x0b,0x37
    ] ;

    static ubyte[4194304] output;

    crypto_stream_salsa20(output,noncesuffix,secondkey);
    assert(hashToString(SHA256(output[0..$])) == "662b9d0e3463029156069b12f918691a98f7dfb2ca0393c96bbfc6b1fbd630a2");
  }
  stream2();

  void stream3 () {
    writeln("stream3");
    static immutable ubyte[32] firstkey = [
     0x1b,0x27,0x55,0x64,0x73,0xe9,0x85,0xd4
    ,0x62,0xcd,0x51,0x19,0x7a,0x9a,0x46,0xc7
    ,0x60,0x09,0x54,0x9e,0xac,0x64,0x74,0xf2
    ,0x06,0xc4,0xee,0x08,0x44,0xf6,0x83,0x89
    ] ;

    static immutable ubyte[24] nonce = [
     0x69,0x69,0x6e,0xe9,0x55,0xb6,0x2b,0x73
    ,0xcd,0x62,0xbd,0xa8,0x75,0xfc,0x73,0xd6
    ,0x82,0x19,0xe0,0x03,0x6b,0x7a,0x0b,0x37
    ] ;

    ubyte rs[32];

    static immutable ubyte[32] res = [
     0xee,0xa6,0xa7,0x25,0x1c,0x1e,0x72,0x91
    ,0x6d,0x11,0xc2,0xcb,0x21,0x4d,0x3c,0x25
    ,0x25,0x39,0x12,0x1d,0x8e,0x23,0x4e,0x65
    ,0x2d,0x65,0x1f,0xa4,0xc8,0xcf,0xf8,0x80
    ];

    crypto_stream/*_xsalsa20*/(rs,nonce,firstkey);
    assert(rs == res);
  }
  stream3();

  void stream4 () {
    writeln("stream4");
    static immutable ubyte[32] firstkey = [
     0x1b,0x27,0x55,0x64,0x73,0xe9,0x85,0xd4
    ,0x62,0xcd,0x51,0x19,0x7a,0x9a,0x46,0xc7
    ,0x60,0x09,0x54,0x9e,0xac,0x64,0x74,0xf2
    ,0x06,0xc4,0xee,0x08,0x44,0xf6,0x83,0x89
    ] ;

    static immutable ubyte[24] nonce = [
     0x69,0x69,0x6e,0xe9,0x55,0xb6,0x2b,0x73
    ,0xcd,0x62,0xbd,0xa8,0x75,0xfc,0x73,0xd6
    ,0x82,0x19,0xe0,0x03,0x6b,0x7a,0x0b,0x37
    ] ;

    static immutable ubyte[163] m = [
        0,   0,   0,   0,   0,   0,   0,   0
    ,   0,   0,   0,   0,   0,   0,   0,   0
    ,   0,   0,   0,   0,   0,   0,   0,   0
    ,   0,   0,   0,   0,   0,   0,   0,   0
    ,0xbe,0x07,0x5f,0xc5,0x3c,0x81,0xf2,0xd5
    ,0xcf,0x14,0x13,0x16,0xeb,0xeb,0x0c,0x7b
    ,0x52,0x28,0xc5,0x2a,0x4c,0x62,0xcb,0xd4
    ,0x4b,0x66,0x84,0x9b,0x64,0x24,0x4f,0xfc
    ,0xe5,0xec,0xba,0xaf,0x33,0xbd,0x75,0x1a
    ,0x1a,0xc7,0x28,0xd4,0x5e,0x6c,0x61,0x29
    ,0x6c,0xdc,0x3c,0x01,0x23,0x35,0x61,0xf4
    ,0x1d,0xb6,0x6c,0xce,0x31,0x4a,0xdb,0x31
    ,0x0e,0x3b,0xe8,0x25,0x0c,0x46,0xf0,0x6d
    ,0xce,0xea,0x3a,0x7f,0xa1,0x34,0x80,0x57
    ,0xe2,0xf6,0x55,0x6a,0xd6,0xb1,0x31,0x8a
    ,0x02,0x4a,0x83,0x8f,0x21,0xaf,0x1f,0xde
    ,0x04,0x89,0x77,0xeb,0x48,0xf5,0x9f,0xfd
    ,0x49,0x24,0xca,0x1c,0x60,0x90,0x2e,0x52
    ,0xf0,0xa0,0x89,0xbc,0x76,0x89,0x70,0x40
    ,0xe0,0x82,0xf9,0x37,0x76,0x38,0x48,0x64
    ,0x5e,0x07,0x05
    ] ;

    ubyte c[163];

    static immutable ubyte[] res = [
     0x8e,0x99,0x3b,0x9f,0x48,0x68,0x12,0x73
    ,0xc2,0x96,0x50,0xba,0x32,0xfc,0x76,0xce
    ,0x48,0x33,0x2e,0xa7,0x16,0x4d,0x96,0xa4
    ,0x47,0x6f,0xb8,0xc5,0x31,0xa1,0x18,0x6a
    ,0xc0,0xdf,0xc1,0x7c,0x98,0xdc,0xe8,0x7b
    ,0x4d,0xa7,0xf0,0x11,0xec,0x48,0xc9,0x72
    ,0x71,0xd2,0xc2,0x0f,0x9b,0x92,0x8f,0xe2
    ,0x27,0x0d,0x6f,0xb8,0x63,0xd5,0x17,0x38
    ,0xb4,0x8e,0xee,0xe3,0x14,0xa7,0xcc,0x8a
    ,0xb9,0x32,0x16,0x45,0x48,0xe5,0x26,0xae
    ,0x90,0x22,0x43,0x68,0x51,0x7a,0xcf,0xea
    ,0xbd,0x6b,0xb3,0x73,0x2b,0xc0,0xe9,0xda
    ,0x99,0x83,0x2b,0x61,0xca,0x01,0xb6,0xde
    ,0x56,0x24,0x4a,0x9e,0x88,0xd5,0xf9,0xb3
    ,0x79,0x73,0xf6,0x22,0xa4,0x3d,0x14,0xa6
    ,0x59,0x9b,0x1f,0x65,0x4c,0xb4,0x5a,0x74
    ,0xe3,0x55,0xa5
    ];

    /*crypto_stream_xsalsa20_xor*/crypto_stream_xor(c,m,nonce,firstkey);
    for (auto i = 32; i < 163; ++i) assert(c[i] == res[i-32]);
  }
  stream4();
}
version(unittest) {
  version(unittest_main) {
    void main () {}
  }
}
