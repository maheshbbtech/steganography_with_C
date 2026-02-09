#include "crypto.h"

// ============================================================================
// SHA-256 Implementation
// ============================================================================

#define SHA256_BLOCK_SIZE 32            // SHA256 outputs a 32 byte digest

typedef struct {
    unsigned char data[64];
    unsigned int datalen;
    unsigned long long bitlen;
    unsigned int state[8];
} SHA256_CTX;

#define ROTLEFT(a,b) (((a) << (b)) | ((a) >> (32-(b))))
#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))

#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

static const unsigned int k[64] = {
	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

void sha256_transform(SHA256_CTX *ctx, const unsigned char data[]) {
	unsigned int a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

	for (i = 0, j = 0; i < 16; ++i, j += 4)
		m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
	for ( ; i < 64; ++i)
		m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

	a = ctx->state[0];
	b = ctx->state[1];
	c = ctx->state[2];
	d = ctx->state[3];
	e = ctx->state[4];
	f = ctx->state[5];
	g = ctx->state[6];
	h = ctx->state[7];

	for (i = 0; i < 64; ++i) {
		t1 = h + EP1(e) + CH(e, f, g) + k[i] + m[i];
		t2 = EP0(a) + MAJ(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}

	ctx->state[0] += a;
	ctx->state[1] += b;
	ctx->state[2] += c;
	ctx->state[3] += d;
	ctx->state[4] += e;
	ctx->state[5] += f;
	ctx->state[6] += g;
	ctx->state[7] += h;
}

void sha256_init(SHA256_CTX *ctx) {
	ctx->datalen = 0;
	ctx->bitlen = 0;
	ctx->state[0] = 0x6a09e667;
	ctx->state[1] = 0xbb67ae85;
	ctx->state[2] = 0x3c6ef372;
	ctx->state[3] = 0xa54ff53a;
	ctx->state[4] = 0x510e527f;
	ctx->state[5] = 0x9b05688c;
	ctx->state[6] = 0x1f83d9ab;
	ctx->state[7] = 0x5be0cd19;
}

void sha256_update(SHA256_CTX *ctx, const unsigned char data[], size_t len) {
	for (size_t i = 0; i < len; ++i) {
		ctx->data[ctx->datalen] = data[i];
		ctx->datalen++;
		if (ctx->datalen == 64) {
			sha256_transform(ctx, ctx->data);
			ctx->bitlen += 512;
			ctx->datalen = 0;
		}
	}
}

void sha256_final(SHA256_CTX *ctx, unsigned char hash[]) {
	unsigned int i = ctx->datalen;

	if (ctx->datalen < 56) {
		ctx->data[i++] = 0x80;
		while (i < 56)
			ctx->data[i++] = 0x00;
	}
	else {
		ctx->data[i++] = 0x80;
		while (i < 64)
			ctx->data[i++] = 0x00;
		sha256_transform(ctx, ctx->data);
		memset(ctx->data, 0, 56);
	}

	ctx->bitlen += ctx->datalen * 8;
	ctx->data[63] = ctx->bitlen;
	ctx->data[62] = ctx->bitlen >> 8;
	ctx->data[61] = ctx->bitlen >> 16;
	ctx->data[60] = ctx->bitlen >> 24;
	ctx->data[59] = ctx->bitlen >> 32;
	ctx->data[58] = ctx->bitlen >> 40;
	ctx->data[57] = ctx->bitlen >> 48;
	ctx->data[56] = ctx->bitlen >> 56;
	sha256_transform(ctx, ctx->data);

	for (i = 0; i < 4; ++i) {
		hash[i]      = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 4]  = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 8]  = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0x000000ff;
	}
}

// ============================================================================
// AES-256 Implementation (Tiny AES)
// ============================================================================

#ifndef AES_BLOCK_SIZE
#define AES_BLOCK_SIZE 16
#endif

// S-box
static const uint8_t sbox[256] = {
  //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 
};

static const uint8_t rsbox[256] = {
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d 
};

static const uint8_t Rcon[11] = {
  0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 
};

#define Nb 4
#define Nk 8        // AES-256 has 8 words in key
#define Nr 14       // AES-256 has 14 rounds

typedef struct {
    uint32_t round_key[AES_BLOCK_SIZE * (Nr + 1) / 4]; // round keys (in words)
} AES_CTX;

static void KeyExpansion(const uint8_t* key, uint8_t* RoundKey) {
  unsigned i, j, k;
  uint8_t tempa[4]; 

  // The first Nk words of the expanded key are the key itself.
  for (i = 0; i < Nk; ++i) {
    RoundKey[(i * 4) + 0] = key[(i * 4) + 0];
    RoundKey[(i * 4) + 1] = key[(i * 4) + 1];
    RoundKey[(i * 4) + 2] = key[(i * 4) + 2];
    RoundKey[(i * 4) + 3] = key[(i * 4) + 3];
  }

  // All other words are calculated from the previous words.
  for (i = Nk; i < Nb * (Nr + 1); ++i) {
    {
      k = (i - 1) * 4;
      tempa[0]=RoundKey[k + 0];
      tempa[1]=RoundKey[k + 1];
      tempa[2]=RoundKey[k + 2];
      tempa[3]=RoundKey[k + 3];
    }

    if (i % Nk == 0) {
      // Rotation
      const uint8_t u8tmp = tempa[0];
      tempa[0] = tempa[1];
      tempa[1] = tempa[2];
      tempa[2] = tempa[3];
      tempa[3] = u8tmp;

      // SubBytes
      tempa[0] = sbox[tempa[0]];
      tempa[1] = sbox[tempa[1]];
      tempa[2] = sbox[tempa[2]];
      tempa[3] = sbox[tempa[3]];

      tempa[0] = tempa[0] ^ Rcon[i/Nk];
    }
    else if (i % Nk == 4) {
      // For AES-256, there is an extra SubBytes step
      tempa[0] = sbox[tempa[0]];
      tempa[1] = sbox[tempa[1]];
      tempa[2] = sbox[tempa[2]];
      tempa[3] = sbox[tempa[3]];
    }

    j = i * 4; k=(i - Nk) * 4;
    RoundKey[j + 0] = RoundKey[k + 0] ^ tempa[0];
    RoundKey[j + 1] = RoundKey[k + 1] ^ tempa[1];
    RoundKey[j + 2] = RoundKey[k + 2] ^ tempa[2];
    RoundKey[j + 3] = RoundKey[k + 3] ^ tempa[3];
  }
}

static void AddRoundKey(uint8_t round, uint8_t* state, const uint8_t* RoundKey) {
  uint8_t i,j;
  for (i=0;i<4;++i) {
    for (j=0;j<4;++j) {
      state[j * 4 + i] ^= RoundKey[(round * Nb * 4) + (i * Nb) + j];
    }
  }
}

static void SubBytes(uint8_t* state) {
  uint8_t i, j;
  for (i = 0; i < 4; ++i) {
    for (j = 0; j < 4; ++j) {
      state[j * 4 + i] = sbox[state[j * 4 + i]];
    }
  }
}

static void ShiftRows(uint8_t* state) {
  uint8_t temp;
  // Rotate first row 1 columns to left  
  temp           = state[0 * 4 + 1];
  state[0 * 4 + 1] = state[1 * 4 + 1];
  state[1 * 4 + 1] = state[2 * 4 + 1];
  state[2 * 4 + 1] = state[3 * 4 + 1];
  state[3 * 4 + 1] = temp;

  // Rotate second row 2 columns to left  
  temp           = state[0 * 4 + 2];
  state[0 * 4 + 2] = state[2 * 4 + 2];
  state[2 * 4 + 2] = temp;

  temp           = state[1 * 4 + 2];
  state[1 * 4 + 2] = state[3 * 4 + 2];
  state[3 * 4 + 2] = temp;

  // Rotate third row 3 columns to left
  temp           = state[0 * 4 + 3];
  state[0 * 4 + 3] = state[3 * 4 + 3];
  state[3 * 4 + 3] = state[2 * 4 + 3];
  state[2 * 4 + 3] = state[1 * 4 + 3];
  state[1 * 4 + 3] = temp;
}

static uint8_t xtime(uint8_t x) {
  return ((x<<1) ^ (((x>>7) & 1) * 0x1b));
}

static void MixColumns(uint8_t* state) {
  uint8_t i;
  uint8_t Tmp, Tm, t;
  for (i = 0; i < 4; ++i) {  
    t   = state[i * 4 + 0];
    Tmp = state[i * 4 + 0] ^ state[i * 4 + 1] ^ state[i * 4 + 2] ^ state[i * 4 + 3] ;
    Tm  = state[i * 4 + 0] ^ state[i * 4 + 1] ; Tm = xtime(Tm);  state[i * 4 + 0] ^= Tm ^ Tmp ;
    Tm  = state[i * 4 + 1] ^ state[i * 4 + 2] ; Tm = xtime(Tm);  state[i * 4 + 1] ^= Tm ^ Tmp ;
    Tm  = state[i * 4 + 2] ^ state[i * 4 + 3] ; Tm = xtime(Tm);  state[i * 4 + 2] ^= Tm ^ Tmp ;
    Tm  = state[i * 4 + 3] ^ t ;              Tm = xtime(Tm);  state[i * 4 + 3] ^= Tm ^ Tmp ;
  }
}

static void Cipher(uint8_t* state, const uint8_t* RoundKey) {
  uint8_t round = 0;
  AddRoundKey(0, state, RoundKey);
  for (round = 1; round < Nr; ++round) {
    SubBytes(state);
    ShiftRows(state);
    MixColumns(state);
    AddRoundKey(round, state, RoundKey);
  }
  SubBytes(state);
  ShiftRows(state);
  AddRoundKey(Nr, state, RoundKey);
}

static void InvShiftRows(uint8_t* state) {
  uint8_t temp;
  // Rotate first row 1 columns to right  
  temp = state[3 * 4 + 1];
  state[3 * 4 + 1] = state[2 * 4 + 1];
  state[2 * 4 + 1] = state[1 * 4 + 1];
  state[1 * 4 + 1] = state[0 * 4 + 1];
  state[0 * 4 + 1] = temp;

  // Rotate second row 2 columns to right 
  temp = state[0 * 4 + 2];
  state[0 * 4 + 2] = state[2 * 4 + 2];
  state[2 * 4 + 2] = temp;

  temp = state[1 * 4 + 2];
  state[1 * 4 + 2] = state[3 * 4 + 2];
  state[3 * 4 + 2] = temp;

  // Rotate third row 3 columns to right
  temp = state[0 * 4 + 3];
  state[0 * 4 + 3] = state[1 * 4 + 3];
  state[1 * 4 + 3] = state[2 * 4 + 3];
  state[2 * 4 + 3] = state[3 * 4 + 3];
  state[3 * 4 + 3] = temp;
}

static void InvSubBytes(uint8_t* state) {
  uint8_t i, j;
  for (i = 0; i < 4; ++i) {
    for (j = 0; j < 4; ++j) {
      state[j * 4 + i] = rsbox[state[j * 4 + i]];
    }
  }
}

static uint8_t Multiply(uint8_t x, uint8_t y) {
  return (((y & 1) * x) ^
       ((y>>1 & 1) * xtime(x)) ^
       ((y>>2 & 1) * xtime(xtime(x))) ^
       ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^
       ((y>>4 & 1) * xtime(xtime(xtime(xtime(x)))))); /* this is enough */
}

static void InvMixColumns(uint8_t* state) {
  int i;
  uint8_t a, b, c, d;
  for (i = 0; i < 4; ++i) { 
    a = state[i * 4 + 0];
    b = state[i * 4 + 1];
    c = state[i * 4 + 2];
    d = state[i * 4 + 3];

    state[i * 4 + 0] = Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^ Multiply(d, 0x09);
    state[i * 4 + 1] = Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ Multiply(c, 0x0b) ^ Multiply(d, 0x0d);
    state[i * 4 + 2] = Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0e) ^ Multiply(d, 0x0b);
    state[i * 4 + 3] = Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ Multiply(c, 0x09) ^ Multiply(d, 0x0e);
  }
}

static void InvCipher(uint8_t* state, const uint8_t* RoundKey) {
  uint8_t round = 0;
  AddRoundKey(Nr, state, RoundKey);
  for (round = (Nr - 1); round > 0; --round) {
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(round, state, RoundKey);
    InvMixColumns(state);
  }
  InvShiftRows(state);
  InvSubBytes(state);
  AddRoundKey(0, state, RoundKey);
}

// ============================================================================
// Wrapper Functions
// ============================================================================

void derive_key(const char *password, unsigned char *key) {
    unsigned char hash[32];
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, (const unsigned char*)password, strlen(password));
    sha256_final(&ctx, hash);
    
    // For AES-256, we use the FULL 32 bytes (256 bits)
    memcpy(key, hash, 32); 
}

// PKCS#7 Padding
int encrypt_aes256(const char *plaintext, int len, const unsigned char *key, unsigned char **ciphertext) {
    // 60 words * 4 bytes = 240 bytes for RoundKey
    uint8_t RoundKey[240]; 
    KeyExpansion(key, RoundKey);

    // Padding
    int padding_len = AES_BLOCK_SIZE - (len % AES_BLOCK_SIZE);
    int total_len = len + padding_len;
    
    // Output: IV + Cipherbox
    // For simplicity, we use 0 IV for now, but space is reserved
    int out_len = AES_BLOCK_SIZE + total_len;
    *ciphertext = malloc(out_len);
    if (!*ciphertext) return -1;
    
    unsigned char *iv = *ciphertext;
    unsigned char *data = *ciphertext + AES_BLOCK_SIZE;

    // Use zero IV for simplicity
    memset(iv, 0, AES_BLOCK_SIZE);

    // Copy plaintext and pad
    memcpy(data, plaintext, len);
    memset(data + len, padding_len, padding_len); // PKCS7

    // CBC Encrypt
    unsigned char state[AES_BLOCK_SIZE];
    unsigned char *prev_block = iv;

    for (int i = 0; i < total_len; i += AES_BLOCK_SIZE) {
        memcpy(state, data + i, AES_BLOCK_SIZE);
        // XOR with prev block (IV for first)
        for(int j=0; j<AES_BLOCK_SIZE; j++) state[j] ^= prev_block[j];
        
        Cipher(state, RoundKey);
        
        memcpy(data + i, state, AES_BLOCK_SIZE);
        prev_block = data + i;
    }

    return out_len;
}

char *decrypt_aes256(const unsigned char *ciphertext, int len, const unsigned char *key) {
    if (len < AES_BLOCK_SIZE || len % AES_BLOCK_SIZE != 0) return NULL;

    uint8_t RoundKey[240];
    KeyExpansion(key, RoundKey);

    const unsigned char *iv = ciphertext;
    const unsigned char *data = ciphertext + AES_BLOCK_SIZE;
    int data_len = len - AES_BLOCK_SIZE;

    if (data_len <= 0) return NULL;

    unsigned char *buffer = malloc(data_len);
    if (!buffer) return NULL;

    unsigned char state[AES_BLOCK_SIZE];
    const unsigned char *prev_block = iv;

    for (int i = 0; i < data_len; i += AES_BLOCK_SIZE) {
        memcpy(state, data + i, AES_BLOCK_SIZE);
        InvCipher(state, RoundKey);
        // XOR with prev block
        for(int j=0; j<AES_BLOCK_SIZE; j++) state[j] ^= prev_block[j];
        
        memcpy(buffer + i, state, AES_BLOCK_SIZE);
        prev_block = data + i;
    }

    // Check padding (PKCS7)
    int padding_len = buffer[data_len - 1];
    if (padding_len <= 0 || padding_len > AES_BLOCK_SIZE) {
        free(buffer);
        return NULL; // Invalid padding
    }

    // Verify all padding bytes
    for (int i = 0; i < padding_len; ++i) {
        if (buffer[data_len - 1 - i] != padding_len) {
            free(buffer);
            return NULL;
        }
    }

    int plain_len = data_len - padding_len;
    buffer[plain_len] = '\0'; // Null terminate

    return (char*)buffer;
}
