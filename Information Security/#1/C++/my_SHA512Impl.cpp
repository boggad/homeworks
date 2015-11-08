#include <jni.h>
#include "my_SHA512.h"
#include <stdio.h>
#include <stdlib.h>
#include <cstring>

#define ch(x,y,z) 	((x & y) ^ (~x & z))
#define maj(x,y,z) 	((x & y) ^ (x & z) ^ (y & z))
#define rotr(x,n) 	((x >> n) | (x << ((sizeof(x) << 3) - n)))
#define sig0(x) 	(rotr(x, 28) ^ rotr(x, 34) ^ rotr(x, 39))
#define sig1(x)		(rotr(x, 14) ^ rotr(x, 18) ^ rotr(x, 41))
#define del0(x)		(rotr(x, 1) ^ rotr(x, 8) ^ (x >> 7))
#define del1(x)		(rotr(x, 19) ^ rotr(x, 61) ^ (x >> 6))

typedef	unsigned long long u64;
typedef unsigned char uint8;

#define SHA_PACK(str, x) 		\
{								\
	*(x) = ((u64) *((str) + 7))	\
	| ((u64) *((str) + 6) << 8)	\
	| ((u64) *((str) + 5) << 16)\
	| ((u64) *((str) + 4) << 24)\
	| ((u64) *((str) + 3) << 32)\
	| ((u64) *((str) + 2) << 40)\
	| ((u64) *((str) + 1) << 48)\
	| ((u64) *(str) << 56);		\
}								\

#define SHA_UNPACK(str, x) 				\
{										\
	*((str) + 7) = (uint8) ((x)      ); \
    *((str) + 6) = (uint8) ((x) >>  8); \
    *((str) + 5) = (uint8) ((x) >> 16); \
    *((str) + 4) = (uint8) ((x) >> 24); \
    *((str) + 3) = (uint8) ((x) >> 32); \
    *((str) + 2) = (uint8) ((x) >> 40); \
    *((str) + 1) = (uint8) ((x) >> 48); \
    *((str) + 0) = (uint8) ((x) >> 56); \
}										\

#define SHA_UNPACK32(x, str)                 \
{                                             \
    *((str) + 3) = (uint8) ((x)      );       \
    *((str) + 2) = (uint8) ((x) >>  8);       \
    *((str) + 1) = (uint8) ((x) >> 16);       \
    *((str) + 0) = (uint8) ((x) >> 24);       \
}

#ifdef __cplusplus
extern "C" {
#endif

jbyteArray as_byte_array(unsigned char* buf, int len, JNIEnv* env)
{
    jbyteArray array = env->NewByteArray(len);
    env->SetByteArrayRegion(array, 0, len, reinterpret_cast<jbyte*>(buf));
    return array;
}

unsigned char* as_uchar_array(jbyteArray array, JNIEnv* env)
{
    int len = env->GetArrayLength(array);
    unsigned char* buf = new unsigned char[len];
    env->GetByteArrayRegion(array, 0, len, reinterpret_cast<jbyte*>(buf));
    return buf;
}


const u64 K[80] = {
		0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
		0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
		0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
		0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
		0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
		0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
		0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
		0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
		0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
		0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
		0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
		0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
		0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
		0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
		0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
		0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
		0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
		0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
		0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
		0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

unsigned char* message_padding(const unsigned char* msg, size_t len)
{
	size_t padded_size = (len/128 + 1) * 128;
	unsigned char* padded = (unsigned char*) malloc(padded_size);

	memmove(padded, msg, len);
	*(padded + len) = (unsigned char) 0x80;
	memset((padded + len + 1), 0, (128 - len - 1 - 4));
	unsigned int msg_len = (unsigned int) len;
	SHA_UNPACK32(msg_len*8, (padded + padded_size - 4));

	return padded;
}


JNIEXPORT jbyteArray JNICALL Java_my_SHA512_sha512(JNIEnv* env, jclass _class, jbyteArray message)
{
    size_t len = env->GetArrayLength(message);
    unsigned char *msg = as_uchar_array(message, env);
    unsigned char *padded = message_padding(msg, len);
    size_t padded_len = (len/128 + 1) * 128;

    delete[] msg;

    // init
    u64 H0 = 0x6a09e667f3bcc908ULL;
    u64 H1 = 0xbb67ae8584caa73bULL;
    u64 H2 = 0x3c6ef372fe94f82bULL;
    u64 H3 = 0xa54ff53a5f1d36f1ULL;
    u64 H4 = 0x510e527fade682d1ULL;
    u64 H5 = 0x9b05688c2b3e6c1fULL;
    u64 H6 = 0x1f83d9abfb41bd6bULL;
    u64 H7 = 0x5be0cd19137e2179ULL;

    size_t blocks_num = padded_len / 128;
    for(size_t i = 0; i < blocks_num; i++) {
    	u64 *words = (u64*) malloc(64*80);
    	for(size_t j = 0; j < 16; j++) {
    		 SHA_PACK(&padded[i*128+j*8], &words[j]);
    	}

    	for(size_t j = 16; j < 80; j++) {
    		words[j] = words[j-16] + del0(words[j-15]) + words[j-7] + del1(words[j-2]);
    	}

    	u64 a = H0;
    	u64 b = H1;
    	u64 c = H2;
    	u64 d = H3;
    	u64 e = H4;
    	u64 f = H5;
    	u64 g = H6;
    	u64 h = H7;

    	for(size_t j = 0; j < 80; j++) {
    		u64 tmp1 = h + sig1(e) + ch(e,f,g) + words[j] + K[j];
    		u64 tmp2 = sig0(a) + maj(a,b,c);
    		h = g;
    		g = f;
    		f = e;
    		e = d + tmp1;
    		d = c;
    		c = b;
    		b = a;
    		a = tmp1 + tmp2;
    	}

    	H0 = H0 + a;
    	H1 = H1 + b;
    	H2 = H2 + c;
    	H3 = H3 + d;
    	H4 = H4 + e;
    	H5 = H5 + f;
    	H6 = H6 + g;
    	H7 = H7 + h;

    	// clear memory
    	delete[] words;
    }

    unsigned char hash[64];

    SHA_UNPACK(&hash[0], H0);
    SHA_UNPACK(&hash[1 << 3], H1);
    SHA_UNPACK(&hash[2 << 3], H2);
    SHA_UNPACK(&hash[3 << 3], H3);
    SHA_UNPACK(&hash[4 << 3], H4);
    SHA_UNPACK(&hash[5 << 3], H5);
    SHA_UNPACK(&hash[6 << 3], H6);
    SHA_UNPACK(&hash[7 << 3], H7);

    return as_byte_array(hash, 64, env);
}


#ifdef __cplusplus
}
#endif
