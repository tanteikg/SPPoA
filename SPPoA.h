/*
 * Name: SPPoA.h
 * Author: Tan Teik Guan
 * Description: Signature Pre-image proof of assets 
 *
 * Copyright pQCee 2022,2023. All rights reserved
 * 
 * “Commons Clause” License Condition v1.0
 *
 * The Software is provided to you by the Licensor under the License, as defined below, subject to the following 
 * condition.
 *
 * Without limiting other conditions in the License, the grant of rights under the License will not include, and 
 * the License does not grant to you, the right to Sell the Software.
 *
 * For purposes of the foregoing, “Sell” means practicing any or all of the rights granted to you under the License 
 * to provide to third parties, for a fee or other consideration (including without limitation fees for hosting or 
 * consulting/ support services related to the Software), a product or service whose value derives, entirely or 
 * substantially, from the functionality of the Software. Any license notice or attribution required by the License 
 * must also include this Commons Clause License Condition notice.
 *
 * Software: SPPoA 
 *
 * License: MIT 1.0 
 *
 * Licensor: pQCee Pte Ltd 
 *
 */

/*
 ============================================================================
 Name        : shared.h
 Author      : Sobuno
 Version     : 0.1
 Description : Common functions for the SHA-256 prover and verifier
 ============================================================================
 */

#ifndef SPPOAO_H_
#define SPPOAO_H_


#ifdef WASM
#include <emscripten.h>
#endif

/*
// secp256r1 or prime256v1 parameters
#define CURVE_P "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"
#define CURVE_N "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
#define CURVE_A "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC"
#define CURVE_B "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B"
#define CURVE_Gx "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"
#define CURVE_Gy "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"
*/
// secp256k1 parameters
#define CURVE_FULL "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF"
#define CURVE_P "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"
#define CURVE_N "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
#define CURVE_A "0000000000000000000000000000000000000000000000000000000000000000"
#define CURVE_B "0000000000000000000000000000000000000000000000000000000000000007"
#define CURVE_Gx "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798" 
#define CURVE_Gy "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"


static const uint32_t hA[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };

static const uint32_t k[64] = { 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
				0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98,
				0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
				0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6,
				0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
				0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3,
				0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138,
				0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e,
				0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
				0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
				0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
				0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814,
				0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };

static const uint32_t hRIPE[5] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0};
static const uint32_t hG =  0x5a827999;
static const uint32_t hH =  0x6ed9eba1;
static const uint32_t hI =  0x8f1bbcdc;
static const uint32_t hJ =  0xa953fd4e;

static const uint32_t hGG =  0x7a6d76e9;
static const uint32_t hHH =  0x6d703ef3;
static const uint32_t hII =  0x5c4dd124;
static const uint32_t hJJ =  0x50a28be6;

//#define ySize 736
#define ySize 1623   // 1607 + 16
//#define rSize 6416
//#define rSize (45392/8) 
#define rSize 12512  // (100092/8 + 1) 

#define NUM_PARTIES 32
#define NUM_ROUNDS 10 
#define SHA256_INPUTS 64
#define NUM_ONLINE 4 
#define ECC_INPUTS 32
#define ECC_PUBKEY_LENGTH 32

#define RIPEMD160_DIGEST_LENGTH 20
#define SHA256_DIGEST_LENGTH 32
typedef struct {
	uint32_t y[ySize];
} View;

typedef struct {
	unsigned char rsseed[16];
	unsigned char H[SHA256_DIGEST_LENGTH];
	unsigned char masterkeys[NUM_ROUNDS-NUM_ONLINE][16];
	unsigned char H2[NUM_ROUNDS-NUM_ONLINE][SHA256_DIGEST_LENGTH];
	unsigned char keys[NUM_ONLINE][NUM_PARTIES-1][16];
	unsigned char com[NUM_ONLINE][SHA256_DIGEST_LENGTH];
	unsigned char auxBits[NUM_ONLINE][rSize];
	unsigned char maskedInput[NUM_ONLINE][ECC_INPUTS];
	View views[NUM_ONLINE];
} z;


extern void ripemd160(const uint8_t* msg, uint32_t msg_len, uint8_t* hash);
#define USER_LEN 20

//#define P_SIZE (((sizeof(z)+sizeof(a))*2*NUM_ROUNDS)+1)
#define P_SIZE ((((sizeof(z)/3)+1)*4) + 200) // b64 + JSON

#endif /* SPPOA_H_ */
