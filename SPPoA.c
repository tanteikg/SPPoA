/*
 *
 * Name: SPPoA.c
 * Author: Tan Teik Guan
 * Description : Signature Pre-image proof of  assets
 *
 * Copyright pQCee 2023. All rights reserved
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
/*
 *  @brief This is the main implementation file of the signature scheme. All of
 *  the LowMC MPC code is here as well as lower-level versions of sign and
 *  verify that are called by the signature API.
 *
 *  This file is part of the reference implementation of the Picnic signature scheme.
 *  See the accompanying documentation for complete details.
 *
 *  The code is provided under the MIT license, see LICENSE for
 *  more details.
 *  SPDX-License-Identifier: MIT
 */
//#include <emscripten.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "SPPoA.h"
#include "sha256.h"

#define VERBOSE 0 
#define ToBytes(x) (x == 0)? 0:((x-1)/8+1)
#define WORD_SIZE_BITS 32

#define RIGHTROTATE(x,n) (((x) >> (n)) | ((x) << (32-(n))))
#define LEFTROTATE(x,n) (((x) << (n)) | ((x) >> (32-(n))))
#define GETBIT(x, i) (((x) >> (i)) & 0x01)
#define SETBIT(x, i, b)   x= (b)&1 ? (x)|(1 << (i)) : (x)&(~(1 << (i)))

// prototype from hash.c
// to implement using sha256 instead of sha3

#define MAX_DIGEST_SIZE 64
#define SHA256_DIGEST_SIZE 32

static void printdigest(unsigned char * digest)
{
	for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
		fprintf(stderr,"%02x",digest[i]);
	fprintf(stderr,"\n");
}

static int RAND_bytes(unsigned char * buf, int numBytes)
{
	while (numBytes-- > 0)
	{
		*buf = (unsigned char) (rand() & 0xFF);
		buf++;
	}
	return 1;
}

static void Compute_RAND(unsigned char * output, int size, unsigned char * seed, int seedLen)
{
	unsigned char hash[SHA256_DIGEST_LENGTH];
	char * namestr = "pQCee BeQuantumReady";
	char * tempptr = output;
	uint32_t count = 1;

	SHA256_CTX ctx;
	sha256_init(&ctx);
	sha256_update(&ctx, namestr, strlen(namestr));
	sha256_update(&ctx, (unsigned char*)&seedLen, sizeof(int));
	sha256_update(&ctx, seed, seedLen);
	sha256_update(&ctx, (unsigned char *)&size, sizeof(int));
	sha256_final(&ctx,hash);
	while (size > 0)
	{
		sha256_init(&ctx);
		sha256_update(&ctx, (unsigned char *)&count, sizeof(int));
		sha256_update(&ctx, (unsigned char *)&seedLen, sizeof(int));
		sha256_update(&ctx, seed, seedLen);
		sha256_update(&ctx, hash, sizeof(hash));
		sha256_final(&ctx,hash);
		if (size >= SHA256_DIGEST_LENGTH)
		{
			memcpy(tempptr,hash,SHA256_DIGEST_LENGTH);
			tempptr += SHA256_DIGEST_LENGTH;
		}
		else
			memcpy(tempptr,hash,size);
		size -= SHA256_DIGEST_LENGTH;
		count++;
	}
}

static void getAllRandomness(unsigned char key[16], unsigned char *randomness) {
	//Generate randomness: We use 728*32 bit of randomness per key.
	//Since AES block size is 128 bit, we need to run 728*32/128 = 182 iterations

        SHA256_CTX ctx;
        unsigned char * iv = (unsigned char *) "01234567890123456";
        unsigned char *plaintext =
                        (unsigned char *)"pQCee0SPPoA00000";
        unsigned char hashbuf[SHA256_DIGEST_LENGTH];
        int len;
        sha256_init(&ctx);
        sha256_update(&ctx,iv,strlen((char *)iv));
        sha256_update(&ctx,plaintext,strlen((char *)plaintext));
        sha256_update(&ctx,key,16);
        sha256_final(&ctx,hashbuf);
        for(int j=0;j<(rSize/16);j++) {
                sha256_init(&ctx);
                sha256_update(&ctx,hashbuf,SHA256_DIGEST_LENGTH);
                sha256_final(&ctx,hashbuf);
                memcpy(&randomness[j*16],hashbuf,16);
        }

}

static void H3(unsigned char finalhash[SHA256_DIGEST_LENGTH], int s, int es[NUM_ROUNDS]) {

	unsigned char hash[SHA256_DIGEST_LENGTH];
	int i = NUM_ROUNDS;
	int j;
	SHA256_CTX ctx;
	sha256_init(&ctx);
	sha256_update(&ctx, finalhash, SHA256_DIGEST_LENGTH);
	sha256_update(&ctx, (unsigned char *)&i, sizeof(int));
	sha256_update(&ctx, (unsigned char *)&s, sizeof(int));
	sha256_final(&ctx,hash);

	//Pick bits from hash
	memset(es,0,sizeof(int)*NUM_ROUNDS);
	int bitTracker = 0;
	while(s>0) {
		if(bitTracker >= 32) { //Generate new hash as we have run out of bits in the previous hash
			sha256_init(&ctx);
			sha256_update(&ctx, hash, sizeof(hash));
			sha256_update(&ctx, (unsigned char *)&s, sizeof(int));
			sha256_final(&ctx,hash);
			bitTracker = 0;
		}
		memcpy((unsigned char *)&i,&hash[bitTracker],4);
		if (i < 0)
			i *= -1;
		bitTracker+=4;
		i %= NUM_ROUNDS;
		if (bitTracker >= 32)
			continue;
		if (es[i] == 0)
		{
			memcpy((unsigned char *)&j,&hash[bitTracker],4);
			if (j < 0)
				j *= -1;
			bitTracker+=4;
			j %= (NUM_PARTIES-1);
			es[i] = j+1;
			s--;
		}
	}

}

// from Picnic Project
//
/* For an input bit b = 0 or 1, return the word of all b bits, i.e.,
 * extend(1) = 0xFFFFFFFFFFFFFFFF
 * extend(0) = 0x0000000000000000
 * Assumes inputs are always 0 or 1.  If this doesn't hold, add "& 1" to the
 * input.
 */
static uint32_t extend(uint8_t bit)
{
    return ~(bit - 1);
}


/* Get one bit from a byte array */
uint8_t getBit(const uint8_t* array, uint32_t bitNumber)
{
	return (array[bitNumber / 8] >> (7 - (bitNumber % 8))) & 0x01;
}

uint8_t getBit32(uint32_t value, uint32_t bitNumber)
{
	return (value>>(31-bitNumber))&0x01;
}

void setBit32(uint32_t * value, uint32_t bitNumber, uint8_t b)
{
	*value = (b&1)? (*value)|(1<<(31-bitNumber)) : (*value)&(~(1<<(31-bitNumber)));
}

uint8_t getParityFromWordArray(uint32_t * array, uint32_t size, uint32_t bitNumber)
{
	uint8_t parity = 0;

	for (int i=0;i<size;i++)
	{
		parity ^= getBit32(array[i],bitNumber);
	}
	return parity;
}


/* Get one bit from a 32-bit int array for all parties*/
uint32_t getBitFromWordArray(const uint32_t* array, uint32_t size, uint32_t bitNumber)
{
	if (size == 1)
	{
		return getBit32(array[0], bitNumber);
	}
	else
	{
		return getBit32(array[size-1], bitNumber) | (getBitFromWordArray(array,size-1,bitNumber)<<1);
	}
	
}

/* Set a specific bit in a byte array to a given value */
void setBit(uint8_t* bytes, uint32_t bitNumber, uint8_t val)
{
	bytes[bitNumber / 8] = (bytes[bitNumber >> 3]
				& ~(1 << (7 - (bitNumber % 8)))) | (val << (7 - (bitNumber % 8)));
}

static uint32_t parity32(uint32_t x)
{
	uint32_t y = x ^ (x >> 1);

	y ^= (y >> 2);
	y ^= (y >> 4);
	y ^= (y >> 8);
	y ^= (y >> 16);
	return y & 1;
}

static uint32_t int32ToWord(uint32_t x[NUM_PARTIES], int posn)
{
	uint32_t shares;

	for (size_t i = 0; i < NUM_PARTIES;i++) // NUM_PARTIES = 32 
	{
		uint8_t bit = getBit32(x[i],posn);
		setBit32(&shares,i,bit);
	}
	return shares;

}

static uint32_t tapesToWord(unsigned char * randomness[NUM_PARTIES],int * randCount)
{
	uint32_t shares;

	for (size_t i = 0; i < NUM_PARTIES;i++) // NUM_PARTIES = 32 
	{
		uint8_t bit = getBit(randomness[i],*randCount);
		setBit32(&shares,i,bit);
	}
	*randCount += 1;

	return shares;  
}

static void mpc_RIGHTROTATE(uint32_t x[NUM_PARTIES], int j, uint32_t z[NUM_PARTIES]) {

	for (int i=0; i < NUM_PARTIES;i++)
		z[i] = RIGHTROTATE(x[i], j);
}

static void mpc_LEFTROTATE(uint32_t x[NUM_PARTIES], int j, uint32_t z[NUM_PARTIES]) {

	for (int i=0; i < NUM_PARTIES;i++)
		z[i] = LEFTROTATE(x[i], j);
}

static void mpc_RIGHTSHIFT(uint32_t x[NUM_PARTIES], int j, uint32_t z[NUM_PARTIES]) {
	for (int i=0; i < NUM_PARTIES;i++)
		z[i] = x[i] >> j;
}

static void mpc_NEGATE(uint32_t x[NUM_PARTIES], uint32_t z[NUM_PARTIES]) 
{
	for (int i=0; i < NUM_PARTIES;i++)
		z[i] = ~x[i];
}

static void mpc_XOR(uint32_t x[NUM_PARTIES], uint32_t y[NUM_PARTIES], uint32_t z[NUM_PARTIES]) 
{
	for (int i=0; i < NUM_PARTIES;i++)
		z[i] = x[i] ^ y[i];
}

static void mpc_ENDIAN(uint32_t x[NUM_PARTIES], uint32_t z[NUM_PARTIES]) 
{
	for (int i=0; i < NUM_PARTIES;i++)
	{
		z[i] = (x[i] >> 24) + ((x[i] & 0x00FF0000)>> 8) + ((x[i] & 0x0000FF00) << 8) + ((x[i] & 0xFF) << 24) ;
	}
}

static int32_t aux_bit_AND(uint8_t mask_a, uint8_t mask_b, unsigned char* randomness[NUM_PARTIES], int *randCount)
{
	uint32_t output_mask = tapesToWord(randomness,randCount);

	size_t lastParty = NUM_PARTIES-1;
	uint32_t and_helper = tapesToWord(randomness,randCount);
	setBit32(&and_helper,NUM_PARTIES-1,0);
	uint8_t aux_bit = (mask_a & mask_b) ^ parity32(and_helper);
	setBit(randomness[lastParty], *randCount-1,aux_bit);

	return output_mask;
} 	

static void aux_AND(uint32_t x[NUM_PARTIES], uint32_t y[NUM_PARTIES], uint32_t z[NUM_PARTIES], unsigned char *randomness[NUM_PARTIES], int* randCount) 
{
	uint8_t mask_a,mask_b;
	uint32_t output_mask; // NUM_PARTIES=32

	for (int i = 0; i < 32;i++) 
	{
		mask_a = getParityFromWordArray(x,NUM_PARTIES,i);  
		mask_b = getParityFromWordArray(y,NUM_PARTIES,i);  

		output_mask = aux_bit_AND(mask_a,mask_b,randomness,randCount);

		for (int j = (NUM_PARTIES-1); j >= 0 ; j--)
		{
			setBit32(&z[j],i,output_mask & 0x01);
			output_mask>>=1;
		}
	}


}

static void aux_ADD(uint32_t x[NUM_PARTIES], uint32_t y[NUM_PARTIES], uint32_t z[NUM_PARTIES], unsigned char *randomness[NUM_PARTIES], int* randCount) {

	uint32_t aANDb, prev_carry = 0;
	uint32_t carry[NUM_PARTIES] = {0};
	uint8_t mask_a, mask_b;

	// sum = x ^ y ^ c
	// carry = ((x ^ c) & (y ^ c)) ^ c
	memset(carry,0,sizeof(uint32_t)*NUM_PARTIES);
	for (int i = 31; i > 0; i--)
	{
		prev_carry = getBitFromWordArray(carry,NUM_PARTIES,i);
		mask_a = parity32(getBitFromWordArray(x,NUM_PARTIES,i) ^ prev_carry);  
		mask_b = parity32(getBitFromWordArray(y,NUM_PARTIES,i) ^ prev_carry);  

		aANDb = aux_bit_AND(mask_a,mask_b,randomness,randCount);
		aANDb ^= prev_carry;
		{
			for (int j = (NUM_PARTIES-1); j >= 0; j--)
			{
				setBit32(&carry[j],i-1,(aANDb & 0x01));
				aANDb>>=1;
			}
		}
	}

	for (int i=0;i<NUM_PARTIES;i++)
		z[i] = x[i]^y[i]^carry[i];


}

static void aux_OR(uint32_t x[NUM_PARTIES], uint32_t y[NUM_PARTIES], uint32_t z[NUM_PARTIES], unsigned char *randomness[NUM_PARTIES], int* randCount) {

	uint32_t t0[NUM_PARTIES];
	uint32_t t1[NUM_PARTIES];
	uint32_t t2[NUM_PARTIES];

	mpc_NEGATE(x, t0);
	mpc_NEGATE(y, t1);
	aux_AND(t0, t1, t2, randomness, randCount);
	mpc_NEGATE(t2, z);
}

static void aux_MAJ(uint32_t a[NUM_PARTIES], uint32_t b[NUM_PARTIES], uint32_t c[NUM_PARTIES], uint32_t z[NUM_PARTIES], unsigned char * randomness[NUM_PARTIES], int* randCount) {
	uint32_t t0[NUM_PARTIES];
	uint32_t t1[NUM_PARTIES];

	mpc_XOR(a, b, t0);
	mpc_XOR(a, c, t1);
	aux_AND(t0, t1, z, randomness, randCount);
	mpc_XOR(z, a, z);
}


static void aux_CH(uint32_t e[NUM_PARTIES], uint32_t f[NUM_PARTIES], uint32_t g[NUM_PARTIES], uint32_t z[NUM_PARTIES], unsigned char * randomness[NUM_PARTIES], int* randCount) {
	uint32_t t0[NUM_PARTIES]; 

	//e & (f^g) ^ g
	mpc_XOR(f,g,t0);
	aux_AND(e,t0,t0, randomness, randCount);
	mpc_XOR(t0,g,z);

}

static void mpc_F(uint32_t x1[NUM_PARTIES], uint32_t x2[NUM_PARTIES], uint32_t x3[NUM_PARTIES], uint32_t z[NUM_PARTIES]) {

	uint32_t t0[NUM_PARTIES];
	mpc_XOR(x1,x2,t0);
	mpc_XOR(t0,x3,z);
}

static void aux_G(uint32_t x1[NUM_PARTIES], uint32_t x2[NUM_PARTIES], uint32_t x3[NUM_PARTIES], uint32_t z[NUM_PARTIES], unsigned char *randomness[NUM_PARTIES], int* randCount) {
	uint32_t t0[NUM_PARTIES];
	uint32_t t1[NUM_PARTIES];
	uint32_t t2[NUM_PARTIES];

	aux_AND(x1, x2, t0, randomness, randCount);
	mpc_NEGATE(x1,t1);

	aux_AND(t1, x3, t2, randomness, randCount);
	aux_OR(t0, t2, z, randomness, randCount);

}

static void aux_H(uint32_t x1[NUM_PARTIES], uint32_t x2[NUM_PARTIES], uint32_t x3[NUM_PARTIES], uint32_t z[NUM_PARTIES], unsigned char *randomness[NUM_PARTIES], int * randCount) {
	uint32_t t0[NUM_PARTIES];
	uint32_t t1[NUM_PARTIES];

	mpc_NEGATE(x2,t0);

	aux_OR(x1, t0, t1, randomness, randCount);

	mpc_XOR(t1,x3,z);
}

static void aux_I(uint32_t x1[NUM_PARTIES], uint32_t x2[NUM_PARTIES], uint32_t x3[NUM_PARTIES], uint32_t z[NUM_PARTIES], unsigned char *randomness[NUM_PARTIES], int * randCount) {
	uint32_t t0[NUM_PARTIES];
	uint32_t t1[NUM_PARTIES];
	uint32_t t2[NUM_PARTIES];

	aux_AND(x1, x3, t0, randomness, randCount);
	mpc_NEGATE(x3,t1);

	aux_AND(x2, t1, t2, randomness, randCount);
	aux_OR(t0, t2, z, randomness, randCount);
}

static void aux_J(uint32_t x1[NUM_PARTIES], uint32_t x2[NUM_PARTIES], uint32_t x3[NUM_PARTIES], uint32_t z[NUM_PARTIES], unsigned char *randomness[NUM_PARTIES], int * randCount) {
	uint32_t t0[NUM_PARTIES];
	uint32_t t1[NUM_PARTIES];

	mpc_NEGATE(x3,t0);

	aux_OR(x2, t0, t1, randomness, randCount);

	mpc_XOR(t1,x1,z);
}

static void aux_FF(uint32_t a[NUM_PARTIES], uint32_t b[NUM_PARTIES], uint32_t c[NUM_PARTIES], uint32_t d[NUM_PARTIES], uint32_t e[NUM_PARTIES], uint32_t x[NUM_PARTIES], uint32_t s, unsigned char *randomness[NUM_PARTIES], int* randCount) {
	uint32_t t0[NUM_PARTIES];
	uint32_t t1[NUM_PARTIES];
	uint32_t t2[NUM_PARTIES];
	uint32_t t3[NUM_PARTIES];

	mpc_F(b,c,d,t0);

	aux_ADD(t0, x, t1, randomness, randCount);
	aux_ADD(t1, a, t2, randomness, randCount);

	mpc_LEFTROTATE(t2,s,t3);

	aux_ADD(t3, e, a, randomness, randCount);

	mpc_LEFTROTATE(c,10,c);
}

static void aux_GG(uint32_t a[NUM_PARTIES], uint32_t b[NUM_PARTIES], uint32_t c[NUM_PARTIES], uint32_t d[NUM_PARTIES], uint32_t e[NUM_PARTIES], uint32_t x[NUM_PARTIES], uint32_t s, uint32_t C, unsigned char *randomness[NUM_PARTIES], int* randCount) {
        uint32_t t0[NUM_PARTIES];
        uint32_t t1[NUM_PARTIES];
        uint32_t t2[NUM_PARTIES];
        uint32_t t3[NUM_PARTIES];
        uint32_t t4[NUM_PARTIES];

	aux_G(b, c, d, t0, randomness, randCount);

	aux_ADD(t0, x, t1, randomness, randCount);
	for (int i = 0; i < NUM_PARTIES; i++)
		t0[i] = C;

	aux_ADD(t1, t0, t2, randomness, randCount);
	aux_ADD(t2, a, t3, randomness, randCount);

	mpc_LEFTROTATE(t3,s,t4);

	aux_ADD(t4, e, a, randomness, randCount);

	mpc_LEFTROTATE(c,10,c);
}

static void aux_HH(uint32_t a[NUM_PARTIES], uint32_t b[NUM_PARTIES], uint32_t c[NUM_PARTIES], uint32_t d[NUM_PARTIES], uint32_t e[NUM_PARTIES], uint32_t x[NUM_PARTIES], uint32_t s, uint32_t C, unsigned char *randomness[NUM_PARTIES], int* randCount) {
        uint32_t t0[NUM_PARTIES];
        uint32_t t1[NUM_PARTIES];
        uint32_t t2[NUM_PARTIES];
        uint32_t t3[NUM_PARTIES];
        uint32_t t4[NUM_PARTIES];

	aux_H(b, c, d, t0, randomness, randCount);

	aux_ADD(t0, x, t1, randomness, randCount);
	for (int i = 0; i < NUM_PARTIES; i++)
		t0[i] = C;

	aux_ADD(t1, t0, t2, randomness, randCount);
	aux_ADD(t2, a, t3, randomness, randCount);

	mpc_LEFTROTATE(t3,s,t4);

	aux_ADD(t4, e, a, randomness, randCount);

	mpc_LEFTROTATE(c,10,c);
}

static void aux_II(uint32_t a[NUM_PARTIES], uint32_t b[NUM_PARTIES], uint32_t c[NUM_PARTIES], uint32_t d[NUM_PARTIES], uint32_t e[NUM_PARTIES], uint32_t x[NUM_PARTIES], uint32_t s, uint32_t C, unsigned char *randomness[NUM_PARTIES], int* randCount) {
        uint32_t t0[NUM_PARTIES];
        uint32_t t1[NUM_PARTIES];
        uint32_t t2[NUM_PARTIES];
        uint32_t t3[NUM_PARTIES];
        uint32_t t4[NUM_PARTIES];

	aux_I(b, c, d, t0, randomness, randCount);

	aux_ADD(t0, x, t1, randomness, randCount);
	for (int i = 0; i < NUM_PARTIES; i++)
		t0[i] = C;

	aux_ADD(t1, t0, t2, randomness, randCount);
	aux_ADD(t2, a, t3, randomness, randCount);

	mpc_LEFTROTATE(t3,s,t4);

	aux_ADD(t4, e, a, randomness, randCount);

	mpc_LEFTROTATE(c,10,c);
}

static void aux_JJ(uint32_t a[NUM_PARTIES], uint32_t b[NUM_PARTIES], uint32_t c[NUM_PARTIES], uint32_t d[NUM_PARTIES], uint32_t e[NUM_PARTIES], uint32_t x[NUM_PARTIES], uint32_t s, uint32_t C, unsigned char *randomness[NUM_PARTIES], int* randCount) {
        uint32_t t0[NUM_PARTIES];
        uint32_t t1[NUM_PARTIES];
        uint32_t t2[NUM_PARTIES];
        uint32_t t3[NUM_PARTIES];
        uint32_t t4[NUM_PARTIES];

	aux_J(b, c, d, t0, randomness, randCount);

	aux_ADD(t0, x, t1, randomness, randCount);
	for (int i = 0; i < NUM_PARTIES; i++)
		t0[i] = C;

	aux_ADD(t1, t0, t2, randomness, randCount);
	aux_ADD(t2, a, t3, randomness, randCount);

	mpc_LEFTROTATE(t3,s,t4);

	aux_ADD(t4, e, a, randomness, randCount);

	mpc_LEFTROTATE(c,10,c);
}

static int computeAuxTape(unsigned char *randomness[NUM_PARTIES],unsigned char shares[NUM_PARTIES][SHA256_INPUTS], unsigned char ripeshares[NUM_PARTIES][32])
{
	int randCount = 0;

	uint32_t w[64][NUM_PARTIES];

	memset(w,0,sizeof(int32_t)*64*NUM_PARTIES);
	for (int i = 0; i < NUM_PARTIES; i++) {
		for (int j = 0; j < 16; j++) {
			w[j][i] = (shares[i][j * 4] << 24) | (shares[i][j * 4 + 1] << 16)
							| (shares[i][j * 4 + 2] << 8) | shares[i][j * 4 + 3];
		}
	}

	uint32_t s0[NUM_PARTIES], s1[NUM_PARTIES];
	uint32_t t0[NUM_PARTIES], t1[NUM_PARTIES];
	for (int j = 16; j < 64; j++) {
		//s0[i] = RIGHTROTATE(w[i][j-15],7) ^ RIGHTROTATE(w[i][j-15],18) ^ (w[i][j-15] >> 3);
		mpc_RIGHTROTATE(w[j-15], 7, t0);

		mpc_RIGHTROTATE(w[j-15], 18, t1);
		mpc_XOR(t0, t1, t0);
		mpc_RIGHTSHIFT(w[j-15], 3, t1);
		mpc_XOR(t0, t1, s0);

		//s1[i] = RIGHTROTATE(w[i][j-2],17) ^ RIGHTROTATE(w[i][j-2],19) ^ (w[i][j-2] >> 10);
		mpc_RIGHTROTATE(w[j-2], 17, t0);
		mpc_RIGHTROTATE(w[j-2], 19, t1);

		mpc_XOR(t0, t1, t0);
		mpc_RIGHTSHIFT(w[j-2], 10, t1);
		mpc_XOR(t0, t1, s1);
		//w[i][j] = w[i][j-16]+s0[i]+w[i][j-7]+s1[i];
		aux_ADD(w[j-16], s0, t1, randomness, &randCount);
		aux_ADD(w[j-7], t1, t1, randomness, &randCount);
		aux_ADD(t1, s1, w[j], randomness, &randCount);

	}

	uint32_t a[NUM_PARTIES];
	uint32_t b[NUM_PARTIES];
	uint32_t c[NUM_PARTIES];
	uint32_t d[NUM_PARTIES];
	uint32_t e[NUM_PARTIES];
	uint32_t f[NUM_PARTIES];
	uint32_t g[NUM_PARTIES];
	uint32_t h[NUM_PARTIES];
	for (int i = 0; i < NUM_PARTIES;i++)
	{
		a[i] = hA[0];
		b[i] = hA[1];
		c[i] = hA[2];
		d[i] = hA[3];
		e[i] = hA[4];
		f[i] = hA[5];
		g[i] = hA[6];
		h[i] = hA[7];
	}

	uint32_t temp1[NUM_PARTIES], temp2[NUM_PARTIES], temp3[NUM_PARTIES], maj[NUM_PARTIES];

	for (int i = 0; i < 64; i++) {
		//s1 = RIGHTROTATE(e,6) ^ RIGHTROTATE(e,11) ^ RIGHTROTATE(e,25);
		mpc_RIGHTROTATE(e, 6, t0);
		mpc_RIGHTROTATE(e, 11, t1);
		mpc_XOR(t0, t1, t0);

		mpc_RIGHTROTATE(e, 25, t1);
		mpc_XOR(t0, t1, s1);


		//ch = (e & f) ^ ((~e) & g);
		//temp1 = h + s1 + CH(e,f,g) + k[i]+w[i];

		//t0 = h + s1

		aux_ADD(h, s1, t0, randomness, &randCount);


		aux_CH(e, f, g, t1, randomness, &randCount);

		//t1 = t0 + t1 (h+s1+ch)
		aux_ADD(t0, t1, t1, randomness, &randCount);

		for (int j = 0; j < NUM_PARTIES; j++)
			temp3[j] = k[i];	
		aux_ADD(t1, temp3, t1, randomness, &randCount);

		aux_ADD(t1, w[i], temp1, randomness, &randCount);

		//s0 = RIGHTROTATE(a,2) ^ RIGHTROTATE(a,13) ^ RIGHTROTATE(a,22);
		mpc_RIGHTROTATE(a, 2, t0);
		mpc_RIGHTROTATE(a, 13, t1);
		mpc_XOR(t0, t1, t0);
		mpc_RIGHTROTATE(a, 22, t1);
		mpc_XOR(t0, t1, s0);


		aux_MAJ(a, b, c, maj, randomness, &randCount);

		//temp2 = s0+maj;
		aux_ADD(s0, maj, temp2, randomness, &randCount);

		memcpy(h, g, sizeof(uint32_t) * NUM_PARTIES);
		memcpy(g, f, sizeof(uint32_t) * NUM_PARTIES);
		memcpy(f, e, sizeof(uint32_t) * NUM_PARTIES);
		//e = d+temp1;
		aux_ADD(d, temp1, e, randomness, &randCount);
		memcpy(d, c, sizeof(uint32_t) * NUM_PARTIES);
		memcpy(c, b, sizeof(uint32_t) * NUM_PARTIES);
		memcpy(b, a, sizeof(uint32_t) * NUM_PARTIES);
		//a = temp1+temp2;

		aux_ADD(temp1, temp2, a, randomness, &randCount);
	}
	uint32_t hHa[8][NUM_PARTIES];
	for (int i = 0;i < 8;i++)
	{
		for (int j = 0;j < NUM_PARTIES;j++)
			hHa[i][j] = hA[i];
	}
	aux_ADD(hHa[0], a, hHa[0], randomness, &randCount);
	aux_ADD(hHa[1], b, hHa[1], randomness, &randCount);
	aux_ADD(hHa[2], c, hHa[2], randomness, &randCount);
	aux_ADD(hHa[3], d, hHa[3], randomness, &randCount);
	aux_ADD(hHa[4], e, hHa[4], randomness, &randCount);
	aux_ADD(hHa[5], f, hHa[5], randomness, &randCount);
	aux_ADD(hHa[6], g, hHa[6], randomness, &randCount);
	aux_ADD(hHa[7], h, hHa[7], randomness, &randCount);

	// ripemd160

	uint32_t X[16][NUM_PARTIES];
	uint32_t buf[5][NUM_PARTIES];
	uint32_t aa[NUM_PARTIES];
	uint32_t bb[NUM_PARTIES];
	uint32_t cc[NUM_PARTIES];
	uint32_t dd[NUM_PARTIES];
	uint32_t ee[NUM_PARTIES];
	uint32_t aaa[NUM_PARTIES];
	uint32_t bbb[NUM_PARTIES];
	uint32_t ccc[NUM_PARTIES];
	uint32_t ddd[NUM_PARTIES];
	uint32_t eee[NUM_PARTIES];

	for (int i = 0; i < 8; i++)	
	{
		mpc_ENDIAN(hHa[i],X[i]);	
		for (int j = 0; j < NUM_PARTIES; j++)
			memcpy(&X[8+i][j],&ripeshares[j][i*4],4);
	}
	for (int i = 0; i < 5; i++)
		for (int j = 0; j < NUM_PARTIES; j++)
			buf[i][j] = hRIPE[i];

	for (int j = 0; j < NUM_PARTIES; j++)
	{
		aa[j] = aaa[j] = buf[0][j];
		bb[j] = bbb[j] = buf[1][j];
		cc[j] = ccc[j] = buf[2][j];
		dd[j] = ddd[j] = buf[3][j];
		ee[j] = eee[j] = buf[4][j];
	}

        // round 1
	aux_FF(aa, bb, cc, dd, ee, X[0], 11, randomness, &randCount);
	aux_FF(ee, aa, bb, cc, dd, X[1], 14, randomness, &randCount);
	aux_FF(dd, ee, aa, bb, cc, X[2], 15, randomness, &randCount);
	aux_FF(cc, dd, ee, aa, bb, X[3], 12, randomness, &randCount);
	aux_FF(bb, cc, dd, ee, aa, X[4], 5, randomness, &randCount);
	aux_FF(aa, bb, cc, dd, ee, X[5], 8, randomness, &randCount);
	aux_FF(ee, aa, bb, cc, dd, X[6], 7, randomness, &randCount);
	aux_FF(dd, ee, aa, bb, cc, X[7], 9, randomness, &randCount);
	aux_FF(cc, dd, ee, aa, bb, X[8], 11, randomness, &randCount);
	aux_FF(bb, cc, dd, ee, aa, X[9], 13, randomness, &randCount);
	aux_FF(aa, bb, cc, dd, ee, X[10], 14, randomness, &randCount);
	aux_FF(ee, aa, bb, cc, dd, X[11], 15, randomness, &randCount);
	aux_FF(dd, ee, aa, bb, cc, X[12], 6, randomness, &randCount);
	aux_FF(cc, dd, ee, aa, bb, X[13], 7, randomness, &randCount);
	aux_FF(bb, cc, dd, ee, aa, X[14], 9, randomness, &randCount);
	aux_FF(aa, bb, cc, dd, ee, X[15], 8, randomness, &randCount);
// round 2
	aux_GG(ee, aa, bb, cc, dd, X[7], 7, hG, randomness, &randCount);
	aux_GG(dd, ee, aa, bb, cc, X[4], 6, hG, randomness, &randCount);
	aux_GG(cc, dd, ee, aa, bb, X[13], 8, hG, randomness, &randCount);
	aux_GG(bb, cc, dd, ee, aa, X[1], 13, hG, randomness, &randCount);
	aux_GG(aa, bb, cc, dd, ee, X[10], 11, hG, randomness, &randCount);
	aux_GG(ee, aa, bb, cc, dd, X[6], 9, hG, randomness, &randCount);
	aux_GG(dd, ee, aa, bb, cc, X[15], 7, hG, randomness, &randCount);
	aux_GG(cc, dd, ee, aa, bb, X[3], 15, hG, randomness, &randCount);
	aux_GG(bb, cc, dd, ee, aa, X[12], 7, hG, randomness, &randCount);
	aux_GG(aa, bb, cc, dd, ee, X[0], 12, hG, randomness, &randCount);
	aux_GG(ee, aa, bb, cc, dd, X[9], 15, hG, randomness, &randCount);
	aux_GG(dd, ee, aa, bb, cc, X[5], 9, hG, randomness, &randCount);
	aux_GG(cc, dd, ee, aa, bb, X[2], 11, hG, randomness, &randCount);
	aux_GG(bb, cc, dd, ee, aa, X[14], 7, hG, randomness, &randCount);
	aux_GG(aa, bb, cc, dd, ee, X[11], 13, hG, randomness, &randCount);
	aux_GG(ee, aa, bb, cc, dd, X[8], 12, hG, randomness, &randCount);
// round 3
	aux_HH(dd, ee, aa, bb, cc, X[3], 11, hH, randomness, &randCount);
	aux_HH(cc, dd, ee, aa, bb, X[10], 13, hH, randomness, &randCount);
	aux_HH(bb, cc, dd, ee, aa, X[14], 6, hH, randomness, &randCount);
	aux_HH(aa, bb, cc, dd, ee, X[4], 7, hH, randomness, &randCount);
	aux_HH(ee, aa, bb, cc, dd, X[9], 14, hH, randomness, &randCount);
	aux_HH(dd, ee, aa, bb, cc, X[15], 9, hH, randomness, &randCount);
	aux_HH(cc, dd, ee, aa, bb, X[8], 13, hH, randomness, &randCount);
	aux_HH(bb, cc, dd, ee, aa, X[1], 15, hH, randomness, &randCount);
	aux_HH(aa, bb, cc, dd, ee, X[2], 14, hH, randomness, &randCount);
	aux_HH(ee, aa, bb, cc, dd, X[7], 8, hH, randomness, &randCount);
	aux_HH(dd, ee, aa, bb, cc, X[0], 13, hH, randomness, &randCount);
	aux_HH(cc, dd, ee, aa, bb, X[6], 6, hH, randomness, &randCount);
	aux_HH(bb, cc, dd, ee, aa, X[13], 5, hH, randomness, &randCount);
	aux_HH(aa, bb, cc, dd, ee, X[11], 12, hH, randomness, &randCount);
	aux_HH(ee, aa, bb, cc, dd, X[5], 7, hH, randomness, &randCount);
	aux_HH(dd, ee, aa, bb, cc, X[12], 5, hH, randomness, &randCount);
// round 4
	aux_II(cc, dd, ee, aa, bb, X[1], 11, hI, randomness, &randCount);
	aux_II(bb, cc, dd, ee, aa, X[9], 12, hI, randomness, &randCount);
	aux_II(aa, bb, cc, dd, ee, X[11], 14, hI, randomness, &randCount);
	aux_II(ee, aa, bb, cc, dd, X[10], 15, hI, randomness, &randCount);
	aux_II(dd, ee, aa, bb, cc, X[0], 14, hI, randomness, &randCount);
	aux_II(cc, dd, ee, aa, bb, X[8], 15, hI, randomness, &randCount);
	aux_II(bb, cc, dd, ee, aa, X[12], 9, hI, randomness, &randCount);
	aux_II(aa, bb, cc, dd, ee, X[4], 8, hI, randomness, &randCount);
	aux_II(ee, aa, bb, cc, dd, X[13], 9, hI, randomness, &randCount);
	aux_II(dd, ee, aa, bb, cc, X[3], 14, hI, randomness, &randCount);
	aux_II(cc, dd, ee, aa, bb, X[7], 5, hI, randomness, &randCount);
	aux_II(bb, cc, dd, ee, aa, X[15], 6, hI, randomness, &randCount);
	aux_II(aa, bb, cc, dd, ee, X[14], 8, hI, randomness, &randCount);
	aux_II(ee, aa, bb, cc, dd, X[5], 6, hI, randomness, &randCount);
	aux_II(dd, ee, aa, bb, cc, X[6], 5, hI, randomness, &randCount);
	aux_II(cc, dd, ee, aa, bb, X[2], 12, hI, randomness, &randCount);
// round 5
	aux_JJ(bb, cc, dd, ee, aa, X[4], 9, hJ, randomness, &randCount);
	aux_JJ(aa, bb, cc, dd, ee, X[0], 15, hJ, randomness, &randCount);
	aux_JJ(ee, aa, bb, cc, dd, X[5], 5, hJ, randomness, &randCount);
	aux_JJ(dd, ee, aa, bb, cc, X[9], 11, hJ, randomness, &randCount);
	aux_JJ(cc, dd, ee, aa, bb, X[7], 6, hJ, randomness, &randCount);
	aux_JJ(bb, cc, dd, ee, aa, X[12], 8, hJ, randomness, &randCount);
	aux_JJ(aa, bb, cc, dd, ee, X[2], 13, hJ, randomness, &randCount);
	aux_JJ(ee, aa, bb, cc, dd, X[10], 12, hJ, randomness, &randCount);
	aux_JJ(dd, ee, aa, bb, cc, X[14], 5, hJ, randomness, &randCount);
	aux_JJ(cc, dd, ee, aa, bb, X[1], 12, hJ, randomness, &randCount);
	aux_JJ(bb, cc, dd, ee, aa, X[3], 13, hJ, randomness, &randCount);
	aux_JJ(aa, bb, cc, dd, ee, X[8], 14, hJ, randomness, &randCount);
	aux_JJ(ee, aa, bb, cc, dd, X[11], 11, hJ, randomness, &randCount);
	aux_JJ(dd, ee, aa, bb, cc, X[6], 8, hJ, randomness, &randCount);
	aux_JJ(cc, dd, ee, aa, bb, X[15], 5, hJ, randomness, &randCount);
	aux_JJ(bb, cc, dd, ee, aa, X[13], 6, hJ, randomness, &randCount);

// round 1
	aux_JJ(aaa, bbb, ccc, ddd, eee, X[5], 8, hJJ, randomness, &randCount);
	aux_JJ(eee, aaa, bbb, ccc, ddd, X[14], 9, hJJ, randomness, &randCount);
	aux_JJ(ddd, eee, aaa, bbb, ccc, X[7], 9, hJJ, randomness, &randCount);
	aux_JJ(ccc, ddd, eee, aaa, bbb, X[0], 11, hJJ, randomness, &randCount);
	aux_JJ(bbb, ccc, ddd, eee, aaa, X[9], 13, hJJ, randomness, &randCount);
	aux_JJ(aaa, bbb, ccc, ddd, eee, X[2], 15, hJJ, randomness, &randCount);
	aux_JJ(eee, aaa, bbb, ccc, ddd, X[11], 15, hJJ, randomness, &randCount);
	aux_JJ(ddd, eee, aaa, bbb, ccc, X[4], 5, hJJ, randomness, &randCount);
	aux_JJ(ccc, ddd, eee, aaa, bbb, X[13], 7, hJJ, randomness, &randCount);
	aux_JJ(bbb, ccc, ddd, eee, aaa, X[6], 7, hJJ, randomness, &randCount);
	aux_JJ(aaa, bbb, ccc, ddd, eee, X[15], 8, hJJ, randomness, &randCount);
	aux_JJ(eee, aaa, bbb, ccc, ddd, X[8], 11, hJJ, randomness, &randCount);
	aux_JJ(ddd, eee, aaa, bbb, ccc, X[1], 14, hJJ, randomness, &randCount);
	aux_JJ(ccc, ddd, eee, aaa, bbb, X[10], 14, hJJ, randomness, &randCount);
	aux_JJ(bbb, ccc, ddd, eee, aaa, X[3], 12, hJJ, randomness, &randCount);
	aux_JJ(aaa, bbb, ccc, ddd, eee, X[12], 6, hJJ, randomness, &randCount);
// round 2
	aux_II(eee, aaa, bbb, ccc, ddd, X[6], 9, hII, randomness, &randCount);
	aux_II(ddd, eee, aaa, bbb, ccc, X[11], 13, hII, randomness, &randCount);
	aux_II(ccc, ddd, eee, aaa, bbb, X[3], 15, hII, randomness, &randCount);
	aux_II(bbb, ccc, ddd, eee, aaa, X[7], 7, hII, randomness, &randCount);
	aux_II(aaa, bbb, ccc, ddd, eee, X[0], 12, hII, randomness, &randCount);
	aux_II(eee, aaa, bbb, ccc, ddd, X[13], 8, hII, randomness, &randCount);
	aux_II(ddd, eee, aaa, bbb, ccc, X[5], 9, hII, randomness, &randCount);
	aux_II(ccc, ddd, eee, aaa, bbb, X[10], 11, hII, randomness, &randCount);
	aux_II(bbb, ccc, ddd, eee, aaa, X[14], 7, hII, randomness, &randCount);
	aux_II(aaa, bbb, ccc, ddd, eee, X[15], 7, hII, randomness, &randCount);
	aux_II(eee, aaa, bbb, ccc, ddd, X[8], 12, hII, randomness, &randCount);
	aux_II(ddd, eee, aaa, bbb, ccc, X[12], 7, hII, randomness, &randCount);
	aux_II(ccc, ddd, eee, aaa, bbb, X[4], 6, hII, randomness, &randCount);
	aux_II(bbb, ccc, ddd, eee, aaa, X[9], 15, hII, randomness, &randCount);
	aux_II(aaa, bbb, ccc, ddd, eee, X[1], 13, hII, randomness, &randCount);
	aux_II(eee, aaa, bbb, ccc, ddd, X[2], 11, hII, randomness, &randCount);
// round 3
	aux_HH(ddd, eee, aaa, bbb, ccc, X[15], 9, hHH, randomness, &randCount);
	aux_HH(ccc, ddd, eee, aaa, bbb, X[5], 7, hHH, randomness, &randCount);
	aux_HH(bbb, ccc, ddd, eee, aaa, X[1], 15, hHH, randomness, &randCount);
	aux_HH(aaa, bbb, ccc, ddd, eee, X[3], 11, hHH, randomness, &randCount);
	aux_HH(eee, aaa, bbb, ccc, ddd, X[7], 8, hHH, randomness, &randCount);
	aux_HH(ddd, eee, aaa, bbb, ccc, X[14], 6, hHH, randomness, &randCount);
	aux_HH(ccc, ddd, eee, aaa, bbb, X[6], 6, hHH, randomness, &randCount);
	aux_HH(bbb, ccc, ddd, eee, aaa, X[9], 14, hHH, randomness, &randCount);
	aux_HH(aaa, bbb, ccc, ddd, eee, X[11], 12, hHH, randomness, &randCount);
	aux_HH(eee, aaa, bbb, ccc, ddd, X[8], 13, hHH, randomness, &randCount);
	aux_HH(ddd, eee, aaa, bbb, ccc, X[12], 5, hHH, randomness, &randCount);
	aux_HH(ccc, ddd, eee, aaa, bbb, X[2], 14, hHH, randomness, &randCount);
	aux_HH(bbb, ccc, ddd, eee, aaa, X[10], 13, hHH, randomness, &randCount);
	aux_HH(aaa, bbb, ccc, ddd, eee, X[0], 13, hHH, randomness, &randCount);
	aux_HH(eee, aaa, bbb, ccc, ddd, X[4], 7, hHH, randomness, &randCount);
	aux_HH(ddd, eee, aaa, bbb, ccc, X[13], 5, hHH, randomness, &randCount);
// round 4
	aux_GG(ccc, ddd, eee, aaa, bbb, X[8], 15, hGG, randomness, &randCount);
	aux_GG(bbb, ccc, ddd, eee, aaa, X[6], 5, hGG, randomness, &randCount);
	aux_GG(aaa, bbb, ccc, ddd, eee, X[4], 8, hGG, randomness, &randCount);
	aux_GG(eee, aaa, bbb, ccc, ddd, X[1], 11, hGG, randomness, &randCount);
	aux_GG(ddd, eee, aaa, bbb, ccc, X[3], 14, hGG, randomness, &randCount);
	aux_GG(ccc, ddd, eee, aaa, bbb, X[11], 14, hGG, randomness, &randCount);
	aux_GG(bbb, ccc, ddd, eee, aaa, X[15], 6, hGG, randomness, &randCount);
	aux_GG(aaa, bbb, ccc, ddd, eee, X[0], 14, hGG, randomness, &randCount);
	aux_GG(eee, aaa, bbb, ccc, ddd, X[5], 6, hGG, randomness, &randCount);
	aux_GG(ddd, eee, aaa, bbb, ccc, X[12], 9, hGG, randomness, &randCount);
	aux_GG(ccc, ddd, eee, aaa, bbb, X[2], 12, hGG, randomness, &randCount);
	aux_GG(bbb, ccc, ddd, eee, aaa, X[13], 9, hGG, randomness, &randCount);
	aux_GG(aaa, bbb, ccc, ddd, eee, X[9], 12, hGG, randomness, &randCount);
	aux_GG(eee, aaa, bbb, ccc, ddd, X[7], 5, hGG, randomness, &randCount);
	aux_GG(ddd, eee, aaa, bbb, ccc, X[10], 15, hGG, randomness, &randCount);
	aux_GG(ccc, ddd, eee, aaa, bbb, X[14], 8, hGG, randomness, &randCount);
// round 5
	aux_FF(bbb, ccc, ddd, eee, aaa, X[12], 8, randomness, &randCount);
	aux_FF(aaa, bbb, ccc, ddd, eee, X[15], 5, randomness, &randCount);
	aux_FF(eee, aaa, bbb, ccc, ddd, X[10], 12, randomness, &randCount);
	aux_FF(ddd, eee, aaa, bbb, ccc, X[4], 9, randomness, &randCount);
	aux_FF(ccc, ddd, eee, aaa, bbb, X[1], 12, randomness, &randCount);
	aux_FF(bbb, ccc, ddd, eee, aaa, X[5], 5, randomness, &randCount);
	aux_FF(aaa, bbb, ccc, ddd, eee, X[8], 14, randomness, &randCount);
	aux_FF(eee, aaa, bbb, ccc, ddd, X[7], 6, randomness, &randCount);
	aux_FF(ddd, eee, aaa, bbb, ccc, X[6], 8, randomness, &randCount);
	aux_FF(ccc, ddd, eee, aaa, bbb, X[2], 13, randomness, &randCount);
	aux_FF(bbb, ccc, ddd, eee, aaa, X[13], 6, randomness, &randCount);
	aux_FF(aaa, bbb, ccc, ddd, eee, X[14], 5, randomness, &randCount);
	aux_FF(eee, aaa, bbb, ccc, ddd, X[0], 15, randomness, &randCount);
	aux_FF(ddd, eee, aaa, bbb, ccc, X[3], 13, randomness, &randCount);
	aux_FF(ccc, ddd, eee, aaa, bbb, X[9], 11, randomness, &randCount);
	aux_FF(bbb, ccc, ddd, eee, aaa, X[11], 11, randomness, &randCount);

	aux_ADD(cc,buf[1],t0,randomness,&randCount);
	aux_ADD(t0,ddd,t1,randomness,&randCount);
	aux_ADD(dd,buf[2],t0,randomness,&randCount);
	aux_ADD(t0,eee,buf[1],randomness,&randCount);
	aux_ADD(ee,buf[3],t0,randomness,&randCount);
	aux_ADD(t0,aaa,buf[2],randomness,&randCount);
	aux_ADD(aa,buf[4],t0,randomness,&randCount);
	aux_ADD(t0,bbb,buf[3],randomness,&randCount);
	aux_ADD(bb,buf[0],t0,randomness,&randCount);
	aux_ADD(t0,ccc,buf[4],randomness,&randCount);
//	printf("computeAuxTape: randCount %d\n",randCount);

	return 0;
	

}


static int mpc_AND_verify(uint32_t x_state, uint32_t y_state, uint32_t * z_state, uint32_t x[NUM_PARTIES], uint32_t y[NUM_PARTIES], uint32_t z[NUM_PARTIES], unsigned char *randomness[NUM_PARTIES], int* randCount, View views[NUM_PARTIES], int* countY, int unopenParty) 
{
	uint8_t a, b;
	uint32_t mask_a, mask_b;
	uint32_t aANDb, and_helper;
	uint32_t s_shares;

	for (int i=0;i < 32;i++)
	{
		aANDb = tapesToWord(randomness,randCount);
		and_helper = tapesToWord(randomness,randCount);
		a = getBit32(x_state,i);
		b = getBit32(y_state,i);
		mask_a = getBitFromWordArray(x,NUM_PARTIES,i);
		mask_b = getBitFromWordArray(y,NUM_PARTIES,i);


		s_shares = (extend(a) & mask_b) ^ (extend(b) & mask_a) ^ and_helper ^ aANDb;
		setBit32(&s_shares,unopenParty,getBit32(views[unopenParty].y[*countY],i));

		for (int j = (NUM_PARTIES-1); j >= 0 ; j--)
		{
			setBit32(&z[j],i,aANDb & 0x01);
			aANDb >>=1;
		}
		setBit32(z_state,i,parity32(s_shares)^(a&b));
		// write s_shares to view									                 
		for (int j = (NUM_PARTIES-1); j >= 0 ; j--)
		{
			setBit32(&views[j].y[*countY],i,s_shares & 0x01);
			s_shares >>=1;
		}
	}

	*countY+=1;
	return 0;
}

static void mpc_AND(uint32_t x_state, uint32_t y_state, uint32_t * z_state, uint32_t x[NUM_PARTIES], uint32_t y[NUM_PARTIES], uint32_t z[NUM_PARTIES], unsigned char *randomness[NUM_PARTIES], int* randCount, View views[NUM_PARTIES], int* countY) 
{
	uint8_t a, b;
	uint32_t mask_a, mask_b;
	uint32_t aANDb, and_helper;
	uint32_t s_shares;

	for (int i=0;i < 32;i++)
	{
		aANDb = tapesToWord(randomness,randCount);
		and_helper = tapesToWord(randomness,randCount);
		a = getBit32(x_state,i);
		b = getBit32(y_state,i);
		mask_a = getBitFromWordArray(x,NUM_PARTIES,i);
		mask_b = getBitFromWordArray(y,NUM_PARTIES,i);


		s_shares = (extend(a) & mask_b) ^ (extend(b) & mask_a) ^ and_helper ^ aANDb;
		for (int j = (NUM_PARTIES-1); j >= 0 ; j--)
		{
			setBit32(&z[j],i,aANDb & 0x01);
			aANDb >>=1;
		}
		setBit32(z_state,i,parity32(s_shares)^(a&b));
		// write s_shares to view									                 
		for (int j = (NUM_PARTIES-1); j >= 0 ; j--)
		{
			setBit32(&views[j].y[*countY],i,s_shares & 0x01);
			s_shares >>=1;
		}
	}

	*countY+=1;
}

static int mpc_ADD_verify(uint32_t x_state, uint32_t y_state, uint32_t * z_state, uint32_t x[NUM_PARTIES], uint32_t y[NUM_PARTIES], uint32_t z[NUM_PARTIES], unsigned char *randomness[NUM_PARTIES], int* randCount, View views[NUM_PARTIES], int* countY, int unopenParty) {

// sum = x^y^c
// carry = ((x^c)&(y^c))^c
//
	uint32_t aANDb, and_helper;
	uint32_t mask_a, mask_b, mask_c = 0;
	uint32_t carry[NUM_PARTIES] = {0};
	uint8_t a, b, c = 0;
	uint32_t s_shares;
	uint32_t val;

	*z_state = 0;
	for (int i=31; i>=0; i--)
	{
		a = getBit32(x_state,i) ^ c;
		b = getBit32(y_state,i) ^ c;
		setBit32(z_state,i,a^b^c);
		if (i>0)
		{
			mask_c = getBitFromWordArray(carry,NUM_PARTIES,i);
			mask_a = getBitFromWordArray(x,NUM_PARTIES,i) ^ mask_c;
			mask_b = getBitFromWordArray(y,NUM_PARTIES,i) ^ mask_c;

			aANDb = tapesToWord(randomness,randCount);
			and_helper = tapesToWord(randomness,randCount);
			s_shares = (extend(a) & mask_b) ^ (extend(b) & mask_a) ^ and_helper ^ aANDb;
			setBit32(&s_shares,unopenParty,getBit32(views[unopenParty].y[*countY],i));
			c = parity32(s_shares)^(a&b)^c;
			aANDb ^= mask_c;

			for (int j = (NUM_PARTIES-1); j >= 0 ; j--)
			{
				setBit32(&views[j].y[*countY],i,s_shares & 0x01);
				s_shares >>=1;
				setBit32(&carry[j],i-1,aANDb & 0x01);
				aANDb >>=1;
			}
		}
	}
	*countY+= 1;
	for (int i=0;i<NUM_PARTIES;i++)
		z[i] = x[i]^y[i]^carry[i];

	return 0;
}

static void mpc_ADD(uint32_t x_state, uint32_t y_state, uint32_t * z_state, uint32_t x[NUM_PARTIES], uint32_t y[NUM_PARTIES], uint32_t z[NUM_PARTIES], unsigned char* randomness[NUM_PARTIES], int* randCount, View views[NUM_PARTIES], int* countY) {

// sum = x^y^c
// carry = ((x^c)&(y^c))^c
//
	uint32_t aANDb, and_helper;
	uint32_t mask_a, mask_b, mask_c = 0;
	uint32_t carry[NUM_PARTIES] = {0};
	uint8_t a, b, c = 0;
	uint32_t s_shares;
	uint32_t val;

	*z_state = 0;
	for (int i=31; i>=0; i--)
	{
		a = getBit32(x_state,i) ^ c;
		b = getBit32(y_state,i) ^ c;
		setBit32(z_state,i,a^b^c);
		if (i>0)
		{
			mask_c = getBitFromWordArray(carry,NUM_PARTIES,i);
			mask_a = getBitFromWordArray(x,NUM_PARTIES,i) ^ mask_c;
			mask_b = getBitFromWordArray(y,NUM_PARTIES,i) ^ mask_c;

			aANDb = tapesToWord(randomness,randCount);
			and_helper = tapesToWord(randomness,randCount);
			s_shares = (extend(a) & mask_b) ^ (extend(b) & mask_a) ^ and_helper ^ aANDb;
			c = parity32(s_shares)^(a&b)^c;
			aANDb ^= mask_c;

			for (int j = (NUM_PARTIES-1); j >= 0 ; j--)
			{
				setBit32(&views[j].y[*countY],i,s_shares & 0x01);
				s_shares >>=1;
				setBit32(&carry[j],i-1,aANDb & 0x01);
				aANDb >>=1;
			}
		}
	}
	*countY+= 1;
	for (int i=0;i<NUM_PARTIES;i++)
		z[i] = x[i]^y[i]^carry[i];

}


static int mpc_OR_verify(uint32_t x_state, uint32_t y_state, uint32_t * z_state, uint32_t x[NUM_PARTIES], uint32_t y[NUM_PARTIES], uint32_t z[NUM_PARTIES], unsigned char* randomness[NUM_PARTIES], int* randCount, View views[NUM_PARTIES], int* countY, int unopenParty) {
	uint32_t t0[NUM_PARTIES];
	uint32_t t1[NUM_PARTIES];
	uint32_t t2[NUM_PARTIES];
	uint32_t t0_state, t1_state, t2_state;

	mpc_NEGATE(x, t0);
	t0_state = ~x_state ;

	mpc_NEGATE(y, t1);
	t1_state = ~y_state;

	if (mpc_AND_verify(t0_state, t1_state, &t2_state, t0, t1, t2, randomness, randCount, views, countY, unopenParty))
		return -1;

	mpc_NEGATE(t2, z);
	*z_state = ~t2_state;

	return 0;
}

static void mpc_OR(uint32_t x_state, uint32_t y_state, uint32_t * z_state, uint32_t x[NUM_PARTIES], uint32_t y[NUM_PARTIES], uint32_t z[NUM_PARTIES], unsigned char* randomness[NUM_PARTIES], int* randCount, View views[NUM_PARTIES], int* countY) {
	uint32_t t0[NUM_PARTIES];
	uint32_t t1[NUM_PARTIES];
	uint32_t t2[NUM_PARTIES];
	uint32_t t0_state, t1_state, t2_state;

	mpc_NEGATE(x, t0);
	t0_state = ~x_state ;

	mpc_NEGATE(y, t1);
	t1_state = ~y_state;

	mpc_AND(t0_state, t1_state, &t2_state, t0, t1, t2, randomness, randCount, views, countY);

	mpc_NEGATE(t2, z);
	*z_state = ~t2_state;
}


static int mpc_MAJ_verify(uint32_t a_state, uint32_t b_state, uint32_t c_state, uint32_t * z_state, uint32_t a[NUM_PARTIES], uint32_t b[NUM_PARTIES], uint32_t c[NUM_PARTIES], uint32_t z[NUM_PARTIES], unsigned char* randomness[NUM_PARTIES], int* randCount, View views[NUM_PARTIES], int* countY, int unopenParty) {
	uint32_t t0[NUM_PARTIES];
	uint32_t t1[NUM_PARTIES];
	uint32_t t0_state, t1_state;

	mpc_XOR(a, b, t0);
	t0_state = a_state ^ b_state;

	mpc_XOR(a, c, t1);
	t1_state = a_state ^ c_state;

	if (mpc_AND_verify(t0_state, t1_state, z_state, t0, t1, z, randomness, randCount, views, countY, unopenParty))
		return -1;
	mpc_XOR(z, a, z);
	*z_state = a_state ^ (*z_state);
	return 0;
}

static void mpc_MAJ(uint32_t a_state, uint32_t b_state, uint32_t c_state, uint32_t * z_state, uint32_t a[NUM_PARTIES], uint32_t b[NUM_PARTIES], uint32_t c[NUM_PARTIES], uint32_t z[NUM_PARTIES], unsigned char *randomness[NUM_PARTIES], int* randCount, View views[NUM_PARTIES], int* countY) {
	uint32_t t0[NUM_PARTIES];
	uint32_t t1[NUM_PARTIES];
	uint32_t t0_state, t1_state;

	mpc_XOR(a, b, t0);
	t0_state = a_state ^ b_state;

	mpc_XOR(a, c, t1);
	t1_state = a_state ^ c_state;

	mpc_AND(t0_state, t1_state, z_state, t0, t1, z, randomness, randCount, views, countY);
	mpc_XOR(z, a, z);
	*z_state = a_state ^ (*z_state);
}


static int mpc_CH_verify(uint32_t e_state, uint32_t f_state, uint32_t g_state, uint32_t *z_state, uint32_t e[NUM_PARTIES], uint32_t f[NUM_PARTIES], uint32_t g[NUM_PARTIES], uint32_t z[NUM_PARTIES], unsigned char* randomness[NUM_PARTIES], int* randCount, View views[NUM_PARTIES], int* countY, int unopenParty) {
	uint32_t t0[NUM_PARTIES];
	uint32_t t0_state;

	//e & (f^g) ^ g
	mpc_XOR(f,g,t0);
	t0_state = f_state ^ g_state;

	if (mpc_AND_verify(e_state, t0_state, &t0_state, e,t0,t0, randomness, randCount, views, countY, unopenParty))
		return -1;
	mpc_XOR(t0,g,z);
	*z_state = t0_state ^ g_state;

	return 0;
}

static void mpc_CH(uint32_t e_state, uint32_t f_state, uint32_t g_state, uint32_t *z_state, uint32_t e[NUM_PARTIES], uint32_t f[NUM_PARTIES], uint32_t g[NUM_PARTIES], uint32_t z[NUM_PARTIES], unsigned char *randomness[NUM_PARTIES], int* randCount, View views[NUM_PARTIES], int* countY) {
	uint32_t t0[NUM_PARTIES];
	uint32_t t0_state;

	//e & (f^g) ^ g
	mpc_XOR(f,g,t0);
	t0_state = f_state ^ g_state;

	mpc_AND(e_state, t0_state, &t0_state, e,t0,t0, randomness, randCount, views, countY);
	mpc_XOR(t0,g,z);
	*z_state = t0_state ^ g_state;

}


static int mpc_G_verify(uint32_t x1_state, uint32_t x2_state, uint32_t x3_state, uint32_t *z_state, uint32_t x1[NUM_PARTIES], uint32_t x2[NUM_PARTIES], uint32_t x3[NUM_PARTIES], uint32_t z[NUM_PARTIES], unsigned char *randomness[NUM_PARTIES], int* randCount, View views[NUM_PARTIES], int* countY, int unopenParty) {
	uint32_t t0[NUM_PARTIES];
	uint32_t t1[NUM_PARTIES];
	uint32_t t2[NUM_PARTIES];
	uint32_t t0_state, t1_state, t2_state;

	if (mpc_AND_verify(x1_state, x2_state, &t0_state, x1, x2, t0, randomness, randCount, views, countY, unopenParty))
		return -1;
	mpc_NEGATE(x1,t1);
	t1_state = ~x1_state;

	if (mpc_AND_verify(t1_state, x3_state, &t2_state, t1, x3, t2, randomness, randCount, views, countY, unopenParty))
		return -1;
	if (mpc_OR_verify(t0_state, t2_state, z_state, t0, t2, z, randomness, randCount, views, countY, unopenParty))
		return -1;
	return 0;

}

static void mpc_G(uint32_t x1_state, uint32_t x2_state, uint32_t x3_state, uint32_t *z_state, uint32_t x1[NUM_PARTIES], uint32_t x2[NUM_PARTIES], uint32_t x3[NUM_PARTIES], uint32_t z[NUM_PARTIES], unsigned char *randomness[NUM_PARTIES], int* randCount, View views[NUM_PARTIES], int* countY) {
	uint32_t t0[NUM_PARTIES];
	uint32_t t1[NUM_PARTIES];
	uint32_t t2[NUM_PARTIES];
	uint32_t t0_state, t1_state, t2_state;

	mpc_AND(x1_state, x2_state, &t0_state, x1, x2, t0, randomness, randCount, views, countY);
	mpc_NEGATE(x1,t1);
	t1_state = ~x1_state;

	mpc_AND(t1_state, x3_state, &t2_state, t1, x3, t2, randomness, randCount, views, countY);
	mpc_OR(t0_state, t2_state, z_state, t0, t2, z, randomness, randCount, views, countY);

}

static int mpc_H_verify(uint32_t x1_state, uint32_t x2_state, uint32_t x3_state, uint32_t *z_state, uint32_t x1[NUM_PARTIES], uint32_t x2[NUM_PARTIES], uint32_t x3[NUM_PARTIES], uint32_t z[NUM_PARTIES], unsigned char *randomness[NUM_PARTIES], int* randCount, View views[NUM_PARTIES], int* countY, int unopenParty) {
	uint32_t t0[NUM_PARTIES];
	uint32_t t1[NUM_PARTIES];
	uint32_t t0_state, t1_state;

	mpc_NEGATE(x2,t0);
	t0_state = ~x2_state;

	if (mpc_OR_verify(x1_state, t0_state, &t1_state, x1, t0, t1, randomness, randCount, views, countY, unopenParty))
		return -1;

	mpc_XOR(t1,x3,z);
	*z_state = t1_state ^ x3_state;
	return 0;
}

static void mpc_H(uint32_t x1_state, uint32_t x2_state, uint32_t x3_state, uint32_t *z_state, uint32_t x1[NUM_PARTIES], uint32_t x2[NUM_PARTIES], uint32_t x3[NUM_PARTIES], uint32_t z[NUM_PARTIES], unsigned char *randomness[NUM_PARTIES], int* randCount, View views[NUM_PARTIES], int* countY) {
	uint32_t t0[NUM_PARTIES];
	uint32_t t1[NUM_PARTIES];
	uint32_t t0_state, t1_state;

	mpc_NEGATE(x2,t0);
	t0_state = ~x2_state;

	mpc_OR(x1_state, t0_state, &t1_state, x1, t0, t1, randomness, randCount, views, countY);

	mpc_XOR(t1,x3,z);
	*z_state = t1_state ^ x3_state;
}

static int mpc_I_verify(uint32_t x1_state, uint32_t x2_state, uint32_t x3_state, uint32_t *z_state, uint32_t x1[NUM_PARTIES], uint32_t x2[NUM_PARTIES], uint32_t x3[NUM_PARTIES], uint32_t z[NUM_PARTIES], unsigned char *randomness[NUM_PARTIES], int* randCount, View views[NUM_PARTIES], int* countY, int unopenParty) {
	uint32_t t0[NUM_PARTIES];
	uint32_t t1[NUM_PARTIES];
	uint32_t t2[NUM_PARTIES];
	uint32_t t0_state, t1_state, t2_state;

	if (mpc_AND_verify(x1_state, x3_state, &t0_state, x1, x3, t0, randomness, randCount, views, countY, unopenParty))
		return -1;
	mpc_NEGATE(x3,t1);
	t1_state = ~x3_state;

	if (mpc_AND_verify(x2_state, t1_state, &t2_state, x2, t1, t2, randomness, randCount, views, countY, unopenParty))
		return -1;
	if (mpc_OR_verify(t0_state, t2_state, z_state, t0, t2, z, randomness, randCount, views, countY, unopenParty))
		return -1;
	return 0;
}

static void mpc_I(uint32_t x1_state, uint32_t x2_state, uint32_t x3_state, uint32_t *z_state, uint32_t x1[NUM_PARTIES], uint32_t x2[NUM_PARTIES], uint32_t x3[NUM_PARTIES], uint32_t z[NUM_PARTIES], unsigned char *randomness[NUM_PARTIES], int* randCount, View views[NUM_PARTIES], int* countY) {
	uint32_t t0[NUM_PARTIES];
	uint32_t t1[NUM_PARTIES];
	uint32_t t2[NUM_PARTIES];
	uint32_t t0_state, t1_state, t2_state;

	mpc_AND(x1_state, x3_state, &t0_state, x1, x3, t0, randomness, randCount, views, countY);
	mpc_NEGATE(x3,t1);
	t1_state = ~x3_state;

	mpc_AND(x2_state, t1_state, &t2_state, x2, t1, t2, randomness, randCount, views, countY);
	mpc_OR(t0_state, t2_state, z_state, t0, t2, z, randomness, randCount, views, countY);
}

static int mpc_J_verify(uint32_t x1_state, uint32_t x2_state, uint32_t x3_state, uint32_t *z_state, uint32_t x1[NUM_PARTIES], uint32_t x2[NUM_PARTIES], uint32_t x3[NUM_PARTIES], uint32_t z[NUM_PARTIES], unsigned char *randomness[NUM_PARTIES], int* randCount, View views[NUM_PARTIES], int* countY, int unopenParty) {
	uint32_t t0[NUM_PARTIES];
	uint32_t t1[NUM_PARTIES];
	uint32_t t0_state, t1_state;

	mpc_NEGATE(x3,t0);
	t0_state = ~x3_state;

	if (mpc_OR_verify(x2_state, t0_state, &t1_state, x2, t0, t1, randomness, randCount, views, countY, unopenParty))
		return -1;

	mpc_XOR(t1,x1,z);
	*z_state = t1_state ^ x1_state;
	return 0;
}

static void mpc_J(uint32_t x1_state, uint32_t x2_state, uint32_t x3_state, uint32_t *z_state, uint32_t x1[NUM_PARTIES], uint32_t x2[NUM_PARTIES], uint32_t x3[NUM_PARTIES], uint32_t z[NUM_PARTIES], unsigned char *randomness[NUM_PARTIES], int* randCount, View views[NUM_PARTIES], int* countY) {
	uint32_t t0[NUM_PARTIES];
	uint32_t t1[NUM_PARTIES];
	uint32_t t0_state, t1_state;

	mpc_NEGATE(x3,t0);
	t0_state = ~x3_state;

	mpc_OR(x2_state, t0_state, &t1_state, x2, t0, t1, randomness, randCount, views, countY);

	mpc_XOR(t1,x1,z);
	*z_state = t1_state ^ x1_state;
}

static int mpc_FF_verify(uint32_t *a_state, uint32_t b_state, uint32_t *c_state, uint32_t d_state, uint32_t e_state, uint32_t x_state, uint32_t s, uint32_t a[NUM_PARTIES], uint32_t b[NUM_PARTIES], uint32_t c[NUM_PARTIES], uint32_t d[NUM_PARTIES], uint32_t e[NUM_PARTIES], uint32_t x[NUM_PARTIES], unsigned char *randomness[NUM_PARTIES], int* randCount, View views[NUM_PARTIES], int* countY, int unopenParty) {
	uint32_t t0[NUM_PARTIES];
	uint32_t t1[NUM_PARTIES];
	uint32_t t2[NUM_PARTIES];
	uint32_t t3[NUM_PARTIES];
	uint32_t t0_state, t1_state, t2_state, t3_state;

	mpc_F(b,c,d,t0);
	t0_state = b_state ^ (*c_state) ^ d_state;

	if (mpc_ADD_verify(t0_state, x_state, &t1_state, t0, x, t1, randomness, randCount, views, countY, unopenParty))
		return -1;
	if (mpc_ADD_verify(t1_state, *a_state, &t2_state, t1, a, t2, randomness, randCount, views, countY, unopenParty))
		return -1;

	mpc_LEFTROTATE(t2,s,t3);
	t3_state = LEFTROTATE(t2_state,s);

	if (mpc_ADD_verify(t3_state, e_state, a_state, t3, e, a, randomness, randCount, views, countY, unopenParty))
		return -1;

	mpc_LEFTROTATE(c,10,c);
	*c_state = LEFTROTATE(*c_state,10);
	return 0;
}

static void mpc_FF(uint32_t *a_state, uint32_t b_state, uint32_t *c_state, uint32_t d_state, uint32_t e_state, uint32_t x_state, uint32_t s, uint32_t a[NUM_PARTIES], uint32_t b[NUM_PARTIES], uint32_t c[NUM_PARTIES], uint32_t d[NUM_PARTIES], uint32_t e[NUM_PARTIES], uint32_t x[NUM_PARTIES], unsigned char *randomness[NUM_PARTIES], int* randCount, View views[NUM_PARTIES], int* countY) {
	uint32_t t0[NUM_PARTIES];
	uint32_t t1[NUM_PARTIES];
	uint32_t t2[NUM_PARTIES];
	uint32_t t3[NUM_PARTIES];
	uint32_t t0_state, t1_state, t2_state, t3_state;

	mpc_F(b,c,d,t0);
	t0_state = b_state ^ (*c_state) ^ d_state;

	mpc_ADD(t0_state, x_state, &t1_state, t0, x, t1, randomness, randCount, views, countY);
	mpc_ADD(t1_state, *a_state, &t2_state, t1, a, t2, randomness, randCount, views, countY);

	mpc_LEFTROTATE(t2,s,t3);
	t3_state = LEFTROTATE(t2_state,s);

	mpc_ADD(t3_state, e_state, a_state, t3, e, a, randomness, randCount, views, countY);

	mpc_LEFTROTATE(c,10,c);
	*c_state = LEFTROTATE(*c_state,10);
}

static int mpc_GG_verify(uint32_t *a_state, uint32_t b_state, uint32_t *c_state, uint32_t d_state, uint32_t e_state, uint32_t x_state, uint32_t s, uint32_t C, uint32_t a[NUM_PARTIES], uint32_t b[NUM_PARTIES], uint32_t c[NUM_PARTIES], uint32_t d[NUM_PARTIES], uint32_t e[NUM_PARTIES], uint32_t x[NUM_PARTIES], unsigned char *randomness[NUM_PARTIES], int* randCount, View views[NUM_PARTIES], int* countY, int unopenParty) {
	uint32_t t0[NUM_PARTIES];
	uint32_t t1[NUM_PARTIES];
	uint32_t t2[NUM_PARTIES];
	uint32_t t3[NUM_PARTIES];
	uint32_t t4[NUM_PARTIES];
	uint32_t t0_state, t1_state, t2_state, t3_state, t4_state;

	if (mpc_G_verify(b_state, *c_state, d_state, &t0_state, b, c, d, t0, randomness, randCount, views, countY, unopenParty))
		return -1;

	if (mpc_ADD_verify(t0_state, x_state, &t1_state, t0, x, t1, randomness, randCount, views, countY, unopenParty))
		return -1;
	for (int i = 0; i < NUM_PARTIES; i++)
		t0[i] = C;
	t0_state = C;

	if (mpc_ADD_verify(t1_state, t0_state, &t2_state, t1, t0, t2, randomness, randCount, views, countY, unopenParty))
		return -1;
	if (mpc_ADD_verify(t2_state, *a_state, &t3_state, t2, a, t3, randomness, randCount, views, countY, unopenParty))
		return -1;

	mpc_LEFTROTATE(t3,s,t4);
	t4_state = LEFTROTATE(t3_state,s);

	if (mpc_ADD_verify(t4_state, e_state, a_state, t4, e, a, randomness, randCount, views, countY, unopenParty))
		return -1;

	mpc_LEFTROTATE(c,10,c);
	*c_state = LEFTROTATE(*c_state,10);
	return 0;
}

static void mpc_GG(uint32_t *a_state, uint32_t b_state, uint32_t *c_state, uint32_t d_state, uint32_t e_state, uint32_t x_state, uint32_t s, uint32_t C, uint32_t a[NUM_PARTIES], uint32_t b[NUM_PARTIES], uint32_t c[NUM_PARTIES], uint32_t d[NUM_PARTIES], uint32_t e[NUM_PARTIES], uint32_t x[NUM_PARTIES], unsigned char *randomness[NUM_PARTIES], int* randCount, View views[NUM_PARTIES], int* countY) {
	uint32_t t0[NUM_PARTIES];
	uint32_t t1[NUM_PARTIES];
	uint32_t t2[NUM_PARTIES];
	uint32_t t3[NUM_PARTIES];
	uint32_t t4[NUM_PARTIES];
	uint32_t t0_state, t1_state, t2_state, t3_state, t4_state;

	mpc_G(b_state, *c_state, d_state, &t0_state, b, c, d, t0, randomness, randCount, views, countY);

	mpc_ADD(t0_state, x_state, &t1_state, t0, x, t1, randomness, randCount, views, countY);
	for (int i = 0; i < NUM_PARTIES; i++)
		t0[i] = C;
	t0_state = C;

	mpc_ADD(t1_state, t0_state, &t2_state, t1, t0, t2, randomness, randCount, views, countY);
	mpc_ADD(t2_state, *a_state, &t3_state, t2, a, t3, randomness, randCount, views, countY);

	mpc_LEFTROTATE(t3,s,t4);
	t4_state = LEFTROTATE(t3_state,s);

	mpc_ADD(t4_state, e_state, a_state, t4, e, a, randomness, randCount, views, countY);

	mpc_LEFTROTATE(c,10,c);
	*c_state = LEFTROTATE(*c_state,10);
}

static int mpc_HH_verify(uint32_t *a_state, uint32_t b_state, uint32_t *c_state, uint32_t d_state, uint32_t e_state, uint32_t x_state, uint32_t s, uint32_t C, uint32_t a[NUM_PARTIES], uint32_t b[NUM_PARTIES], uint32_t c[NUM_PARTIES], uint32_t d[NUM_PARTIES], uint32_t e[NUM_PARTIES], uint32_t x[NUM_PARTIES], unsigned char *randomness[NUM_PARTIES], int* randCount, View views[NUM_PARTIES], int* countY, int unopenParty) {
	uint32_t t0[NUM_PARTIES];
	uint32_t t1[NUM_PARTIES];
	uint32_t t2[NUM_PARTIES];
	uint32_t t3[NUM_PARTIES];
	uint32_t t4[NUM_PARTIES];
	uint32_t t0_state, t1_state, t2_state, t3_state, t4_state;

	if (mpc_H_verify(b_state, *c_state, d_state, &t0_state, b, c, d, t0, randomness, randCount, views, countY, unopenParty))
		return -1;

	if (mpc_ADD_verify(t0_state, x_state, &t1_state, t0, x, t1, randomness, randCount, views, countY, unopenParty))
		return -1;
	for (int i = 0; i < NUM_PARTIES; i++)
		t0[i] = C;
	t0_state = C;

	if (mpc_ADD_verify(t1_state, t0_state, &t2_state, t1, t0, t2, randomness, randCount, views, countY, unopenParty))
		return -1;
	if (mpc_ADD_verify(t2_state, *a_state, &t3_state, t2, a, t3, randomness, randCount, views, countY, unopenParty))
		return -1;

	mpc_LEFTROTATE(t3,s,t4);
	t4_state = LEFTROTATE(t3_state,s);

	if (mpc_ADD_verify(t4_state, e_state, a_state, t4, e, a, randomness, randCount, views, countY, unopenParty))
		return -1;

	mpc_LEFTROTATE(c,10,c);
	*c_state = LEFTROTATE(*c_state,10);
	return 0;
}

static void mpc_HH(uint32_t *a_state, uint32_t b_state, uint32_t *c_state, uint32_t d_state, uint32_t e_state, uint32_t x_state, uint32_t s, uint32_t C, uint32_t a[NUM_PARTIES], uint32_t b[NUM_PARTIES], uint32_t c[NUM_PARTIES], uint32_t d[NUM_PARTIES], uint32_t e[NUM_PARTIES], uint32_t x[NUM_PARTIES], unsigned char *randomness[NUM_PARTIES], int* randCount, View views[NUM_PARTIES], int* countY) {
	uint32_t t0[NUM_PARTIES];
	uint32_t t1[NUM_PARTIES];
	uint32_t t2[NUM_PARTIES];
	uint32_t t3[NUM_PARTIES];
	uint32_t t4[NUM_PARTIES];
	uint32_t t0_state, t1_state, t2_state, t3_state, t4_state;

	mpc_H(b_state, *c_state, d_state, &t0_state, b, c, d, t0, randomness, randCount, views, countY);

	mpc_ADD(t0_state, x_state, &t1_state, t0, x, t1, randomness, randCount, views, countY);
	for (int i = 0; i < NUM_PARTIES; i++)
		t0[i] = C;
	t0_state = C;

	mpc_ADD(t1_state, t0_state, &t2_state, t1, t0, t2, randomness, randCount, views, countY);
	mpc_ADD(t2_state, *a_state, &t3_state, t2, a, t3, randomness, randCount, views, countY);

	mpc_LEFTROTATE(t3,s,t4);
	t4_state = LEFTROTATE(t3_state,s);

	mpc_ADD(t4_state, e_state, a_state, t4, e, a, randomness, randCount, views, countY);

	mpc_LEFTROTATE(c,10,c);
	*c_state = LEFTROTATE(*c_state,10);
}

static int mpc_II_verify(uint32_t *a_state, uint32_t b_state, uint32_t *c_state, uint32_t d_state, uint32_t e_state, uint32_t x_state, uint32_t s, uint32_t C, uint32_t a[NUM_PARTIES], uint32_t b[NUM_PARTIES], uint32_t c[NUM_PARTIES], uint32_t d[NUM_PARTIES], uint32_t e[NUM_PARTIES], uint32_t x[NUM_PARTIES], unsigned char *randomness[NUM_PARTIES], int* randCount, View views[NUM_PARTIES], int* countY, int unopenParty) {
	uint32_t t0[NUM_PARTIES];
	uint32_t t1[NUM_PARTIES];
	uint32_t t2[NUM_PARTIES];
	uint32_t t3[NUM_PARTIES];
	uint32_t t4[NUM_PARTIES];
	uint32_t t0_state, t1_state, t2_state, t3_state, t4_state;

	if (mpc_I_verify(b_state, *c_state, d_state, &t0_state, b, c, d, t0, randomness, randCount, views, countY, unopenParty))
		return -1;

	if (mpc_ADD_verify(t0_state, x_state, &t1_state, t0, x, t1, randomness, randCount, views, countY, unopenParty))
		return -1;
	for (int i = 0; i < NUM_PARTIES; i++)
		t0[i] = C;
	t0_state = C;

	if (mpc_ADD_verify(t1_state, t0_state, &t2_state, t1, t0, t2, randomness, randCount, views, countY, unopenParty))
		return -1;
	if (mpc_ADD_verify(t2_state, *a_state, &t3_state, t2, a, t3, randomness, randCount, views, countY, unopenParty))
		return -1;

	mpc_LEFTROTATE(t3,s,t4);
	t4_state = LEFTROTATE(t3_state,s);

	if (mpc_ADD_verify(t4_state, e_state, a_state, t4, e, a, randomness, randCount, views, countY, unopenParty))
		return -1;

	mpc_LEFTROTATE(c,10,c);
	*c_state = LEFTROTATE(*c_state,10);
	return 0;
}

static void mpc_II(uint32_t *a_state, uint32_t b_state, uint32_t *c_state, uint32_t d_state, uint32_t e_state, uint32_t x_state, uint32_t s, uint32_t C, uint32_t a[NUM_PARTIES], uint32_t b[NUM_PARTIES], uint32_t c[NUM_PARTIES], uint32_t d[NUM_PARTIES], uint32_t e[NUM_PARTIES], uint32_t x[NUM_PARTIES], unsigned char *randomness[NUM_PARTIES], int* randCount, View views[NUM_PARTIES], int* countY) {
	uint32_t t0[NUM_PARTIES];
	uint32_t t1[NUM_PARTIES];
	uint32_t t2[NUM_PARTIES];
	uint32_t t3[NUM_PARTIES];
	uint32_t t4[NUM_PARTIES];
	uint32_t t0_state, t1_state, t2_state, t3_state, t4_state;

	mpc_I(b_state, *c_state, d_state, &t0_state, b, c, d, t0, randomness, randCount, views, countY);

	mpc_ADD(t0_state, x_state, &t1_state, t0, x, t1, randomness, randCount, views, countY);
	for (int i = 0; i < NUM_PARTIES; i++)
		t0[i] = C;
	t0_state = C;

	mpc_ADD(t1_state, t0_state, &t2_state, t1, t0, t2, randomness, randCount, views, countY);
	mpc_ADD(t2_state, *a_state, &t3_state, t2, a, t3, randomness, randCount, views, countY);

	mpc_LEFTROTATE(t3,s,t4);
	t4_state = LEFTROTATE(t3_state,s);

	mpc_ADD(t4_state, e_state, a_state, t4, e, a, randomness, randCount, views, countY);

	mpc_LEFTROTATE(c,10,c);
	*c_state = LEFTROTATE(*c_state,10);
}

static int mpc_JJ_verify(uint32_t *a_state, uint32_t b_state, uint32_t *c_state, uint32_t d_state, uint32_t e_state, uint32_t x_state, uint32_t s, uint32_t C, uint32_t a[NUM_PARTIES], uint32_t b[NUM_PARTIES], uint32_t c[NUM_PARTIES], uint32_t d[NUM_PARTIES], uint32_t e[NUM_PARTIES], uint32_t x[NUM_PARTIES], unsigned char *randomness[NUM_PARTIES], int* randCount, View views[NUM_PARTIES], int* countY, int unopenParty) {
	uint32_t t0[NUM_PARTIES];
	uint32_t t1[NUM_PARTIES];
	uint32_t t2[NUM_PARTIES];
	uint32_t t3[NUM_PARTIES];
	uint32_t t4[NUM_PARTIES];
	uint32_t t0_state, t1_state, t2_state, t3_state, t4_state;

	if (mpc_I_verify(b_state, *c_state, d_state, &t0_state, b, c, d, t0, randomness, randCount, views, countY, unopenParty))
		return -1;

	if (mpc_ADD_verify(t0_state, x_state, &t1_state, t0, x, t1, randomness, randCount, views, countY, unopenParty))
		return -1;
	for (int i = 0; i < NUM_PARTIES; i++)
		t0[i] = C;
	t0_state = C;

	if (mpc_ADD_verify(t1_state, t0_state, &t2_state, t1, t0, t2, randomness, randCount, views, countY, unopenParty))
		return -1;
	if (mpc_ADD_verify(t2_state, *a_state, &t3_state, t2, a, t3, randomness, randCount, views, countY, unopenParty))
		return -1;

	mpc_LEFTROTATE(t3,s,t4);
	t4_state = LEFTROTATE(t3_state,s);

	if (mpc_ADD_verify(t4_state, e_state, a_state, t4, e, a, randomness, randCount, views, countY, unopenParty))
		return -1;

	mpc_LEFTROTATE(c,10,c);
	*c_state = LEFTROTATE(*c_state,10);
	return 0;
}

static void mpc_JJ(uint32_t *a_state, uint32_t b_state, uint32_t *c_state, uint32_t d_state, uint32_t e_state, uint32_t x_state, uint32_t s, uint32_t C, uint32_t a[NUM_PARTIES], uint32_t b[NUM_PARTIES], uint32_t c[NUM_PARTIES], uint32_t d[NUM_PARTIES], uint32_t e[NUM_PARTIES], uint32_t x[NUM_PARTIES], unsigned char *randomness[NUM_PARTIES], int* randCount, View views[NUM_PARTIES], int* countY) {
	uint32_t t0[NUM_PARTIES];
	uint32_t t1[NUM_PARTIES];
	uint32_t t2[NUM_PARTIES];
	uint32_t t3[NUM_PARTIES];
	uint32_t t4[NUM_PARTIES];
	uint32_t t0_state, t1_state, t2_state, t3_state, t4_state;

	mpc_J(b_state, *c_state, d_state, &t0_state, b, c, d, t0, randomness, randCount, views, countY);

	mpc_ADD(t0_state, x_state, &t1_state, t0, x, t1, randomness, randCount, views, countY);
	for (int i = 0; i < NUM_PARTIES; i++)
		t0[i] = C;
	t0_state = C;

	mpc_ADD(t1_state, t0_state, &t2_state, t1, t0, t2, randomness, randCount, views, countY);
	mpc_ADD(t2_state, *a_state, &t3_state, t2, a, t3, randomness, randCount, views, countY);

	mpc_LEFTROTATE(t3,s,t4);
	t4_state = LEFTROTATE(t3_state,s);

	mpc_ADD(t4_state, e_state, a_state, t4, e, a, randomness, randCount, views, countY);

	mpc_LEFTROTATE(c,10,c);
	*c_state = LEFTROTATE(*c_state,10);
}

static uint32_t consol(uint32_t array[NUM_PARTIES])
{
	uint32_t ret = 0;
	for (int i = 0; i<NUM_PARTIES;i++)
		ret ^= array[i];
	return ret;
}



static int mpc_compute(unsigned char masked_result[RIPEMD160_DIGEST_LENGTH], unsigned char masked_input[SHA256_INPUTS], unsigned char shares[NUM_PARTIES][SHA256_INPUTS], unsigned char ripeshares[NUM_PARTIES][32], unsigned char * inputs, int numBytes, unsigned char *randomness[NUM_PARTIES], View views[NUM_PARTIES], unsigned char party_result[NUM_PARTIES][RIPEMD160_DIGEST_LENGTH], int* countY) 
{

	if ((inputs) && (numBytes > 55))
	{	
		printf("Input too long, aborting!");
		return -1;
	}
	int randCount=0;

	uint32_t w_state[64] = {0};
	uint32_t w[64][NUM_PARTIES] = {0};
	memset(w,0,sizeof(int32_t)*64*NUM_PARTIES);
	memset(w_state,0,sizeof(int32_t)*64);

	for (int i = 0; i < NUM_PARTIES; i++) {
		for (int j = 0; j < 16; j++) {
			w[j][i] = (shares[i][j * 4] << 24) | (shares[i][j * 4 + 1] << 16)
							| (shares[i][j * 4 + 2] << 8) | shares[i][j * 4 + 3];
			w_state[j] ^= w[j][i];
		}
	}

	if (inputs) // prove
	{
		inputs[numBytes] = 0x80;
		inputs[62] = (numBytes *8) >> 8;
		inputs[63] = (numBytes * 8);
		for (int j = 0; j < 16; j++) {
			w_state[j] ^= (inputs[j * 4] << 24) | (inputs[j * 4 + 1] << 16)
								| (inputs[j * 4 + 2] << 8) | inputs[j * 4 + 3];
		}

		memcpy(masked_input, (unsigned char *) w_state, SHA256_INPUTS);
	}
	else // verify
		memcpy((unsigned char *)w_state,masked_input, SHA256_INPUTS);

	uint32_t s0[NUM_PARTIES], s1[NUM_PARTIES];
	uint32_t t0[NUM_PARTIES], t1[NUM_PARTIES];
	uint32_t s0_state, s1_state;
	uint32_t t0_state, t1_state;

	for (int j = 16; j < 64; j++) {
		//s0[i] = RIGHTROTATE(w[i][j-15],7) ^ RIGHTROTATE(w[i][j-15],18) ^ (w[i][j-15] >> 3);
		mpc_RIGHTROTATE(w[j-15], 7, t0);
		t0_state = RIGHTROTATE(w_state[j-15],7);
		mpc_RIGHTROTATE(w[j-15], 18, t1);
		t1_state = RIGHTROTATE(w_state[j-15],18);

		mpc_XOR(t0, t1, t0);
		t0_state = t0_state^t1_state;

		mpc_RIGHTSHIFT(w[j-15], 3, t1);
		t1_state = w_state[j-15] >> 3;

		mpc_XOR(t0, t1, s0);
		s0_state = t0_state^t1_state;

		//s1[i] = RIGHTROTATE(w[i][j-2],17) ^ RIGHTROTATE(w[i][j-2],19) ^ (w[i][j-2] >> 10);
		mpc_RIGHTROTATE(w[j-2], 17, t0);
		t0_state = RIGHTROTATE(w_state[j-2],17);

		mpc_RIGHTROTATE(w[j-2], 19, t1);
		t1_state = RIGHTROTATE(w_state[j-2],19);

		mpc_XOR(t0, t1, t0);
		t0_state = t0_state^t1_state;

		mpc_RIGHTSHIFT(w[j-2], 10, t1);
		t1_state = w_state[j-2] >> 10;

		mpc_XOR(t0, t1, s1);
		s1_state = t0_state^t1_state;
		//w[i][j] = w[i][j-16]+s0[i]+w[i][j-7]+s1[i];
		if (inputs)
		{
			mpc_ADD(w_state[j-16],s0_state,&t1_state,w[j-16], s0, t1, randomness, &randCount, views, countY);
			mpc_ADD(w_state[j-7],t1_state,&t1_state, w[j-7], t1, t1, randomness, &randCount, views, countY);
			mpc_ADD(t1_state, s1_state, &(w_state[j]), t1, s1, w[j], randomness, &randCount, views, countY);
		}
		else
		{
			if (mpc_ADD_verify(w_state[j-16],s0_state,&t1_state,w[j-16], s0, t1, randomness, &randCount, views, countY, numBytes))
				return -1;
			if (mpc_ADD_verify(w_state[j-7],t1_state,&t1_state, w[j-7], t1, t1, randomness, &randCount, views, countY, numBytes))
				return -1;
			if (mpc_ADD_verify(t1_state, s1_state, &(w_state[j]), t1, s1, w[j], randomness, &randCount, views, countY, numBytes))
				return -1;
		}

	}
	uint32_t a[NUM_PARTIES];
	uint32_t b[NUM_PARTIES];
	uint32_t c[NUM_PARTIES];
	uint32_t d[NUM_PARTIES];
	uint32_t e[NUM_PARTIES];
	uint32_t f[NUM_PARTIES];
	uint32_t g[NUM_PARTIES];
	uint32_t h[NUM_PARTIES];
	uint32_t a_state = hA[0];
	uint32_t b_state = hA[1];
	uint32_t c_state = hA[2];
	uint32_t d_state = hA[3];
	uint32_t e_state = hA[4];
	uint32_t f_state = hA[5];
	uint32_t g_state = hA[6];
	uint32_t h_state = hA[7];

	for (int i = 0; i < NUM_PARTIES; i++)
	{
		a[i] = hA[0];
		b[i] = hA[1];
		c[i] = hA[2];
		d[i] = hA[3];
		e[i] = hA[4];
		f[i] = hA[5];
		g[i] = hA[6];
		h[i] = hA[7];
	}

	uint32_t temp1[NUM_PARTIES], temp2[NUM_PARTIES], temp3[NUM_PARTIES], maj[NUM_PARTIES];
	uint32_t temp1_state, temp2_state, temp3_state, maj_state;
	for (int i = 0; i < 64; i++) {
		//s1 = RIGHTROTATE(e,6) ^ RIGHTROTATE(e,11) ^ RIGHTROTATE(e,25);
		mpc_RIGHTROTATE(e, 6, t0);
		t0_state = RIGHTROTATE(e_state,6);

		mpc_RIGHTROTATE(e, 11, t1);
		t1_state = RIGHTROTATE(e_state,11);

		mpc_XOR(t0, t1, t0);
		t0_state = t0_state^t1_state;

		mpc_RIGHTROTATE(e, 25, t1);
		t1_state = RIGHTROTATE(e_state,25);

		mpc_XOR(t0, t1, s1);
		s1_state = t0_state^t1_state;


		//ch = (e & f) ^ ((~e) & g);
		//temp1 = h + s1 + CH(e,f,g) + k[i]+w[i];

		//t0 = h + s1

		for (int j = 0; j < NUM_PARTIES;j++)
			temp3[j] = k[i];
		temp3_state = k[i];
		if (inputs)
		{
			mpc_ADD(h_state, s1_state, &t0_state, h, s1, t0, randomness, &randCount, views,countY);

			mpc_CH(e_state, f_state, g_state, &t1_state, e, f, g, t1, randomness, &randCount, views, countY);

		//t1 = t0 + t1 (h+s1+ch)
			mpc_ADD(t0_state, t1_state, &t1_state, t0, t1, t1, randomness, &randCount, views, countY);

			mpc_ADD(t1_state, temp3_state, &t1_state, t1,temp3, t1, randomness, &randCount, views, countY);

			mpc_ADD(t1_state, w_state[i], &temp1_state, t1, w[i], temp1, randomness, &randCount, views, countY);
		}
		else
		{
			if (mpc_ADD_verify(h_state, s1_state, &t0_state, h, s1, t0, randomness, &randCount, views,countY, numBytes) )
				return -1;

			if (mpc_CH_verify(e_state, f_state, g_state, &t1_state, e, f, g, t1, randomness, &randCount, views, countY, numBytes))
				return -1;

		//t1 = t0 + t1 (h+s1+ch)
			if (mpc_ADD_verify(t0_state, t1_state, &t1_state, t0, t1, t1, randomness, &randCount, views, countY, numBytes))
				return -1;

			if (mpc_ADD_verify(t1_state, temp3_state, &t1_state, t1,temp3, t1, randomness, &randCount, views, countY, numBytes))
				return -1;

			if (mpc_ADD_verify(t1_state, w_state[i], &temp1_state, t1, w[i], temp1, randomness, &randCount, views, countY, numBytes))
				return -1;

		}

		//s0 = RIGHTROTATE(a,2) ^ RIGHTROTATE(a,13) ^ RIGHTROTATE(a,22);
		mpc_RIGHTROTATE(a, 2, t0);
		t0_state = RIGHTROTATE(a_state,2);

		mpc_RIGHTROTATE(a, 13, t1);
		t1_state = RIGHTROTATE(a_state,13);

		mpc_XOR(t0, t1, t0);
		t0_state = t0_state^t1_state;

		mpc_RIGHTROTATE(a, 22, t1);
		t1_state = RIGHTROTATE(a_state,22);

		mpc_XOR(t0, t1, s0);
		s0_state = t0_state^t1_state;

		if (inputs)
		{
			mpc_MAJ(a_state, b_state, c_state, &maj_state, a, b, c, maj, randomness, &randCount, views, countY);

		//temp2 = s0+maj;
			mpc_ADD(s0_state, maj_state, &temp2_state, s0, maj, temp2, randomness, &randCount, views, countY);
		}
		else
		{
			if (mpc_MAJ_verify(a_state, b_state, c_state, &maj_state, a, b, c, maj, randomness, &randCount, views, countY, numBytes))
				return -1;
			if (mpc_ADD_verify(s0_state, maj_state, &temp2_state, s0, maj, temp2, randomness, &randCount, views, countY, numBytes))
				return -1;

		}

		memcpy(h,g,sizeof(uint32_t) * NUM_PARTIES);
		memcpy(g,f,sizeof(uint32_t) * NUM_PARTIES);
		memcpy(f,e,sizeof(uint32_t) * NUM_PARTIES);
		h_state = g_state;
		g_state = f_state;
		f_state = e_state;
		//e = d+temp1;
		if (inputs)
		{
			mpc_ADD(d_state, temp1_state, &e_state, d, temp1, e, randomness, &randCount, views, countY);
		}
		else
		{
			if (mpc_ADD_verify(d_state, temp1_state, &e_state, d, temp1, e, randomness, &randCount, views, countY, numBytes))
				return -1;
		}
		memcpy(d,c,sizeof(uint32_t) * NUM_PARTIES);
		memcpy(c,b,sizeof(uint32_t) * NUM_PARTIES);
		memcpy(b,a,sizeof(uint32_t) * NUM_PARTIES);
		d_state = c_state;
		c_state = b_state;
		b_state = a_state;
		//a = temp1+temp2;

		if (inputs)
		{
			mpc_ADD(temp1_state, temp2_state, &a_state, temp1, temp2, a, randomness, &randCount, views, countY);
		}
		else
		{
			if (mpc_ADD_verify(temp1_state, temp2_state, &a_state, temp1, temp2, a, randomness, &randCount, views, countY, numBytes))
				return -1;
		}

	}
	uint32_t hHa[8][NUM_PARTIES];
	uint32_t hHa_state[8];
	for (int i = 0;i < 8;i++)
	{
		hHa_state[i] = hA[i];
		for (int j = 0; j < NUM_PARTIES;j++)
			hHa[i][j] = hA[i];
	}
	if (inputs)
	{
		mpc_ADD(hHa_state[0], a_state, &hHa_state[0], hHa[0], a, hHa[0], randomness, &randCount, views, countY);
		mpc_ADD(hHa_state[1], b_state, &hHa_state[1], hHa[1], b, hHa[1], randomness, &randCount, views, countY);
		mpc_ADD(hHa_state[2], c_state, &hHa_state[2], hHa[2], c, hHa[2], randomness, &randCount, views, countY);
		mpc_ADD(hHa_state[3], d_state, &hHa_state[3], hHa[3], d, hHa[3], randomness, &randCount, views, countY);
		mpc_ADD(hHa_state[4], e_state, &hHa_state[4], hHa[4], e, hHa[4], randomness, &randCount, views, countY);
		mpc_ADD(hHa_state[5], f_state, &hHa_state[5], hHa[5], f, hHa[5], randomness, &randCount, views, countY);
		mpc_ADD(hHa_state[6], g_state, &hHa_state[6], hHa[6], g, hHa[6], randomness, &randCount, views, countY);
		mpc_ADD(hHa_state[7], h_state, &hHa_state[7], hHa[7], h, hHa[7], randomness, &randCount, views, countY);
	}
	else
	{
		if (mpc_ADD_verify(hHa_state[0], a_state, &hHa_state[0], hHa[0], a, hHa[0], randomness, &randCount, views, countY, numBytes))
			return -1;
		if (mpc_ADD_verify(hHa_state[1], b_state, &hHa_state[1], hHa[1], b, hHa[1], randomness, &randCount, views, countY, numBytes))
			return -1;
		if (mpc_ADD_verify(hHa_state[2], c_state, &hHa_state[2], hHa[2], c, hHa[2], randomness, &randCount, views, countY, numBytes))
			return -1;
		if (mpc_ADD_verify(hHa_state[3], d_state, &hHa_state[3], hHa[3], d, hHa[3], randomness, &randCount, views, countY, numBytes))
			return -1;
		if (mpc_ADD_verify(hHa_state[4], e_state, &hHa_state[4], hHa[4], e, hHa[4], randomness, &randCount, views, countY, numBytes))
			return -1;
		if (mpc_ADD_verify(hHa_state[5], f_state, &hHa_state[5], hHa[5], f, hHa[5], randomness, &randCount, views, countY, numBytes))
			return -1;
		if (mpc_ADD_verify(hHa_state[6], g_state, &hHa_state[6], hHa[6], g, hHa[6], randomness, &randCount, views, countY, numBytes))
			return -1;
		if (mpc_ADD_verify(hHa_state[7], h_state, &hHa_state[7], hHa[7], h, hHa[7], randomness, &randCount, views, countY, numBytes))
			return -1;
	}

	if (VERBOSE)
	{
		unsigned char temp;
		fprintf(stderr,"after sha256: ");
		for (int i = 0; i < 8; i++)
		{
			temp = hHa_state[i]>>24;
			fprintf(stderr,"%02X",temp);
			temp = hHa_state[i]>>16;
			fprintf(stderr,"%02X",temp);
			temp = hHa_state[i]>>8;
			fprintf(stderr,"%02X",temp);
			temp = hHa_state[i];
			fprintf(stderr,"%02X",temp);
		}
		fprintf(stderr,"\n");
	}	
	// ripemd160

	uint32_t X[16][NUM_PARTIES];
	uint32_t buf[5][NUM_PARTIES];
	unsigned char back8[32];
	uint32_t aa[NUM_PARTIES];
	uint32_t bb[NUM_PARTIES];
	uint32_t cc[NUM_PARTIES];
	uint32_t dd[NUM_PARTIES];
	uint32_t ee[NUM_PARTIES];
	uint32_t aaa[NUM_PARTIES];
	uint32_t bbb[NUM_PARTIES];
	uint32_t ccc[NUM_PARTIES];
	uint32_t ddd[NUM_PARTIES];
	uint32_t eee[NUM_PARTIES];
	uint32_t X_state[16];
	uint32_t buf_state[5];
	uint32_t aa_state,bb_state,cc_state,dd_state,ee_state;
	uint32_t aaa_state,bbb_state,ccc_state,ddd_state,eee_state;

	memset(back8,0,32);
	back8[0] = 0x80;
	back8[25] = 256 >> 8;

	memset(X_state,0,16*4);	
	for (int i = 0; i < 8; i++)
	{
		mpc_ENDIAN(hHa[i],X[i]);
		X_state[i] = (hHa_state[i] >> 24) + ((hHa_state[i] & 0x00FF0000)>> 8)+((hHa_state[i] & 0x0000FF00) << 8) + ((hHa_state[i] & 0xFF) << 24) ;
		X_state[i+8] = (((uint32_t)back8[i * 4 + 0] << 0) | ((uint32_t)back8[i * 4 + 1] << 8) | ((uint32_t)back8[i * 4 + 2] << 16) | ((uint32_t)back8[i * 4 + 3] << 24)) ;
		for (int j = 0; j < NUM_PARTIES; j++)
		{
			memcpy(&X[i+8][j],&ripeshares[j][i*4],4);	
			X_state[i+8] ^= X[i+8][j];
		}
	}
	for (int i = 0; i < 5; i++)
		for (int j = 0; j < NUM_PARTIES; j++)
		{
			buf[i][j] = hRIPE[i];
			buf_state[i] = hRIPE[i];
		}

	for (int j = 0; j < NUM_PARTIES; j++)
	{
		aa[j] = aaa[j] = buf[0][j];
		aa_state = aaa_state = buf_state[0];
		bb[j] = bbb[j] = buf[1][j];
		bb_state = bbb_state = buf_state[1];
		cc[j] = ccc[j] = buf[2][j];
		cc_state = ccc_state = buf_state[2];
		dd[j] = ddd[j] = buf[3][j];
		dd_state = ddd_state = buf_state[3];
		ee[j] = eee[j] = buf[4][j];	
		ee_state = eee_state = buf_state[4];
	}

// round 1
	mpc_FF(&aa_state, bb_state, &cc_state, dd_state, ee_state, X_state[0], 11, aa, bb, cc, dd, ee, X[0], randomness, &randCount, views, countY);
	mpc_FF(&ee_state, aa_state, &bb_state, cc_state, dd_state, X_state[1], 14, ee, aa, bb, cc, dd, X[1], randomness, &randCount, views, countY);
	mpc_FF(&dd_state, ee_state, &aa_state, bb_state, cc_state, X_state[2], 15, dd, ee, aa, bb, cc, X[2], randomness, &randCount, views, countY);
	mpc_FF(&cc_state, dd_state, &ee_state, aa_state, bb_state, X_state[3], 12, cc, dd, ee, aa, bb, X[3], randomness, &randCount, views, countY);
	mpc_FF(&bb_state, cc_state, &dd_state, ee_state, aa_state, X_state[4], 5, bb, cc, dd, ee, aa, X[4], randomness, &randCount, views, countY);
	mpc_FF(&aa_state, bb_state, &cc_state, dd_state, ee_state, X_state[5], 8, aa, bb, cc, dd, ee, X[5], randomness, &randCount, views, countY);
	mpc_FF(&ee_state, aa_state, &bb_state, cc_state, dd_state, X_state[6], 7, ee, aa, bb, cc, dd, X[6], randomness, &randCount, views, countY);
	mpc_FF(&dd_state, ee_state, &aa_state, bb_state, cc_state, X_state[7], 9, dd, ee, aa, bb, cc, X[7], randomness, &randCount, views, countY);
	mpc_FF(&cc_state, dd_state, &ee_state, aa_state, bb_state, X_state[8], 11, cc, dd, ee, aa, bb, X[8], randomness, &randCount, views, countY);
	mpc_FF(&bb_state, cc_state, &dd_state, ee_state, aa_state, X_state[9], 13, bb, cc, dd, ee, aa, X[9], randomness, &randCount, views, countY);
	mpc_FF(&aa_state, bb_state, &cc_state, dd_state, ee_state, X_state[10], 14, aa, bb, cc, dd, ee, X[10], randomness, &randCount, views, countY);
	mpc_FF(&ee_state, aa_state, &bb_state, cc_state, dd_state, X_state[11], 15, ee, aa, bb, cc, dd, X[11], randomness, &randCount, views, countY);
	mpc_FF(&dd_state, ee_state, &aa_state, bb_state, cc_state, X_state[12], 6, dd, ee, aa, bb, cc, X[12], randomness, &randCount, views, countY);
	mpc_FF(&cc_state, dd_state, &ee_state, aa_state, bb_state, X_state[13], 7, cc, dd, ee, aa, bb, X[13], randomness, &randCount, views, countY);
	mpc_FF(&bb_state, cc_state, &dd_state, ee_state, aa_state, X_state[14], 9, bb, cc, dd, ee, aa, X[14], randomness, &randCount, views, countY);
	mpc_FF(&aa_state, bb_state, &cc_state, dd_state, ee_state, X_state[15], 8, aa, bb, cc, dd, ee, X[15], randomness, &randCount, views, countY);

// round 2
	mpc_GG(&ee_state, aa_state, &bb_state, cc_state, dd_state, X_state[7], 7, hG, ee, aa, bb, cc, dd, X[7], randomness, &randCount, views, countY);
	mpc_GG(&dd_state, ee_state, &aa_state, bb_state, cc_state, X_state[4], 6, hG, dd, ee, aa, bb, cc, X[4], randomness, &randCount, views, countY);
	mpc_GG(&cc_state, dd_state, &ee_state, aa_state, bb_state, X_state[13], 8, hG, cc, dd, ee, aa, bb, X[13], randomness, &randCount, views, countY);
	mpc_GG(&bb_state, cc_state, &dd_state, ee_state, aa_state, X_state[1], 13, hG, bb, cc, dd, ee, aa, X[1], randomness, &randCount, views, countY);
	mpc_GG(&aa_state, bb_state, &cc_state, dd_state, ee_state, X_state[10], 11, hG, aa, bb, cc, dd, ee, X[10], randomness, &randCount, views, countY);
	mpc_GG(&ee_state, aa_state, &bb_state, cc_state, dd_state, X_state[6], 9, hG, ee, aa, bb, cc, dd, X[6], randomness, &randCount, views, countY);
	mpc_GG(&dd_state, ee_state, &aa_state, bb_state, cc_state, X_state[15], 7, hG, dd, ee, aa, bb, cc, X[15], randomness, &randCount, views, countY);
	mpc_GG(&cc_state, dd_state, &ee_state, aa_state, bb_state, X_state[3], 15, hG, cc, dd, ee, aa, bb, X[3], randomness, &randCount, views, countY);
	mpc_GG(&bb_state, cc_state, &dd_state, ee_state, aa_state, X_state[12], 7, hG, bb, cc, dd, ee, aa, X[12], randomness, &randCount, views, countY);
	mpc_GG(&aa_state, bb_state, &cc_state, dd_state, ee_state, X_state[0], 12, hG, aa, bb, cc, dd, ee, X[0], randomness, &randCount, views, countY);
	mpc_GG(&ee_state, aa_state, &bb_state, cc_state, dd_state, X_state[9], 15, hG, ee, aa, bb, cc, dd, X[9], randomness, &randCount, views, countY);
	mpc_GG(&dd_state, ee_state, &aa_state, bb_state, cc_state, X_state[5], 9, hG, dd, ee, aa, bb, cc, X[5], randomness, &randCount, views, countY);
	mpc_GG(&cc_state, dd_state, &ee_state, aa_state, bb_state, X_state[2], 11, hG, cc, dd, ee, aa, bb, X[2], randomness, &randCount, views, countY);
	mpc_GG(&bb_state, cc_state, &dd_state, ee_state, aa_state, X_state[14], 7, hG, bb, cc, dd, ee, aa, X[14], randomness, &randCount, views, countY);
	mpc_GG(&aa_state, bb_state, &cc_state, dd_state, ee_state, X_state[11], 13, hG, aa, bb, cc, dd, ee, X[11], randomness, &randCount, views, countY);
	mpc_GG(&ee_state, aa_state, &bb_state, cc_state, dd_state, X_state[8], 12, hG, ee, aa, bb, cc, dd, X[8], randomness, &randCount, views, countY);

// round 3
	mpc_HH(&dd_state, ee_state, &aa_state, bb_state, cc_state, X_state[3], 11, hH, dd, ee, aa, bb, cc, X[3], randomness, &randCount, views, countY);
	mpc_HH(&cc_state, dd_state, &ee_state, aa_state, bb_state, X_state[10], 13, hH, cc, dd, ee, aa, bb, X[10], randomness, &randCount, views, countY);
	mpc_HH(&bb_state, cc_state, &dd_state, ee_state, aa_state, X_state[14], 6, hH, bb, cc, dd, ee, aa, X[14], randomness, &randCount, views, countY);
	mpc_HH(&aa_state, bb_state, &cc_state, dd_state, ee_state, X_state[4], 7, hH, aa, bb, cc, dd, ee, X[4], randomness, &randCount, views, countY);
	mpc_HH(&ee_state, aa_state, &bb_state, cc_state, dd_state, X_state[9], 14, hH, ee, aa, bb, cc, dd, X[9], randomness, &randCount, views, countY);
	mpc_HH(&dd_state, ee_state, &aa_state, bb_state, cc_state, X_state[15], 9, hH, dd, ee, aa, bb, cc, X[15], randomness, &randCount, views, countY);
	mpc_HH(&cc_state, dd_state, &ee_state, aa_state, bb_state, X_state[8], 13, hH, cc, dd, ee, aa, bb, X[8], randomness, &randCount, views, countY);
	mpc_HH(&bb_state, cc_state, &dd_state, ee_state, aa_state, X_state[1], 15, hH, bb, cc, dd, ee, aa, X[1], randomness, &randCount, views, countY);
	mpc_HH(&aa_state, bb_state, &cc_state, dd_state, ee_state, X_state[2], 14, hH, aa, bb, cc, dd, ee, X[2], randomness, &randCount, views, countY);
	mpc_HH(&ee_state, aa_state, &bb_state, cc_state, dd_state, X_state[7], 8, hH, ee, aa, bb, cc, dd, X[7], randomness, &randCount, views, countY);
	mpc_HH(&dd_state, ee_state, &aa_state, bb_state, cc_state, X_state[0], 13, hH, dd, ee, aa, bb, cc, X[0], randomness, &randCount, views, countY);
	mpc_HH(&cc_state, dd_state, &ee_state, aa_state, bb_state, X_state[6], 6, hH, cc, dd, ee, aa, bb, X[6], randomness, &randCount, views, countY);
	mpc_HH(&bb_state, cc_state, &dd_state, ee_state, aa_state, X_state[13], 5, hH, bb, cc, dd, ee, aa, X[13], randomness, &randCount, views, countY);
	mpc_HH(&aa_state, bb_state, &cc_state, dd_state, ee_state, X_state[11], 12, hH, aa, bb, cc, dd, ee, X[11], randomness, &randCount, views, countY);
	mpc_HH(&ee_state, aa_state, &bb_state, cc_state, dd_state, X_state[5], 7, hH, ee, aa, bb, cc, dd, X[5], randomness, &randCount, views, countY);
 	mpc_HH(&dd_state, ee_state, &aa_state, bb_state, cc_state, X_state[12], 5, hH, dd, ee, aa, bb, cc, X[12], randomness, &randCount, views, countY);
	
// round 4
	mpc_II(&cc_state, dd_state, &ee_state, aa_state, bb_state, X_state[1], 11, hI, cc, dd, ee, aa, bb, X[1], randomness, &randCount, views, countY);
	mpc_II(&bb_state, cc_state, &dd_state, ee_state, aa_state, X_state[9], 12, hI, bb, cc, dd, ee, aa, X[9], randomness, &randCount, views, countY);
	mpc_II(&aa_state, bb_state, &cc_state, dd_state, ee_state, X_state[11], 14, hI, aa, bb, cc, dd, ee, X[11], randomness, &randCount, views, countY);
	mpc_II(&ee_state, aa_state, &bb_state, cc_state, dd_state, X_state[10], 15, hI, ee, aa, bb, cc, dd, X[10], randomness, &randCount, views, countY);
	mpc_II(&dd_state, ee_state, &aa_state, bb_state, cc_state, X_state[0], 14, hI, dd, ee, aa, bb, cc, X[0], randomness, &randCount, views, countY);
	mpc_II(&cc_state, dd_state, &ee_state, aa_state, bb_state, X_state[8], 15, hI, cc, dd, ee, aa, bb, X[8], randomness, &randCount, views, countY);
	mpc_II(&bb_state, cc_state, &dd_state, ee_state, aa_state, X_state[12], 9, hI, bb, cc, dd, ee, aa, X[12], randomness, &randCount, views, countY);
	mpc_II(&aa_state, bb_state, &cc_state, dd_state, ee_state, X_state[4], 8, hI, aa, bb, cc, dd, ee, X[4], randomness, &randCount, views, countY);
	mpc_II(&ee_state, aa_state, &bb_state, cc_state, dd_state, X_state[13], 9, hI, ee, aa, bb, cc, dd, X[13], randomness, &randCount, views, countY);
	mpc_II(&dd_state, ee_state, &aa_state, bb_state, cc_state, X_state[3], 14, hI, dd, ee, aa, bb, cc, X[3], randomness, &randCount, views, countY);
	mpc_II(&cc_state, dd_state, &ee_state, aa_state, bb_state, X_state[7], 5, hI, cc, dd, ee, aa, bb, X[7], randomness, &randCount, views, countY);
	mpc_II(&bb_state, cc_state, &dd_state, ee_state, aa_state, X_state[15], 6, hI, bb, cc, dd, ee, aa, X[15], randomness, &randCount, views, countY);
	mpc_II(&aa_state, bb_state, &cc_state, dd_state, ee_state, X_state[14], 8, hI, aa, bb, cc, dd, ee, X[14], randomness, &randCount, views, countY);
	mpc_II(&ee_state, aa_state, &bb_state, cc_state, dd_state, X_state[5], 6, hI, ee, aa, bb, cc, dd, X[5], randomness, &randCount, views, countY);
	mpc_II(&dd_state, ee_state, &aa_state, bb_state, cc_state, X_state[6], 5, hI, dd, ee, aa, bb, cc, X[6], randomness, &randCount, views, countY);
	mpc_II(&cc_state, dd_state, &ee_state, aa_state, bb_state, X_state[2], 12, hI, cc, dd, ee, aa, bb, X[2], randomness, &randCount, views, countY);

// round 5
	mpc_JJ(&bb_state, cc_state, &dd_state, ee_state, aa_state, X_state[4], 9, hJ, bb, cc, dd, ee, aa, X[4], randomness, &randCount, views, countY);
	mpc_JJ(&aa_state, bb_state, &cc_state, dd_state, ee_state, X_state[0], 15, hJ, aa, bb, cc, dd, ee, X[0], randomness, &randCount, views, countY);
	mpc_JJ(&ee_state, aa_state, &bb_state, cc_state, dd_state, X_state[5], 5, hJ, ee, aa, bb, cc, dd, X[5], randomness, &randCount, views, countY);
	mpc_JJ(&dd_state, ee_state, &aa_state, bb_state, cc_state, X_state[9], 11, hJ, dd, ee, aa, bb, cc, X[9], randomness, &randCount, views, countY);
	mpc_JJ(&cc_state, dd_state, &ee_state, aa_state, bb_state, X_state[7], 6, hJ, cc, dd, ee, aa, bb, X[7], randomness, &randCount, views, countY);
	mpc_JJ(&bb_state, cc_state, &dd_state, ee_state, aa_state, X_state[12], 8, hJ, bb, cc, dd, ee, aa, X[12], randomness, &randCount, views, countY);
	mpc_JJ(&aa_state, bb_state, &cc_state, dd_state, ee_state, X_state[2], 13, hJ, aa, bb, cc, dd, ee, X[2], randomness, &randCount, views, countY);
	mpc_JJ(&ee_state, aa_state, &bb_state, cc_state, dd_state, X_state[10], 12, hJ, ee, aa, bb, cc, dd, X[10], randomness, &randCount, views, countY);
	mpc_JJ(&dd_state, ee_state, &aa_state, bb_state, cc_state, X_state[14], 5, hJ, dd, ee, aa, bb, cc, X[14], randomness, &randCount, views, countY);
	mpc_JJ(&cc_state, dd_state, &ee_state, aa_state, bb_state, X_state[1], 12, hJ, cc, dd, ee, aa, bb, X[1], randomness, &randCount, views, countY);
	mpc_JJ(&bb_state, cc_state, &dd_state, ee_state, aa_state, X_state[3], 13, hJ, bb, cc, dd, ee, aa, X[3], randomness, &randCount, views, countY);
	mpc_JJ(&aa_state, bb_state, &cc_state, dd_state, ee_state, X_state[8], 14, hJ, aa, bb, cc, dd, ee, X[8], randomness, &randCount, views, countY);
	mpc_JJ(&ee_state, aa_state, &bb_state, cc_state, dd_state, X_state[11], 11, hJ, ee, aa, bb, cc, dd, X[11], randomness, &randCount, views, countY);
	mpc_JJ(&dd_state, ee_state, &aa_state, bb_state, cc_state, X_state[6], 8, hJ, dd, ee, aa, bb, cc, X[6], randomness, &randCount, views, countY);
	mpc_JJ(&cc_state, dd_state, &ee_state, aa_state, bb_state, X_state[15], 5, hJ, cc, dd, ee, aa, bb, X[15], randomness, &randCount, views, countY);
	mpc_JJ(&bb_state, cc_state, &dd_state, ee_state, aa_state, X_state[13], 6, hJ, bb, cc, dd, ee, aa, X[13], randomness, &randCount, views, countY);
		
 // round 1
	mpc_JJ(&aaa_state, bbb_state, &ccc_state, ddd_state, eee_state, X_state[5], 8, hJJ, aaa, bbb, ccc, ddd, eee, X[5], randomness, &randCount, views, countY);
	mpc_JJ(&eee_state, aaa_state, &bbb_state, ccc_state, ddd_state, X_state[14], 9, hJJ, eee, aaa, bbb, ccc, ddd, X[14], randomness, &randCount, views, countY);
	mpc_JJ(&ddd_state, eee_state, &aaa_state, bbb_state, ccc_state, X_state[7], 9, hJJ, ddd, eee, aaa, bbb, ccc, X[7], randomness, &randCount, views, countY);
	mpc_JJ(&ccc_state, ddd_state, &eee_state, aaa_state, bbb_state, X_state[0], 11, hJJ, ccc, ddd, eee, aaa, bbb, X[0], randomness, &randCount, views, countY);
	mpc_JJ(&bbb_state, ccc_state, &ddd_state, eee_state, aaa_state, X_state[9], 13, hJJ, bbb, ccc, ddd, eee, aaa, X[9], randomness, &randCount, views, countY);
	mpc_JJ(&aaa_state, bbb_state, &ccc_state, ddd_state, eee_state, X_state[2], 15, hJJ, aaa, bbb, ccc, ddd, eee, X[2], randomness, &randCount, views, countY);
	mpc_JJ(&eee_state, aaa_state, &bbb_state, ccc_state, ddd_state, X_state[11], 15, hJJ, eee, aaa, bbb, ccc, ddd, X[11], randomness, &randCount, views, countY);
	mpc_JJ(&ddd_state, eee_state, &aaa_state, bbb_state, ccc_state, X_state[4], 5, hJJ, ddd, eee, aaa, bbb, ccc, X[4], randomness, &randCount, views, countY);
	mpc_JJ(&ccc_state, ddd_state, &eee_state, aaa_state, bbb_state, X_state[13], 7, hJJ, ccc, ddd, eee, aaa, bbb, X[13], randomness, &randCount, views, countY);
	mpc_JJ(&bbb_state, ccc_state, &ddd_state, eee_state, aaa_state, X_state[6], 7, hJJ, bbb, ccc, ddd, eee, aaa, X[6], randomness, &randCount, views, countY);
	mpc_JJ(&aaa_state, bbb_state, &ccc_state, ddd_state, eee_state, X_state[15], 8, hJJ, aaa, bbb, ccc, ddd, eee, X[15], randomness, &randCount, views, countY);
	mpc_JJ(&eee_state, aaa_state, &bbb_state, ccc_state, ddd_state, X_state[8], 11, hJJ, eee, aaa, bbb, ccc, ddd, X[8], randomness, &randCount, views, countY);
	mpc_JJ(&ddd_state, eee_state, &aaa_state, bbb_state, ccc_state, X_state[1], 14, hJJ, ddd, eee, aaa, bbb, ccc, X[1], randomness, &randCount, views, countY);
	mpc_JJ(&ccc_state, ddd_state, &eee_state, aaa_state, bbb_state, X_state[10], 14, hJJ, ccc, ddd, eee, aaa, bbb, X[10], randomness, &randCount, views, countY);
	mpc_JJ(&bbb_state, ccc_state, &ddd_state, eee_state, aaa_state, X_state[3], 12, hJJ, bbb, ccc, ddd, eee, aaa, X[3], randomness, &randCount, views, countY);
	mpc_JJ(&aaa_state, bbb_state, &ccc_state, ddd_state, eee_state, X_state[12], 6, hJJ, aaa, bbb, ccc, ddd, eee, X[12], randomness, &randCount, views, countY);
// round 2
	mpc_II(&eee_state, aaa_state, &bbb_state, ccc_state, ddd_state, X_state[6], 9, hII, eee, aaa, bbb, ccc, ddd, X[6], randomness, &randCount, views, countY);
	mpc_II(&ddd_state, eee_state, &aaa_state, bbb_state, ccc_state, X_state[11], 13, hII, ddd, eee, aaa, bbb, ccc, X[11], randomness, &randCount, views, countY);
	mpc_II(&ccc_state, ddd_state, &eee_state, aaa_state, bbb_state, X_state[3], 15, hII, ccc, ddd, eee, aaa, bbb, X[3], randomness, &randCount, views, countY);
	mpc_II(&bbb_state, ccc_state, &ddd_state, eee_state, aaa_state, X_state[7], 7, hII, bbb, ccc, ddd, eee, aaa, X[7], randomness, &randCount, views, countY);
	mpc_II(&aaa_state, bbb_state, &ccc_state, ddd_state, eee_state, X_state[0], 12, hII, aaa, bbb, ccc, ddd, eee, X[0], randomness, &randCount, views, countY);
	mpc_II(&eee_state, aaa_state, &bbb_state, ccc_state, ddd_state, X_state[13], 8, hII, eee, aaa, bbb, ccc, ddd, X[13], randomness, &randCount, views, countY);
	mpc_II(&ddd_state, eee_state, &aaa_state, bbb_state, ccc_state, X_state[5], 9, hII, ddd, eee, aaa, bbb, ccc, X[5], randomness, &randCount, views, countY);
	mpc_II(&ccc_state, ddd_state, &eee_state, aaa_state, bbb_state, X_state[10], 11, hII, ccc, ddd, eee, aaa, bbb, X[10], randomness, &randCount, views, countY);
	mpc_II(&bbb_state, ccc_state, &ddd_state, eee_state, aaa_state, X_state[14], 7, hII, bbb, ccc, ddd, eee, aaa, X[14], randomness, &randCount, views, countY);
	mpc_II(&aaa_state, bbb_state, &ccc_state, ddd_state, eee_state, X_state[15], 7, hII, aaa, bbb, ccc, ddd, eee, X[15], randomness, &randCount, views, countY);
	mpc_II(&eee_state, aaa_state, &bbb_state, ccc_state, ddd_state, X_state[8], 12, hII, eee, aaa, bbb, ccc, ddd, X[8], randomness, &randCount, views, countY);
	mpc_II(&ddd_state, eee_state, &aaa_state, bbb_state, ccc_state, X_state[12], 7, hII, ddd, eee, aaa, bbb, ccc, X[12], randomness, &randCount, views, countY);
	mpc_II(&ccc_state, ddd_state, &eee_state, aaa_state, bbb_state, X_state[4], 6, hII, ccc, ddd, eee, aaa, bbb, X[4], randomness, &randCount, views, countY);
	mpc_II(&bbb_state, ccc_state, &ddd_state, eee_state, aaa_state, X_state[9], 15, hII, bbb, ccc, ddd, eee, aaa, X[9], randomness, &randCount, views, countY);
	mpc_II(&aaa_state, bbb_state, &ccc_state, ddd_state, eee_state, X_state[1], 13, hII, aaa, bbb, ccc, ddd, eee, X[1], randomness, &randCount, views, countY);
	mpc_II(&eee_state, aaa_state, &bbb_state, ccc_state, ddd_state, X_state[2], 11, hII, eee, aaa, bbb, ccc, ddd, X[2], randomness, &randCount, views, countY);
// round 3
	mpc_HH(&ddd_state, eee_state, &aaa_state, bbb_state, ccc_state, X_state[15], 9, hHH, ddd, eee, aaa, bbb, ccc, X[15], randomness, &randCount, views, countY);
	mpc_HH(&ccc_state, ddd_state, &eee_state, aaa_state, bbb_state, X_state[5], 7, hHH, ccc, ddd, eee, aaa, bbb, X[5], randomness, &randCount, views, countY);
	mpc_HH(&bbb_state, ccc_state, &ddd_state, eee_state, aaa_state, X_state[1], 15, hHH, bbb, ccc, ddd, eee, aaa, X[1], randomness, &randCount, views, countY);
	mpc_HH(&aaa_state, bbb_state, &ccc_state, ddd_state, eee_state, X_state[3], 11, hHH, aaa, bbb, ccc, ddd, eee, X[3], randomness, &randCount, views, countY);
	mpc_HH(&eee_state, aaa_state, &bbb_state, ccc_state, ddd_state, X_state[7], 8, hHH, eee, aaa, bbb, ccc, ddd, X[7], randomness, &randCount, views, countY);
	mpc_HH(&ddd_state, eee_state, &aaa_state, bbb_state, ccc_state, X_state[14], 6, hHH, ddd, eee, aaa, bbb, ccc, X[14], randomness, &randCount, views, countY);
	mpc_HH(&ccc_state, ddd_state, &eee_state, aaa_state, bbb_state, X_state[6], 6, hHH, ccc, ddd, eee, aaa, bbb, X[6], randomness, &randCount, views, countY);
	mpc_HH(&bbb_state, ccc_state, &ddd_state, eee_state, aaa_state, X_state[9], 14, hHH, bbb, ccc, ddd, eee, aaa, X[9], randomness, &randCount, views, countY);
	mpc_HH(&aaa_state, bbb_state, &ccc_state, ddd_state, eee_state, X_state[11], 12, hHH, aaa, bbb, ccc, ddd, eee, X[11], randomness, &randCount, views, countY);
	mpc_HH(&eee_state, aaa_state, &bbb_state, ccc_state, ddd_state, X_state[8], 13, hHH, eee, aaa, bbb, ccc, ddd, X[8], randomness, &randCount, views, countY);
	mpc_HH(&ddd_state, eee_state, &aaa_state, bbb_state, ccc_state, X_state[12], 5, hHH, ddd, eee, aaa, bbb, ccc, X[12], randomness, &randCount, views, countY);
	mpc_HH(&ccc_state, ddd_state, &eee_state, aaa_state, bbb_state, X_state[2], 14, hHH, ccc, ddd, eee, aaa, bbb, X[2], randomness, &randCount, views, countY);
	mpc_HH(&bbb_state, ccc_state, &ddd_state, eee_state, aaa_state, X_state[10], 13, hHH, bbb, ccc, ddd, eee, aaa, X[10], randomness, &randCount, views, countY);
	mpc_HH(&aaa_state, bbb_state, &ccc_state, ddd_state, eee_state, X_state[0], 13, hHH, aaa, bbb, ccc, ddd, eee, X[0], randomness, &randCount, views, countY);
	mpc_HH(&eee_state, aaa_state, &bbb_state, ccc_state, ddd_state, X_state[4], 7, hHH, eee, aaa, bbb, ccc, ddd, X[4], randomness, &randCount, views, countY);
	mpc_HH(&ddd_state, eee_state, &aaa_state, bbb_state, ccc_state, X_state[13], 5, hHH, ddd, eee, aaa, bbb, ccc, X[13], randomness, &randCount, views, countY);
// round 4
	mpc_GG(&ccc_state, ddd_state, &eee_state, aaa_state, bbb_state, X_state[8], 15, hGG, ccc, ddd, eee, aaa, bbb, X[8], randomness, &randCount, views, countY);
	mpc_GG(&bbb_state, ccc_state, &ddd_state, eee_state, aaa_state, X_state[6], 5, hGG, bbb, ccc, ddd, eee, aaa, X[6], randomness, &randCount, views, countY);
	mpc_GG(&aaa_state, bbb_state, &ccc_state, ddd_state, eee_state, X_state[4], 8, hGG, aaa, bbb, ccc, ddd, eee, X[4], randomness, &randCount, views, countY);
	mpc_GG(&eee_state, aaa_state, &bbb_state, ccc_state, ddd_state, X_state[1], 11, hGG, eee, aaa, bbb, ccc, ddd, X[1], randomness, &randCount, views, countY);
	mpc_GG(&ddd_state, eee_state, &aaa_state, bbb_state, ccc_state, X_state[3], 14, hGG, ddd, eee, aaa, bbb, ccc, X[3], randomness, &randCount, views, countY);
	mpc_GG(&ccc_state, ddd_state, &eee_state, aaa_state, bbb_state, X_state[11], 14, hGG, ccc, ddd, eee, aaa, bbb, X[11], randomness, &randCount, views, countY);
	mpc_GG(&bbb_state, ccc_state, &ddd_state, eee_state, aaa_state, X_state[15], 6, hGG, bbb, ccc, ddd, eee, aaa, X[15], randomness, &randCount, views, countY);
	mpc_GG(&aaa_state, bbb_state, &ccc_state, ddd_state, eee_state, X_state[0], 14, hGG, aaa, bbb, ccc, ddd, eee, X[0], randomness, &randCount, views, countY);
	mpc_GG(&eee_state, aaa_state, &bbb_state, ccc_state, ddd_state, X_state[5], 6, hGG, eee, aaa, bbb, ccc, ddd, X[5], randomness, &randCount, views, countY);
	mpc_GG(&ddd_state, eee_state, &aaa_state, bbb_state, ccc_state, X_state[12], 9, hGG, ddd, eee, aaa, bbb, ccc, X[12], randomness, &randCount, views, countY);
	mpc_GG(&ccc_state, ddd_state, &eee_state, aaa_state, bbb_state, X_state[2], 12, hGG, ccc, ddd, eee, aaa, bbb, X[2], randomness, &randCount, views, countY);
	mpc_GG(&bbb_state, ccc_state, &ddd_state, eee_state, aaa_state, X_state[13], 9, hGG, bbb, ccc, ddd, eee, aaa, X[13], randomness, &randCount, views, countY);
	mpc_GG(&aaa_state, bbb_state, &ccc_state, ddd_state, eee_state, X_state[9], 12, hGG, aaa, bbb, ccc, ddd, eee, X[9], randomness, &randCount, views, countY);
	mpc_GG(&eee_state, aaa_state, &bbb_state, ccc_state, ddd_state, X_state[7], 5, hGG, eee, aaa, bbb, ccc, ddd, X[7], randomness, &randCount, views, countY);
	mpc_GG(&ddd_state, eee_state, &aaa_state, bbb_state, ccc_state, X_state[10], 15, hGG, ddd, eee, aaa, bbb, ccc, X[10], randomness, &randCount, views, countY);
	mpc_GG(&ccc_state, ddd_state, &eee_state, aaa_state, bbb_state, X_state[14], 8, hGG, ccc, ddd, eee, aaa, bbb, X[14], randomness, &randCount, views, countY);

// round 5
	mpc_FF(&bbb_state, ccc_state, &ddd_state, eee_state, aaa_state, X_state[12], 8, bbb, ccc, ddd, eee, aaa, X[12], randomness, &randCount, views, countY);
	mpc_FF(&aaa_state, bbb_state, &ccc_state, ddd_state, eee_state, X_state[15], 5, aaa, bbb, ccc, ddd, eee, X[15], randomness, &randCount, views, countY);
	mpc_FF(&eee_state, aaa_state, &bbb_state, ccc_state, ddd_state, X_state[10], 12, eee, aaa, bbb, ccc, ddd, X[10], randomness, &randCount, views, countY);
	mpc_FF(&ddd_state, eee_state, &aaa_state, bbb_state, ccc_state, X_state[4], 9, ddd, eee, aaa, bbb, ccc, X[4], randomness, &randCount, views, countY);
	mpc_FF(&ccc_state, ddd_state, &eee_state, aaa_state, bbb_state, X_state[1], 12, ccc, ddd, eee, aaa, bbb, X[1], randomness, &randCount, views, countY);
	mpc_FF(&bbb_state, ccc_state, &ddd_state, eee_state, aaa_state, X_state[5], 5, bbb, ccc, ddd, eee, aaa, X[5], randomness, &randCount, views, countY);
	mpc_FF(&aaa_state, bbb_state, &ccc_state, ddd_state, eee_state, X_state[8], 14, aaa, bbb, ccc, ddd, eee, X[8], randomness, &randCount, views, countY);
	mpc_FF(&eee_state, aaa_state, &bbb_state, ccc_state, ddd_state, X_state[7], 6, eee, aaa, bbb, ccc, ddd, X[7], randomness, &randCount, views, countY);
	mpc_FF(&ddd_state, eee_state, &aaa_state, bbb_state, ccc_state, X_state[6], 8, ddd, eee, aaa, bbb, ccc, X[6], randomness, &randCount, views, countY);
	mpc_FF(&ccc_state, ddd_state, &eee_state, aaa_state, bbb_state, X_state[2], 13, ccc, ddd, eee, aaa, bbb, X[2], randomness, &randCount, views, countY);
	mpc_FF(&bbb_state, ccc_state, &ddd_state, eee_state, aaa_state, X_state[13], 6, bbb, ccc, ddd, eee, aaa, X[13], randomness, &randCount, views, countY);
	mpc_FF(&aaa_state, bbb_state, &ccc_state, ddd_state, eee_state, X_state[14], 5, aaa, bbb, ccc, ddd, eee, X[14], randomness, &randCount, views, countY);
	mpc_FF(&eee_state, aaa_state, &bbb_state, ccc_state, ddd_state, X_state[0], 15, eee, aaa, bbb, ccc, ddd, X[0], randomness, &randCount, views, countY);
	mpc_FF(&ddd_state, eee_state, &aaa_state, bbb_state, ccc_state, X_state[3], 13, ddd, eee, aaa, bbb, ccc, X[3], randomness, &randCount, views, countY);
	mpc_FF(&ccc_state, ddd_state, &eee_state, aaa_state, bbb_state, X_state[9], 11, ccc, ddd, eee, aaa, bbb, X[9], randomness, &randCount, views, countY);
	mpc_FF(&bbb_state, ccc_state, &ddd_state, eee_state, aaa_state, X_state[11], 11, bbb, ccc, ddd, eee, aaa, X[11], randomness, &randCount, views, countY);

	mpc_ADD(cc_state,buf_state[1],&t0_state,cc,buf[1],t0,randomness,&randCount,views,countY);
	mpc_ADD(t0_state,ddd_state,&t1_state,t0,ddd,t1,randomness,&randCount,views,countY);
	mpc_ADD(dd_state,buf_state[2],&t0_state,dd,buf[2],t0,randomness,&randCount,views,countY);
	mpc_ADD(t0_state,eee_state,&buf_state[1],t0,eee,buf[1],randomness,&randCount,views,countY);
	mpc_ADD(ee_state,buf_state[3],&t0_state,ee,buf[3],t0,randomness,&randCount,views,countY);
	mpc_ADD(t0_state,aaa_state,&buf_state[2],t0,aaa,buf[2],randomness,&randCount,views,countY);
	mpc_ADD(aa_state,buf_state[4],&t0_state,aa,buf[4],t0,randomness,&randCount,views,countY);
	mpc_ADD(t0_state,bbb_state,&buf_state[3],t0,bbb,buf[3],randomness,&randCount,views,countY);
	mpc_ADD(bb_state,buf_state[0],&t0_state,bb,buf[0],t0,randomness,&randCount,views,countY);
	mpc_ADD(t0_state,ccc_state,&buf_state[4],t0,ccc,buf[4],randomness,&randCount,views,countY);

	for (int i = 0; i < NUM_PARTIES; i++)
		buf[0][i] = t1[i];
	buf_state[0] = t1_state;

	for (int i = 0; i < 5; i++)
	{
		for (int j = 0; j < NUM_PARTIES; j++)
		{
			if (inputs)
			{
				views[j].y[*countY] = buf[i][j];
			}
			else
			{
				if (j == numBytes)
					buf[i][j] = views[j].y[*countY];
				else
					views[j].y[*countY] = buf[i][j];
			}
		}
		*countY+=1;
	}

	for (int i = 0; i < 5; i++) {
		for (int j = 0;j< NUM_PARTIES;j++)
			party_result[j][i * 4] = buf[i][j];
		masked_result[i*4] = buf_state[i];

		mpc_RIGHTSHIFT(buf[i], 8, t0);
		t0_state = buf_state[i] >> 8;
		for (int j = 0;j< NUM_PARTIES;j++)
			party_result[j][i * 4 + 1] = t0[j];
		masked_result[i*4+1] = t0_state;

		mpc_RIGHTSHIFT(buf[i], 16, t0);
		t0_state = buf_state[i] >> 16;
		for (int j = 0;j< NUM_PARTIES;j++)
			party_result[j][i * 4 + 2] = t0[j];
		masked_result[i*4+2] = t0_state;

		mpc_RIGHTSHIFT(buf[i], 24, t0);
		t0_state = buf_state[i] >> 24;
		for (int j = 0;j< NUM_PARTIES;j++)
			party_result[j][i * 4 + 3] = t0[j];
		masked_result[i*4+3] = t0_state;

	}
//	printf("mpc_compute: Ycount %d\n",*countY);;

	return 0;
}


/**
 * Copyright (c) 2012-2014 Luke Dashjr
 * Copyright (c) 2013-2014 Pavol Rusnak
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 * OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

const char b58digits_ordered[] =
	"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const int8_t b58digits_map[] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0,  1,  2,  3,  4,  5,  6,  7,
    8,  -1, -1, -1, -1, -1, -1, -1, 9,  10, 11, 12, 13, 14, 15, 16, -1, 17, 18,
    19, 20, 21, -1, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, -1, -1, -1, -1,
    -1, -1, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, -1, 44, 45, 46, 47, 48,
    49, 50, 51, 52, 53, 54, 55, 56, 57, -1, -1, -1, -1, -1,
};

static int b58tobin(void *bin, size_t *binszp, const char *b58) {
  size_t binsz = *binszp;
  size_t retsz = 0;
  if (binsz == 0) {
    return 0;
  }
  const unsigned char *b58u = (const unsigned char *)b58;
  unsigned char *binu = bin;
  size_t outisz = (binsz + 3) / 4;
  uint32_t outi[outisz];
  uint64_t t;
  uint32_t c;
  size_t i, j;
  uint8_t bytesleft = binsz % 4;
  uint32_t zeromask = bytesleft ? (0xffffffff << (bytesleft * 8)) : 0;
  unsigned zerocount = 0;
  size_t b58sz;
b58sz = strlen(b58);
  memset(outi,0, sizeof(outi));

  // Leading zeros, just count
  for (i = 0; i < b58sz && b58u[i] == '1'; ++i) ++zerocount;

  for (; i < b58sz; ++i) {
    if (b58u[i] & 0x80)
      // High-bit set on invalid digit
      return 0;
    if (b58digits_map[b58u[i]] == -1)
      // Invalid base58 digit
      return 0;
    c = (unsigned)b58digits_map[b58u[i]];
    for (j = outisz; j--;) {
     t = ((uint64_t)outi[j]) * 58 + c;
      c = (t & 0x3f00000000) >> 32;
      outi[j] = t & 0xffffffff;
    }
    if (c)
      // Output number too big (carry to the next int32)
      return 0;
    if (outi[0] & zeromask)
      // Output number too big (last int32 filled too far)
      return 0;
  }
j = 0;
  switch (bytesleft) {
    case 3:
      *(binu++) = (outi[0] & 0xff0000) >> 16;
      //-fallthrough
    case 2:
      *(binu++) = (outi[0] & 0xff00) >> 8;
      //-fallthrough
    case 1:
      *(binu++) = (outi[0] & 0xff);
      ++j;
    default:
      break;
  }
  for (; j < outisz; ++j) {
    *(binu++) = (outi[j] >> 0x18) & 0xff;
    *(binu++) = (outi[j] >> 0x10) & 0xff;
    *(binu++) = (outi[j] >> 8) & 0xff;
    *(binu++) = (outi[j] >> 0) & 0xff;
  }

  // Count canonical base58 byte count
  binu = bin;
  for (i = 0; i < binsz; ++i) {
    if (binu[i]) {
      if (zerocount > i) {
        /* result too large */
        return 0;
      }
      break;
    }
    --*binszp;
  }
  *binszp += zerocount;

  return 1;
}

static int b58enc(char *b58, size_t *b58sz, const void *data, size_t binsz) {
  const uint8_t *bin = data;
  int carry;
  ssize_t i, j, high, zcount = 0;
  size_t size;

  while (zcount < (ssize_t)binsz && !bin[zcount]) ++zcount;

  size = (binsz - zcount) * 138 / 100 + 1;
  uint8_t buf[size];
  memset(buf,0, size);

  for (i = zcount, high = size - 1; i < (ssize_t)binsz; ++i, high = j) {
    for (carry = bin[i], j = size - 1; (j > high) || carry; --j) {
      carry += 256 * buf[j];
      buf[j] = carry % 58;
      carry /= 58;
    }
  }

  for (j = 0; j < (ssize_t)size && !buf[j]; ++j)
    ;

  if (*b58sz <= zcount + size - j) {
    *b58sz = zcount + size - j + 1;
    return 0;
  }
  if (zcount) memset(b58, '1', zcount);
  for (i = zcount; j < (ssize_t)size; ++i, ++j)
    b58[i] = b58digits_ordered[buf[j]];
  b58[i] = '\0';
  *b58sz = i + 1;

  return 1;
}

static void hex2bin(char * hex , int hexsize, unsigned char * bin)
{
	unsigned char tempc;
	int i;
	for (i=0;i<hexsize;i+=2)
	{
		tempc = 0;
		if ((hex[i]>='0') && (hex[i]<='9'))
			tempc = hex[i] - '0';
		else if ((hex[i]>='a') && (hex[i]<='f'))
			tempc = hex[i] - 'a' + 10;
		else if ((hex[i]>='A') && (hex[i]<='F'))
			tempc = hex[i] - 'A' + 10;
		tempc <<= 4;
		if ((hex[i+1]>='0') && (hex[i+1]<='9'))
			tempc += hex[i+1] - '0';
		else if ((hex[i+1]>='a') && (hex[i+1]<='f'))
			tempc += hex[i+1] - 'a' + 10;
		else if ((hex[i+1]>='A') && (hex[i+1]<='F'))
			tempc += hex[i+1] - 'A' + 10;
		bin[(i)/2] = tempc;
	}
}
static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
				'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
				'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
				'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
				'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
    				'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
   				'w', 'x', 'y', 'z', '0', '1', '2', '3',
				'4', '5', '6', '7', '8', '9', '+', '/'};
static char decoding_table[256];
static int mod_table[] = {0, 2, 1};
static int decoding_table_init =0;

char *base64_encode(const unsigned char *data, size_t input_length, char * encoded_data, size_t *output_length)
{
	*output_length = 4 * ((input_length + 2) / 3);
	if (encoded_data == NULL) return NULL;
	for (int i = 0, j = 0; i < input_length;)
	{
		uint32_t octet_a = i < input_length ? (unsigned char)data[i++] : 0;
		uint32_t octet_b = i < input_length ? (unsigned char)data[i++] : 0;
		uint32_t octet_c = i < input_length ? (unsigned char)data[i++] : 0;
		uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;
		encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
		encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
		encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
		encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
	}
	for (int i = 0; i < mod_table[input_length % 3]; i++)
		encoded_data[*output_length - 1 - i] = '=';

	return encoded_data;
}

static unsigned char *base64_decode(const char *data, size_t input_length, unsigned char * decoded_data, size_t *output_length)
{
	if (!decoding_table_init)
	{
		memset(decoding_table,0,256);
		for (int i = 0; i < 64; i++)
			decoding_table[(unsigned char) encoding_table[i]] = i;
		decoding_table_init = 1;
	}

	if (input_length % 4 != 0) return NULL;

	*output_length = input_length / 4 * 3;
	if (data[input_length - 1] == '=') (*output_length)--;
	if (data[input_length - 2] == '=') (*output_length)--;

//      unsigned char *decoded_data = malloc(*output_length);
	if (decoded_data == NULL) return NULL;

	for (int i = 0, j = 0; i < input_length;)
	{
		uint32_t sextet_a = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
		uint32_t sextet_b = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
		uint32_t sextet_c = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
		uint32_t sextet_d = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
		uint32_t triple = (sextet_a << 3 * 6) + (sextet_b << 2 * 6) + (sextet_c << 1 * 6) + (sextet_d << 0 * 6);

		if (j < *output_length) decoded_data[j++] = (triple >> 2 * 8) & 0xFF;
		if (j < *output_length) decoded_data[j++] = (triple >> 1 * 8) & 0xFF;
		if (j < *output_length) decoded_data[j++] = (triple >> 0 * 8) & 0xFF;
	}

	return decoded_data;
}

static void bin2hex(unsigned char * bin, int binsize, char * hex)
{
	char * hexptr;
	int i;

	hexptr = hex;
	for (i=0;i<binsize;i++)
	{
		sprintf(hexptr,"%02X",bin[i]);
		hexptr+=2;
	}

	*hexptr = 0;

}

#ifdef WASM
EMSCRIPTEN_KEEPALIVE
#endif
char * SPPoA_Generate_Proof(char * username, char * secret, char * params) 
{
	char message[200];
	int KEY_LEN = strlen(secret)/2;
	unsigned char pubkey[KEY_LEN];
	unsigned char input[SHA256_INPUTS] = {0}; // 512 bits

	memset(input,0,SHA256_INPUTS);
	memset(message,0,sizeof(message));
	strncpy(message,username,USER_LEN);
	strcat(message," knows the public key to this address");
	srand((unsigned) time(NULL));

	hex2bin(secret,strlen(secret),pubkey);

	int i = strlen(secret)/2; 
	
	//printf("Iterations of SHA: %d\n", NUM_ROUNDS);

	memset(input,0,sizeof(input));
	for(int j = 0; j<i; j++) {
		input[j] = pubkey[j];
	}
	unsigned char masterkeys[NUM_ROUNDS][16];
	unsigned char keys[NUM_ROUNDS][NUM_PARTIES][16];
	unsigned char rsseed[20];
	unsigned char rs[NUM_ROUNDS][NUM_PARTIES][4];

        //Generating keys
	Compute_RAND((unsigned char *)masterkeys, NUM_ROUNDS*16,input,i);  
	memset(rsseed,0,20);
	RAND_bytes((unsigned char *)&rsseed[4],16);
	for (int j = 0; j < NUM_ROUNDS; j++)
	{
		Compute_RAND((unsigned char *)keys[j], NUM_PARTIES*16,masterkeys[j],16);  
		memcpy((unsigned char *)rsseed,&j,sizeof(int));
		Compute_RAND((unsigned char *)rs[j],NUM_PARTIES*4,rsseed,20);
	}
        //Sharing secrets
	unsigned char shares[NUM_ROUNDS][NUM_PARTIES][SHA256_INPUTS];
	unsigned char ripeshares[NUM_ROUNDS][NUM_PARTIES][32];
	for (int j=0;j<NUM_ROUNDS;j++)
	{
		for (int k=0;k<NUM_PARTIES;k++)
		{
			Compute_RAND((unsigned char *)&(shares[j][k]),SHA256_INPUTS,(unsigned char *)keys[j][k],16);
			Compute_RAND((unsigned char *)&(ripeshares[j][k]),32,(unsigned char *)keys[j][k],15);
		}
	}
        //Generating randomness
	unsigned char *randomness[NUM_ROUNDS][NUM_PARTIES];

//	#pragma omp parallel for
	for(int k=0; k<NUM_ROUNDS; k++) {
		for(int j = 0; j<NUM_PARTIES; j++) {
			randomness[k][j]= (unsigned char *)malloc(rSize);
			memset(randomness[k][j],0,rSize);
			getAllRandomness(keys[k][j], randomness[k][j]);
		}
	}
	//compute AUX Tape
	SHA256_CTX ctx,hctx,H1ctx,H2ctx;
	unsigned char temphash1[SHA256_DIGEST_LENGTH];
	unsigned char temphash2[SHA256_DIGEST_LENGTH];
	unsigned char temphash3[SHA256_DIGEST_LENGTH];

	sha256_init(&H1ctx);
	for (int k = 0; k<NUM_ROUNDS;k++)
	{
		computeAuxTape(randomness[k],shares[k],ripeshares[k]);
		sha256_init(&hctx);
		for (int j = 0; j < NUM_PARTIES; j++)
		{
			sha256_init(&ctx);
			sha256_update(&ctx, keys[k][j], 16);
			if (j == (NUM_PARTIES-1))
			{
				sha256_update(&ctx, randomness[k][j], rSize);
			}
			sha256_update(&ctx, rs[k][j], 4);
			sha256_final(&ctx,temphash1);
			sha256_update(&hctx, temphash1, SHA256_DIGEST_LENGTH);
		}
		sha256_final(&hctx,temphash1);
		sha256_update(&H1ctx, temphash1, SHA256_DIGEST_LENGTH);
	}
	sha256_final(&H1ctx,temphash1);

	//Running MPC-SHA2 online
	unsigned char masked_result[NUM_ROUNDS][RIPEMD160_DIGEST_LENGTH];
	unsigned char party_result[NUM_PARTIES][RIPEMD160_DIGEST_LENGTH];
	unsigned char maskedInputs[NUM_ROUNDS][SHA256_INPUTS];
	View localViews[NUM_ROUNDS][NUM_PARTIES];
	memset(localViews,0,NUM_ROUNDS*NUM_PARTIES*sizeof(View));
	unsigned char H2[NUM_ROUNDS][SHA256_DIGEST_LENGTH];
	uint8_t ripehash[RIPEMD160_DIGEST_LENGTH];
	sha256_init(&H2ctx);
//	#pragma omp parallel for
	for(int k=0; k<NUM_ROUNDS; k++) {
		int countY = 0;

		mpc_compute(masked_result[k],maskedInputs[k],shares[k], ripeshares[k], input, i, randomness[k], localViews[k],party_result,&countY);
		sha256_init(&hctx);
		sha256_update(&hctx,maskedInputs[k],SHA256_INPUTS);
		sha256_update(&hctx,masked_result[k],SHA256_DIGEST_LENGTH);
		for (int j=0;j<NUM_PARTIES;j++)
			sha256_update(&hctx, (unsigned char*)localViews[k][j].y,ySize*4);
		sha256_update(&hctx, (unsigned char *)rs[k], NUM_PARTIES*4);
		sha256_final(&hctx,H2[k]);
		if (VERBOSE)
		{
			fprintf(stderr,"round %d H2: ",k);
			printdigest(H2[k]);
		}
		sha256_update(&H2ctx, H2[k], SHA256_DIGEST_LENGTH);
		if ((k == 0) && (VERBOSE))
		{
			fprintf(stderr,"Created proof for :");
			for (int j=0;j<RIPEMD160_DIGEST_LENGTH;j++)
			{
				unsigned char temp = masked_result[k][j];
				for (int i=0;i<NUM_PARTIES;i++)
				{
					temp ^= party_result[i][j];
				}
				fprintf(stderr,"%02X",temp);
				ripehash[j] = temp;
			}
			fprintf(stderr,"\n");
		}
	}
	sha256_final(&H2ctx,temphash2);
	sha256_init(&hctx);
	sha256_update(&hctx, temphash1, SHA256_DIGEST_LENGTH);
	sha256_update(&hctx, temphash2, SHA256_DIGEST_LENGTH);
	sha256_final(&hctx,temphash3);

	if (VERBOSE)
	{
		fprintf(stderr,"hashes: ");
		printdigest(temphash1);
		printdigest(temphash2);
		printdigest(temphash3);
	}

	//Committing
	z kkwProof;
	int es[NUM_ROUNDS];
	memcpy(kkwProof.H,temphash3,SHA256_DIGEST_LENGTH);
	memcpy(kkwProof.rsseed,&rsseed[4],16);
	H3(temphash3, NUM_ONLINE, es);

	int masterkeycount = 0;
	int onlinecount = 0;

	for (int i = 0; i < NUM_ROUNDS;i++)
	{
		if (!es[i])
		{
			memcpy(kkwProof.masterkeys[masterkeycount],masterkeys[i],16);
			memcpy(kkwProof.H2[masterkeycount++],H2[i],SHA256_DIGEST_LENGTH);
		}
		else
		{
			memcpy(kkwProof.auxBits[onlinecount],randomness[i][NUM_PARTIES-1],rSize);
			memcpy(kkwProof.maskedInput[onlinecount],maskedInputs[i],SHA256_INPUTS);
			int partycount = 0;
			for (int j = 0; j < NUM_PARTIES; j++)
			{
				if ((j+1) != es[i])
				{
					memcpy(kkwProof.keys[onlinecount][partycount++],keys[i][j],16);
				}
				else
				{
					sha256_init(&ctx);
					sha256_update(&ctx,keys[i][j],16);
					if (j == (NUM_PARTIES-1))
					{
						sha256_update(&ctx, randomness[i][NUM_PARTIES-1], rSize);
					}
					sha256_update(&ctx, rs[i][j], 4);
					sha256_final(&ctx,kkwProof.com[onlinecount]);
					memcpy(&kkwProof.views[onlinecount],&localViews[i][j],sizeof(View));
				}
				free(randomness[i][j]);
			}
			onlinecount++;
		}
	}
		
	//Writing to file
	uint32_t combined[5];
	unsigned char shahash[32];
	unsigned char addrbuf[100];
	char  addrstr[200];
	unsigned long int addrstrlen;

 	addrbuf[0] = 0;
	hex2bin(params,2,&(addrbuf[0]));
	memcpy(&addrbuf[1],ripehash,20);
	sha256_init(&ctx);
	sha256_update(&ctx,addrbuf,21);
	sha256_final(&ctx,shahash);
	sha256_init(&ctx);
	sha256_update(&ctx,shahash,sizeof(shahash));
	sha256_final(&ctx,shahash);

	memcpy(&(addrbuf[21]),shahash,4);

	addrstrlen = 200;
	memset(addrstr,0,addrstrlen);
	if (!b58enc(addrstr, &addrstrlen, addrbuf, 25))
	{
		printf("b58enc error\n");
		return NULL;
	}

	char *proof = malloc(P_SIZE);
	memset(proof,0,P_SIZE);
	sprintf(proof,"{\"ver\":\"AS%03d-%02d.%02d\",\"params\":\"%s\",\"wallet\":\"%s\",\"msg\":\"%s\",\"proof\":\"",NUM_ROUNDS,NUM_PARTIES,NUM_ONLINE,params,addrstr,message);
	size_t proofsize = P_SIZE - strlen(proof);
	base64_encode((unsigned char *)&kkwProof,sizeof(z),proof+strlen(proof),&proofsize);
	strcat(proof,"\"}");
	return proof;

}


static int isOnline(int es[NUM_ROUNDS], int round)
{
	return es[round];
}	

static char * getvalue(char * sourcestr)
{
	char * tempc, *tempstart;
	tempc  = sourcestr;
	while ((*tempc != '"') && (*tempc != 0))
	{
		tempc++;
	}
	if (tempc++)
	{
		tempstart = tempc;
		while ((*tempc != '"') && (*tempc != 0))
		{
			tempc++;
		}
 		*tempc = 0;
		return tempstart;
	}
	return NULL;
}

#ifdef WASM
EMSCRIPTEN_KEEPALIVE
#endif
char * SPPoA_Verify_Proof(char * prooffile) {

	char * ret = malloc(1000);	
	char * jsonproof = NULL;
	z kkwProof;
	size_t kkwProofsize = sizeof(z);
	FILE *file;
	static int once = 0;

	file = fopen(prooffile, "r");
	if (!file) {
		printf("Unable to open file %s!\n",prooffile);
		return NULL;
	}
	jsonproof = malloc(P_SIZE+1);
	memset(jsonproof,0,P_SIZE+1);
	fread(jsonproof,1,P_SIZE,file);
	fclose(file);
	if (jsonproof[strlen(jsonproof)-1] == '\n')
		jsonproof[strlen(jsonproof)-1] = 0; 
	if (!base64_decode(jsonproof,strlen(jsonproof),(unsigned char*)&kkwProof,&kkwProofsize))
	{
		free(jsonproof);
		printf("unable to decode file %s\n",prooffile);
		return NULL; 
	}

	free(jsonproof);
	int es[NUM_ROUNDS];
	memset(es,0,NUM_ROUNDS*sizeof(int));
	H3(kkwProof.H, NUM_ONLINE, es);

	unsigned char keys[NUM_ROUNDS][NUM_PARTIES][16];
	unsigned char rsseed[20];
	unsigned char rs[NUM_ROUNDS][NUM_PARTIES][4];
	unsigned char shares[NUM_ROUNDS][NUM_PARTIES][SHA256_INPUTS];
	unsigned char ripeshares[NUM_ROUNDS][NUM_PARTIES][32];
	unsigned char *randomness[NUM_ROUNDS][NUM_PARTIES];

	for (int j = 0; j < NUM_ROUNDS; j++)
		for (int k = 0; k < NUM_PARTIES; k++)
		{
			randomness[j][k] = (unsigned char *) malloc(rSize);
			memset(randomness[j][k],0,rSize);
		}
	memset(shares,0,NUM_ROUNDS*NUM_PARTIES*SHA256_INPUTS);
	memcpy(&rsseed[4],kkwProof.rsseed,16);
	int roundctr = 0;
	int partyctr = 0;
	int onlinectr = 0;
	for (int j = 0; j < NUM_ROUNDS; j++)
	{
		memcpy((unsigned char *)rsseed,&j,sizeof(int));
		Compute_RAND((unsigned char *)rs[j],NUM_PARTIES*4,rsseed,20);
		if (!isOnline(es,j))
		{
			Compute_RAND((unsigned char *)keys[j], NUM_PARTIES*16,kkwProof.masterkeys[roundctr++],16);

			for (int k = 0; k < NUM_PARTIES; k++)
			{
				Compute_RAND((unsigned char *)&(shares[j][k]),SHA256_INPUTS,(unsigned char *)keys[j][k],16);
				Compute_RAND((unsigned char *)&(ripeshares[j][k]),32,(unsigned char *)keys[j][k],15);
				getAllRandomness(keys[j][k], randomness[j][k]);
			}
			computeAuxTape(randomness[j],shares[j],ripeshares[j]);
		}
		else
		{
			partyctr = 0;
			for (int k = 0; k < NUM_PARTIES;k++)
			{
				if ((k+1) != es[j])
				{
					memcpy((unsigned char *)keys[j][k],kkwProof.keys[onlinectr][partyctr++],16);
					Compute_RAND((unsigned char *)&(shares[j][k]),SHA256_INPUTS,(unsigned char *)keys[j][k],16);
					Compute_RAND((unsigned char *)&(ripeshares[j][k]),32,(unsigned char *)keys[j][k],15);
					getAllRandomness(keys[j][k], randomness[j][k]);
				}
				else
				{
					// ?? online how
					memset(randomness[j][k],0,rSize);
				}

			}
			memcpy(randomness[j][NUM_PARTIES-1],kkwProof.auxBits[onlinectr],rSize);
			onlinectr++;
		}
	}
	SHA256_CTX ctx,hctx,H1ctx,H2ctx;
	unsigned char H1hash[SHA256_DIGEST_LENGTH];
	unsigned char H2hash[SHA256_DIGEST_LENGTH];
	unsigned char temphash1[SHA256_DIGEST_LENGTH];
	unsigned char temphash2[SHA256_DIGEST_LENGTH];
	unsigned char masked_result[RIPEMD160_DIGEST_LENGTH];
	unsigned char party_result[NUM_PARTIES][RIPEMD160_DIGEST_LENGTH];
	View localViews[NUM_ONLINE][NUM_PARTIES];
	memset(localViews,0,NUM_ONLINE*NUM_PARTIES*sizeof(View));

	roundctr = 0;

	sha256_init(&H1ctx);
	for (int k = 0; k<NUM_ROUNDS;k++)
	{
		if (!isOnline(es,k))
		{
			sha256_init(&hctx);
			for (int j = 0; j < NUM_PARTIES; j++)
			{
				sha256_init(&ctx);
				sha256_update(&ctx, keys[k][j], 16);
				if (j == (NUM_PARTIES-1))
				{
/*
					size_t pos = 0;
					memset(auxBits,0,rSize/8+1);
                               	 // need to include aux tape
    					for (int i = 1; i < rSize; i+=2)
       					{
						uint8_t auxBit = getBit(randomness[k][j],i);
						setBit(auxBits,pos,auxBit);
						pos++;
					}
*/
             				sha256_update(&ctx, randomness[k][NUM_PARTIES-1], rSize);
				}
				sha256_update(&ctx, rs[k][j], 4);
				sha256_final(&ctx,temphash1);
				sha256_update(&hctx,temphash1,SHA256_DIGEST_LENGTH);
				free(randomness[k][j]);
  			}
			sha256_final(&hctx,temphash2);
			sha256_update(&H1ctx, temphash2, SHA256_DIGEST_LENGTH);
		}
		else
		{
			sha256_init(&hctx);
			for (int j = 0; j < NUM_PARTIES; j++)
			{
				if ((j+1) != es[k])
				{
					sha256_init(&ctx);
					sha256_update(&ctx, keys[k][j], 16);
					if (j == (NUM_PARTIES-1))
					{
             					sha256_update(&ctx, kkwProof.auxBits[roundctr], rSize);
					}
					sha256_update(&ctx, rs[k][j], 4);
					sha256_final(&ctx,temphash1);
				}
				else
				{
					memcpy(temphash1,kkwProof.com[roundctr],SHA256_DIGEST_LENGTH);
				}
				sha256_update(&hctx,temphash1,SHA256_DIGEST_LENGTH);
			}
			sha256_final(&hctx,temphash2);
			sha256_update(&H1ctx, temphash2, SHA256_DIGEST_LENGTH);
			roundctr++;
		}
	}
	sha256_final(&H1ctx,H1hash);

	sha256_init(&H2ctx);
	roundctr = 0;
	onlinectr = 0;
	for (int k=0; k < NUM_ROUNDS; k++)
	{
		int countY = 0;
		if (!isOnline(es,k))
		{
			sha256_update(&H2ctx,kkwProof.H2[roundctr++],SHA256_DIGEST_LENGTH);
		}
		else
		{
			sha256_init(&hctx);
			sha256_update(&hctx,kkwProof.maskedInput[onlinectr],SHA256_INPUTS);
			memcpy(&localViews[onlinectr][es[k]-1],&kkwProof.views[onlinectr],sizeof(View));
			mpc_compute(masked_result,kkwProof.maskedInput[onlinectr],shares[k],ripeshares[k], NULL,es[k]-1,randomness[k],localViews[onlinectr],party_result,&countY);
			if (VERBOSE)
			{
				fprintf(stderr,"mpc round %d verification of hash: ",k);
				for (int j=0;j<SHA256_DIGEST_LENGTH;j++)
				{
					unsigned char temp = masked_result[j];
					for (int i=0;i<NUM_PARTIES;i++)
					{
						temp ^= party_result[i][j];
					}
					fprintf(stderr,"%02X",temp);
				}
				fprintf(stderr,"\n");
		//		once = 1;
			}
			sha256_update(&hctx,masked_result,SHA256_DIGEST_LENGTH);
			for (int j = 0; j < 32; j++)
				sha256_update(&hctx, (unsigned char*)localViews[onlinectr][j].y,ySize*4);
			sha256_update(&hctx,(unsigned char*)rs[k],NUM_PARTIES*4);
			sha256_final(&hctx,temphash1);
			if (VERBOSE)
			{
				fprintf(stderr,"round %d H2: ",k);
				printdigest(temphash1);
			}
			sha256_update(&H2ctx,temphash1,SHA256_DIGEST_LENGTH);
			for (int j = 0; j<NUM_PARTIES;j++)
				free(randomness[k][j]);

			onlinectr++;
		}
	}
	sha256_final(&H2ctx,H2hash);

	sha256_init(&hctx);
	sha256_update(&hctx,H1hash,SHA256_DIGEST_LENGTH);
	sha256_update(&hctx,H2hash,SHA256_DIGEST_LENGTH);
	sha256_final(&hctx,temphash1);

	if (VERBOSE)
	{
		fprintf(stderr,"hashes: ");
		printdigest(H1hash);
		printdigest(H2hash);
		printdigest(temphash1);
	}
	if (memcmp(temphash1,kkwProof.H,SHA256_DIGEST_LENGTH))
	{
		sprintf(ret,"Error: Hash does not match\n");
	}		
	else
	{
		sprintf(ret,"Received pre-image proof for hash : ");
		for (int j = 0; j<SHA256_DIGEST_LENGTH;j++)
		{
			unsigned char temp = masked_result[j];
			char hexstr[3] = {0};
			for (int i=0;i<NUM_PARTIES;i++)
			{
				temp ^= party_result[i][j];
			}
			sprintf(hexstr,"%02X",temp);
			strcat(ret,hexstr);
		}
		strcat(ret,"\n");		
	}
	return ret;	
}
	
#ifdef WASM
EMSCRIPTEN_KEEPALIVE
#endif
void clearbuf(char * ret)
{
	if (ret)
		free(ret);
}

#ifndef WASM
int main(int argc, char * argv[])
{
	char * rc;

	if ((argc != 5) && (argc != 3))
	{
		printf("Usage: %s <func: 1=generate> <message> <key/proof> <params>\n",argv[0]);
		printf("Usage: %s <func: 2=verify> <proof file>\n",argv[0]);
		return -1;
	}
	if ((argv[1][0] == '1') && (argc == 5))
	{
		rc = SPPoA_Generate_Proof(argv[2],argv[3],argv[4]);
		printf("%s",rc);
	}
	else if ((argv[1][0] == '2') && (argc == 3))
	{
		rc = SPPoA_Verify_Proof(argv[2]);
		printf("%s",rc);
	}
	else
	{
		printf("Usage: %s <func: 1=generate> <message> <key/proof> <params>\n",argv[0]);
		printf("Usage: %s <func: 2=verify> <proof file>\n",argv[0]);
		return -1;
	}
	if (rc)
	{
		clearbuf(rc);
		return 0;
	}
	return -1;

}

#endif
