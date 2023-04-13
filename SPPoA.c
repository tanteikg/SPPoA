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
#define GETBIT(x, i) (((x) >> (i)) & 0x01)
#define SETBIT(x, i, b)   x= (b)&1 ? (x)|(1 << (i)) : (x)&(~(1 << (i)))

// prototype from hash.c
// to implement using sha256 instead of sha3

#define MAX_DIGEST_SIZE 64
#define SHA256_DIGEST_SIZE 32

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
	char * namestr = "pQCee AStablish";
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
        unsigned char hashbuf[SHA256_BLOCK_SIZE];
        int len;
        sha256_init(&ctx);
        sha256_update(&ctx,iv,strlen((char *)iv));
        sha256_update(&ctx,plaintext,strlen((char *)plaintext));
        sha256_update(&ctx,key,16);
        sha256_final(&ctx,hashbuf);
        for(int j=0;j<(rSize/16);j++) {
                sha256_init(&ctx);
                sha256_update(&ctx,hashbuf,SHA256_BLOCK_SIZE);
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


static int computeAuxTape(unsigned char *randomness[NUM_PARTIES],unsigned char shares[NUM_PARTIES][SHA256_INPUTS])
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

static uint32_t consol(uint32_t array[NUM_PARTIES])
{
	uint32_t ret = 0;
	for (int i = 0; i<NUM_PARTIES;i++)
		ret ^= array[i];
	return ret;
}



static int mpc_sha256(unsigned char masked_result[SHA256_DIGEST_LENGTH], unsigned char masked_input[SHA256_INPUTS], unsigned char shares[NUM_PARTIES][SHA256_INPUTS], unsigned char * inputs, int numBytes, unsigned char *randomness[NUM_PARTIES], View views[NUM_PARTIES], unsigned char party_result[NUM_PARTIES][SHA256_DIGEST_LENGTH], int* countY) 
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

		memcpy(masked_input, (unsigned char *) w_state, 64);
	}
	else // verify
		memcpy((unsigned char *)w_state,masked_input,64);

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

	for (int i = 0; i < 8; i++)
	{
		for (int j = 0; j < NUM_PARTIES; j++)
		{
			if (inputs)
			{
				views[j].y[*countY] = hHa[i][j];
			}
			else
			{
				if (j == numBytes)
					hHa[i][j] = views[j].y[*countY];
				else
					views[j].y[*countY] = hHa[i][j];
			}
		}
		*countY+=1;
	}
	for (int i = 0; i < 8; i++) {
		mpc_RIGHTSHIFT(hHa[i], 24, t0);
		t0_state = hHa_state[i] >> 24;

		for (int j = 0;j< NUM_PARTIES;j++)
			party_result[j][i * 4] = t0[j];
		masked_result[i*4] = t0_state;

		mpc_RIGHTSHIFT(hHa[i], 16, t0);
		t0_state = hHa_state[i] >> 16;
		for (int j = 0;j< NUM_PARTIES;j++)
			party_result[j][i * 4 + 1] = t0[j];
		masked_result[i*4+1] = t0_state;

		mpc_RIGHTSHIFT(hHa[i], 8, t0);
		t0_state = hHa_state[i] >> 8;
		for (int j = 0;j< NUM_PARTIES;j++)
			party_result[j][i * 4 + 2] = t0[j];
		masked_result[i*4+2] = t0_state;

		for (int j = 0;j< NUM_PARTIES;j++)
			party_result[j][i * 4 + 3] = hHa[i][j];
		masked_result[i*4+3] = hHa_state[i];
	}
//	printf("mpc_sha256: randCount %d\n",randCount);

	return 0;
}

static void printdigest(unsigned char * digest)
{
	for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
		printf("%02x",digest[i]);
	printf("\n");
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
	for (int j=0;j<NUM_ROUNDS;j++)
	{
		for (int k=0;k<NUM_PARTIES;k++)
			Compute_RAND((unsigned char *)&(shares[j][k]),SHA256_INPUTS,(unsigned char *)keys[j][k],16);
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
		computeAuxTape(randomness[k],shares[k]);
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
					setBit(auxBits[k],pos,auxBit);
					pos++;
				}
*/
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
	unsigned char masked_result[NUM_ROUNDS][SHA256_DIGEST_LENGTH];
	unsigned char party_result[NUM_PARTIES][SHA256_DIGEST_LENGTH];
	unsigned char maskedInputs[NUM_ROUNDS][SHA256_INPUTS];
	View localViews[NUM_ROUNDS][NUM_PARTIES];
	unsigned char H2[NUM_ROUNDS][SHA256_DIGEST_LENGTH];
	sha256_init(&H2ctx);
//	#pragma omp parallel for
	for(int k=0; k<NUM_ROUNDS; k++) {
		int countY = 0;

		mpc_sha256(masked_result[k],maskedInputs[k],shares[k],input, i, randomness[k], localViews[k],party_result,&countY);
		sha256_init(&hctx);
		sha256_update(&hctx,maskedInputs[k],SHA256_INPUTS);
		sha256_update(&hctx,masked_result[k],SHA256_DIGEST_LENGTH);
		for (int j=0;j<NUM_PARTIES;j++)
			sha256_update(&hctx, (unsigned char*)localViews[k][j].y,ySize*4);
		sha256_update(&hctx, (unsigned char *)rs[k], NUM_PARTIES*4);
		sha256_final(&hctx,H2[k]);
		sha256_update(&H2ctx, H2[k], SHA256_DIGEST_LENGTH);
		if ((k == 0) && (VERBOSE))
		{
			printf("countY %d result of hash:",countY);
			for (int j=0;j<SHA256_DIGEST_LENGTH;j++)
			{
				unsigned char temp = masked_result[k][j];
				for (int i=0;i<NUM_PARTIES;i++)
				{
					temp ^= party_result[i][j];
				}
				printf("%02X",temp);
			}
			printf("\n");
		}
	}
	sha256_final(&H2ctx,temphash2);
	sha256_init(&hctx);
	sha256_update(&hctx, temphash1, SHA256_DIGEST_LENGTH);
	sha256_update(&hctx, temphash2, SHA256_DIGEST_LENGTH);
	sha256_final(&hctx,temphash3);

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
	char *proof = malloc(P_SIZE);
	size_t proofsize = P_SIZE;
	memset(proof,0,P_SIZE);
	base64_encode((unsigned char *)&kkwProof,sizeof(z),proof,&proofsize);
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
	}
	jsonproof = malloc(P_SIZE+1);
	memset(jsonproof,0,P_SIZE+1);
	fread(jsonproof,1,P_SIZE,file);
	fclose(file);
	if (jsonproof[strlen(jsonproof)-1] == '\n')
		jsonproof[strlen(jsonproof)-1] = 0; 
	base64_decode(jsonproof,strlen(jsonproof),(unsigned char*)&kkwProof,&kkwProofsize);
	free(jsonproof);
	int es[NUM_ROUNDS];
	memset(es,0,NUM_ROUNDS*sizeof(int));
	H3(kkwProof.H, NUM_ONLINE, es);

	unsigned char keys[NUM_ROUNDS][NUM_PARTIES][16];
	unsigned char rsseed[20];
	unsigned char rs[NUM_ROUNDS][NUM_PARTIES][4];
	unsigned char shares[NUM_ROUNDS][NUM_PARTIES][SHA256_INPUTS];
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
				getAllRandomness(keys[j][k], randomness[j][k]);
			}
			computeAuxTape(randomness[j],shares[j]);
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
	unsigned char masked_result[SHA256_DIGEST_LENGTH];
	unsigned char party_result[NUM_PARTIES][SHA256_DIGEST_LENGTH];
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
			mpc_sha256(masked_result,kkwProof.maskedInput[onlinectr],shares[k],NULL,es[k]-1,randomness[k],localViews[onlinectr],party_result,&countY);
			if (0)
			{
				printf("mpc round %d verification of hash: ",k);
				for (int j=0;j<SHA256_DIGEST_LENGTH;j++)
				{
					unsigned char temp = masked_result[j];
					for (int i=0;i<NUM_PARTIES;i++)
					{
						temp ^= party_result[i][j];
					}
					printf("%02X",temp);
				}
				printf("\n");
		//		once = 1;
			}
			sha256_update(&hctx,masked_result,SHA256_DIGEST_LENGTH);
			for (int j = 0; j < 32; j++)
				sha256_update(&hctx, (unsigned char*)localViews[onlinectr][j].y,ySize*4);
			sha256_update(&hctx,(unsigned char*)rs[k],NUM_PARTIES*4);
			sha256_final(&hctx,temphash1);
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
