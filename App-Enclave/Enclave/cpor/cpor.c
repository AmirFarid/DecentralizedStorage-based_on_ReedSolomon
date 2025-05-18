/*
 *
 *
 *
 *
 */

#include "Enclave_t.h"
#include "sgx_trts.h"

#include <string.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "prp.h"
#include "cpor.h"
#include "sharedTypes.h"

void generate_random_mod_p(char* prf_key, int key_len, unsigned char *i, int i_len, BIGNUM *p, BIGNUM *result) 
{
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;

    // Compute the PRF value
    HMAC(EVP_sha256(), prf_key, key_len, i, i_len, hash, &hash_len);
    // Convert the PRF value to a BIGNUM
    BIGNUM *bn_prf = BN_new();
    BN_bin2bn(hash, hash_len, bn_prf);

    // Compute the random number modulo p
    BN_CTX *ctx = BN_CTX_new();
    BN_mod(result, bn_prf, p, ctx);

    // Clean up memory
    BN_free(bn_prf);
}



void prepare_tag(Tag *tag, PorSK porSk) {
    if (!tag || !porSk.encKey || !porSk.macKey) {
        // Handle null pointer error
        return;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        // Handle error
        return;
    }

    // Define IV for testing purposes only
    const unsigned char iv[] = "0123456789abcdef";

    // Encrypt alpha using encKey
    int outlen;
    int len = (SEGMENT_PER_BLOCK * PRIME_LENGTH / 8) + KEY_SIZE;
    unsigned char *out = malloc(len + EVP_MAX_BLOCK_LENGTH);
    if (!out) {
        EVP_CIPHER_CTX_free(ctx);
        // Handle memory allocation error
        return;
    }

    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, porSk.encKey, iv);
    EVP_EncryptUpdate(ctx, out, &outlen, tag->prfKey, len);
    EVP_EncryptFinal_ex(ctx, out + outlen, &outlen);
    memcpy(tag->prfKey, out, len);
    free(out);

    // Compute MAC using macKey
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        EVP_CIPHER_CTX_free(ctx);
        // Handle error
        return;
    }

    const EVP_MD *md = EVP_sha1();
    uint8_t *mac_data[3] = { (uint8_t*)&tag->n, tag->prfKey, (uint8_t*)tag->alpha };
    int mac_data_len[3] = { sizeof(tag->n), KEY_SIZE, (PRIME_LENGTH / 8) * SEGMENT_PER_BLOCK };
    uint8_t mac[MAC_SIZE];
    unsigned int mac_len;

    EVP_DigestInit_ex(md_ctx, md, NULL);
    EVP_DigestUpdate(md_ctx, porSk.macKey, MAC_SIZE);
    for (int i = 0; i < 3; i++) {
        EVP_DigestUpdate(md_ctx, mac_data[i], mac_data_len[i]);
    }

    EVP_DigestFinal_ex(md_ctx, mac, &mac_len);
    memcpy(tag->MAC, mac, MAC_SIZE);

    EVP_CIPHER_CTX_free(ctx);
    EVP_MD_CTX_free(md_ctx);
}

void decrypt_tag(Tag *tag, PorSK porSk) 
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    const unsigned char iv[] = "0123456789abcdef";

    // Decrypt alpha using encKey
    int outlen;
    int len = (SEGMENT_PER_BLOCK * PRIME_LENGTH / 8) + KEY_SIZE;
    unsigned char *out = malloc(len + EVP_MAX_BLOCK_LENGTH);

    if (out == NULL) {
        // Handle memory allocation error
    }

    EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, porSk.encKey, iv);
    EVP_DecryptUpdate(ctx, out, &outlen, tag->prfKey, len);
    EVP_DecryptFinal_ex(ctx, out + outlen, &outlen);
    memcpy(tag->prfKey, out, len);

    EVP_CIPHER_CTX_free(ctx);
    free(out);
    //free(prfKey_out);
}


void gen_challenge(int totalSegments, uint8_t *indices, uint8_t *coefficients, uint8_t *prime) 
{
    BIGNUM *bn_coefficient;
    BIGNUM *bn_prime = BN_bin2bn(prime, PRIME_LENGTH / 8, NULL);
    BN_CTX *ctx = BN_CTX_new();

    int i, j;
    for (i = 0; i < NUM_CHAL_BLOCKS; i++) {
        int bad = 1;
        while(bad == 1) {
            /* Generate a random index between 0 and totalSegments - 1 */
            sgx_read_rand(&indices[i], sizeof(uint8_t));
            indices[i] = indices[i] % totalSegments;

            /* Generate a random coefficient using OpenSSL BIGNUMs */
            bn_coefficient = BN_new();
            BN_rand_range(bn_coefficient, bn_prime);
            BN_bn2bin(bn_coefficient, coefficients + i * (PRIME_LENGTH / 8));
            BN_free(bn_coefficient);

            /* Check if the index has already been generated */
            bad = 0;
            for(j = 0 ; j < i; j++) {
                if(indices[j] == indices[i] || indices[i] < 1) {
                    bad = 1;
                    break;
                }
            }
        }
    }

    BN_free(bn_prime);
    BN_CTX_free(ctx);
}


PorSK por_init() 
{
	
	PorSK porSKL;

	if(sgx_read_rand(porSKL.encKey, KEY_SIZE) != SGX_SUCCESS) {
		// handle error
	}

	if(sgx_read_rand(porSKL.macKey, KEY_SIZE) != SGX_SUCCESS) {
		// handle error
	}

	return porSKL;
}

void gen_file_tag(BIGNUM *prime, Tag *tag) 
{

    // Generate prfKey
    if(sgx_read_rand(tag->prfKey, KEY_SIZE) != SGX_SUCCESS) {
        // handle error
    }


	BIGNUM *alpha_BN[SEGMENT_PER_BLOCK];

	for(int i = 0; i < SEGMENT_PER_BLOCK; i++) {
    	alpha_BN[i] = BN_new(); // Allocate memory for a new BIGNUM object

    	if(!BN_rand_range(alpha_BN[i], prime)) { // Will generate random number in range(0, prime - 1)
       		// handle error
    	}

    	BN_bn2bin(alpha_BN[i], tag->alpha[i]);
	}

    return tag;
}


/*
 * Input: key - The key used in the PRP. 
 * 		  numBlocks
 *        numGroups
 * Output: groups - a 2d array representing which blocks are in each group. groups[group][index]
 */
uint64_t** get_groups(const uint8_t *key, int numBlocks, int numGroups) 
{
    int maxBlocksPerGroup = (int) ceil((double) numBlocks / numGroups);

    // Allocate memory and initialize values
    uint64_t **groups = malloc(numGroups * sizeof(uint64_t*));
    for(int i = 0; i < numGroups; i++) {
        groups[i] = malloc(maxBlocksPerGroup * sizeof(uint64_t));
    }
    for(int i = 0; i < numGroups; i++) {
        for(int j = 0; j < numBlocks; j++) {
            groups[i][j] = -1;
        }

    }

	int groupIdx[numGroups]; // Current index for each group
	for(int i = 0; i < numGroups; i++) {
		groupIdx[i] = 0;
	}

	int iter = 0;
	int prevbits = 0;
	int groupNum = 0;
    while (numBlocks != 0) {
        int numBits = (int)floor(log2(numBlocks));
        int numBlocksInIter = (int)pow(2, numBits);
        int remainingBlocks = numBlocks - numBlocksInIter;

        for (int blockNum = 0; blockNum < numBlocksInIter; blockNum++) {

            int index = feistel_network_prp(key, blockNum, numBits);

			if(iter == 0) {
				groupNum = index % numGroups;
			}
			else {
				groupNum = (index + (int) pow(2, prevbits)) % numGroups;
			}
            groups[groupNum][groupIdx[groupNum]] = blockNum + remainingBlocks;
			groupIdx[groupNum]++;
        }

        numBlocks = remainingBlocks;
		iter++;
		prevbits = numBits;
    }

    return groups;
}

// Amir M M Farid

uint64_t** shuffle_blocks(const uint8_t *key, int numBlocks) 
{

    // Allocate memory and initialize values
    uint64_t **shuffledBlocks = malloc(numBlocks * sizeof(uint64_t*));
    for(int i = 0; i < numBlocks; i++) {
        shuffledBlocks[i] = malloc(sizeof(uint64_t));
    }
    // for(int i = 0; i < numBlocks; i++) {
    //     for(int j = 0; j < numBlocks; j++) {
    //         shuffledBlocks[i][j] = -1;
    //     }

    // }

	int blockIdx[numBlocks]; // Current index for each group
	for(int i = 0; i < numBlocks; i++) {
		blockIdx[i] = 0;
	}

	int iter = 0;
	int prevbits = 0;
	int groupNum = 0;
    while (numBlocks != 0) {
        int numBits = (int)floor(log2(numBlocks));
        int numBlocksInIter = (int)pow(2, numBits);
        int remainingBlocks = numBlocks - numBlocksInIter;

        for (int blockNum = 0; blockNum < numBlocksInIter; blockNum++) {

            int index = feistel_network_prp(key, blockNum, numBits);

			if(iter == 0) {
				groupNum = index % numBlocks;
			}
			else {
				groupNum = (index + (int) pow(2, prevbits)) % numBlocks;
			}
            shuffledBlocks[groupNum][blockIdx[groupNum]] = blockNum + remainingBlocks;
			blockIdx[groupNum]++;
        }

        numBlocks = remainingBlocks;
		iter++;
		prevbits = numBits;
    }

    return shuffledBlocks;
}



// end Amir M M Farid




// void get_sigma(BIGNUM *sigma, BIGNUM **data, BIGNUM **alpha, uint8_t blockNum, uint8_t *prfKey, BIGNUM *prime) {

// 	BIGNUM *blockRand;
// 	BIGNUM *result;
// 	BIGNUM *sum;
// 	BN_CTX *ctx;

// //	BIGNUM *randAtI = BN_new();
// 	result = BN_new();
// 	sum = BN_new();
// 	ctx = BN_CTX_new();
// 	blockRand = BN_new();

// 	BN_zero(sum);

// 	generate_random_mod_p(prfKey, KEY_SIZE, &blockNum, sizeof(uint8_t), prime, blockRand);

// 	for(int i = 0; i < SEGMENT_PER_BLOCK; i++) {
// 		BN_mod_mul(result, data[i], alpha[i], prime, ctx);
// 		BN_mod_add(sum, sum, result, prime, ctx);
// 	}

// 	BN_mod_add(sigma, sum, blockRand, prime, ctx);

// 	return;
// }


