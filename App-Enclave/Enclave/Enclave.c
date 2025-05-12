/*
 *
 *
 *
 *
 */


#include "sgx_trts.h"
#include "Enclave_t.h"
#include "pthread.h" // Is this being used?

#include "sharedTypes.h"
#include "enDefs.h"

/* 
 * TODO: maybe these should be actually installed as C libraries as libfec is.
 * I need to make a list of what exactly is also running in the FTL, So this can be done.
 */
#include "ecdh.h"
#include "cpor.h"
#include "hmac.h"
#include "aes.h"
#include "prp.h"


#include <fec.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <math.h>

// TODO: How should these be stored?
uint8_t dh_sharedKey[ECC_PUB_KEY_SIZE];
PorSK porSK;
File files[MAX_FILES];

#ifdef TEST_MODE

static BIGNUM *testFile[SEGMENT_PER_BLOCK * 10];
static BIGNUM *testPrime;
static BIGNUM *testSigmas[10];
static BIGNUM *testCoefficients[5];
static BIGNUM *testAlphas[SEGMENT_PER_BLOCK];
static BIGNUM *testRandoms[10];

#endif 

/* pseudo random number generator with 128 bit internal state... probably not suited for cryptographical usage */
typedef struct
{
  uint32_t a;
  uint32_t b;
  uint32_t c;
  uint32_t d;
} prng_t;

static prng_t prng_ctx;

static uint32_t prng_rotate(uint32_t x, uint32_t k)
{
  return (x << k) | (x >> (32 - k)); 
}

static uint32_t prng_next(void)
{
  uint32_t e = prng_ctx.a - prng_rotate(prng_ctx.b, 27); 
  prng_ctx.a = prng_ctx.b ^ prng_rotate(prng_ctx.c, 17); 
  prng_ctx.b = prng_ctx.c + prng_ctx.d;
  prng_ctx.c = prng_ctx.d + e; 
  prng_ctx.d = e + prng_ctx.a;
  return prng_ctx.d;
}

static void prng_init(uint32_t seed)
{
  uint32_t i;
  prng_ctx.a = 0xf1ea5eed;
  prng_ctx.b = prng_ctx.c = prng_ctx.d = seed;

  for (i = 0; i < 31; ++i) 
  {
    (void) prng_next();
  }
}

// AES decrypt function
#define NUM1 (1 << 24)
#define NUM2 (1 << 16)
#define NUM3 (1 << 8)
int DecryptData(uint32_t* KEY,void* buffer, int dataLen)
{
   //decrypt after read
    AesCtx ctx;
    unsigned char iv[] = "1234"; // Needs to be same between FTL and SGX
    unsigned char key[16];
    uint8_t i;
    for(i=0;i<4;i++){    
    	key[4*i]=(*(KEY+i))/NUM1;
    	key[(4*i)+1]=((*(KEY+i))/NUM2)%NUM3;
    	key[(4*i)+2]=(*(KEY+i)% NUM2)/NUM3;
    	key[(4*i)+3]=(*(KEY+i)% NUM2)%NUM3;
    }
    
   if( AesCtxIni(&ctx, iv, key, KEY128, EBC) < 0) return -1;

   if (AesDecrypt(&ctx, (unsigned char *)buffer, (unsigned char *)buffer, dataLen) < 0) return -1;

   return 0;
}

int EncryptData(uint32_t* KEY,void* buffer, int dataLen)
{
    //encrypt before writing
    AesCtx ctx;
    unsigned char iv[] = "1234";
    //unsigned char key[] = "876543218765432";
    unsigned char key[16];    
    uint8_t i;
    for(i=0;i<4;i++){    
     key[4*i]=(*(KEY+i))/NUM1;
     key[(4*i)+1]=((*(KEY+i))/NUM2)%NUM3;
     key[(4*i)+2]=(*(KEY+i)% NUM2)/NUM3;
     key[(4*i)+3]=(*(KEY+i)% NUM2)%NUM3;
    }
    for(i=0;i<16;i++){ 
     // uart_printf("EncryptData():the %d byte of key is %x\n\r",i,key[i]); 
    }
    
    //uart_printf("before encrypt: %s\n\r", buffer);
    
   // initialize context and encrypt data at one end    
    if( AesCtxIni(&ctx, iv, key, KEY128, EBC) < 0) {
        //uart_printf("init error\n");
	}

    
    int flag = 0;
    if ((flag = AesEncrypt(&ctx, (unsigned char *)buffer, (unsigned char *)buffer, dataLen)) < 0) 
      // dataLen needs to be different based on PDP vs ECC. Full 512 byte segment for ECC. KEY_SIZE for PDP.
    {
       //uart_printf("error in encryption\n");
       if(flag == -2)
      {
        //uart_printf("Data is empty");
        //return -2;
      }
      else if(flag == -3)
      {
        //uart_printf("cipher is empty");
      //return -3;
      }
      else if(flag == -4)
      {
        //uart_printf("context is empty");
       // return -4;
      }
      else if(flag == -5)
      {
        //uart_printf("data length is not a multiple of 16");
      //return -5;
      }
      else
      {
        //uart_printf("other error");
      }    
    }else{
      //uart_printf("encryption ok %d\n\r",count_write);
      //uart_printf("after encrypt: %s\n\r", buffer);      
    }
  return 0;
}

// Uses repeated calls to ocall_printf, to print arbitrarily sized bignums
void printBN(BIGNUM *bn, int size) 
{
	uint8_t temp[size];
	BN_bn2bin(bn, temp);
	ocall_printf(temp, size, 1);
}

/*
 * The get_sigma procedure is used to generate sigma, a tag generated for each file block which is used in data integrity auditing.
 * 
 * The resulting sigma is stored in the sigma parameter
 * The the product of data and alpha are summed over each sector (each sector has a corresponding alpha). 
 * generate_random_mod_p uses prfKey to generate a random number. This random number is added to the sum to get sigma.
 * This is all modular arithmatic, so the prime modulus is taken as an additional parameter. 
 */
void get_sigma(BIGNUM *sigma, BIGNUM **data, BIGNUM **alpha, uint8_t blockNum, uint8_t *prfKey, BIGNUM *prime) 
{

	BIGNUM *blockRand;
	BIGNUM *result;
	BIGNUM *sum;
	BN_CTX *ctx;

	blockRand = BN_new();
	result = BN_new();
	sum = BN_new();
	
	BN_zero(blockRand);
	BN_zero(result);
	BN_zero(sum);

	ctx = BN_CTX_new();

	#ifdef TEST_MODE

	testRandoms[blockNum] = BN_new();
	BN_zero(testRandoms[blockNum]);
	BN_copy(testRandoms[blockNum], blockRand);

	#endif

	for(int i = 0; i < SEGMENT_PER_BLOCK; i++) {

		#ifdef TEST_MODE
		if(BN_cmp(data[i], testFile[blockNum * SEGMENT_PER_BLOCK + i]) != 0) {
			ocall_printf("fail file", 10, 0);
		}

		if(BN_cmp(alpha[i], testAlphas[i]) != 0) {
			ocall_printf("fail alpha3", 12, 0);
		}
		#endif

		BN_mod(data[i], data[i], prime, ctx);
		BN_mod_mul(result, data[i], alpha[i], prime, ctx);

		BN_mod_add(sum, sum, result, prime, ctx);
	}
	uint8_t randbuf[PRIME_LENGTH / 8];
	generate_random_mod_p(prfKey, KEY_SIZE, &blockNum, sizeof(uint8_t), prime, blockRand);
	//ocall_printf(prfKey, KEY_SIZE, 1);
	BN_bn2bin(blockRand, randbuf);
	//ocall_printf(randbuf, PRIME_LENGTH / 8, 1);
	BN_mod_add(sigma, sum, blockRand, prime, ctx);

	BN_free(blockRand);
	BN_free(result);
	BN_free(sum);

	return;
}

// TODO: Check that this works

int audit_block_group(int fileNum, int numBlocks, int *blockNums, BIGNUM **sigmas, Tag *tag, uint8_t *data) {
    if (fileNum < 0 || numBlocks <= 0 || !blockNums || !sigmas || !tag || !data) {
        return -1; // Invalid input
    }

    //ocall_printf("in audit_block_group", 21, 0);

    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *bn_prime = BN_bin2bn(files[fileNum].prime, PRIME_LENGTH / 8, NULL);
    BIGNUM *sigma = BN_new(), *sigma2 = BN_new(), *sum1 = BN_new(), *sum2 = BN_new();
    if (!ctx || !bn_prime || !sigma || !sigma2 || !sum1 || !sum2) {
        BN_free(bn_prime);
        BN_CTX_free(ctx);
        BN_free(sigma);
        BN_free(sigma2);
        BN_free(sum1);
        BN_free(sum2);
        return -1; // Memory allocation failure
    }

    BIGNUM **coefficients = (BIGNUM **)malloc(numBlocks * sizeof(BIGNUM *));
    if (!coefficients) {
        goto cleanup;
    }
	
	BIGNUM *tempProduct = BN_new();
	BN_zero(tempProduct);
    for (int i = 0; i < numBlocks; i++) {
        coefficients[i] = BN_new();
        if (!coefficients[i] || !sigmas[i]) {
            goto cleanup;
        }
        BN_rand_range(coefficients[i], bn_prime);
        BN_mod_mul(tempProduct, sigmas[i], coefficients[i], bn_prime, ctx);
        BN_mod_add(sigma, sigma, tempProduct, bn_prime, ctx);
		BN_zero(tempProduct);
    }

    for (int i = 0; i < numBlocks; i++) {
        BIGNUM *product2 = BN_new();
        BIGNUM *blockRand = BN_new();
        if (!product2 || !blockRand) {
            goto cleanup; 
        }

        BN_zero(product2);
        BN_zero(blockRand);
		uint8_t randbuf[PRIME_LENGTH / 8];

		uint8_t blockNum = blockNums[i * 2];
		//ocall_printf(&blockNum,1,1);
        generate_random_mod_p(tag->prfKey, KEY_SIZE, &blockNum, sizeof(uint8_t), bn_prime, blockRand);
		//ocall_printf(tag->prfKey, KEY_SIZE, 1);

		BN_bn2bin(blockRand, randbuf);
		//ocall_printf(randbuf, PRIME_LENGTH / 8, 1);
        BN_mod_mul(product2, blockRand, coefficients[i], bn_prime, ctx);
        BN_mod_add(sum1, sum1, product2, bn_prime, ctx);

        BN_free(product2);
        BN_free(blockRand);
    }

    for (int j = 0; j < numBlocks; j++) {
        BIGNUM *sum = BN_new();
        BIGNUM *product3 = BN_new();
        if (!sum || !product3) {
            goto cleanup; 
        }

        BN_zero(sum);

        for (int i = 0; i < SEGMENT_PER_BLOCK; i++) {


			BIGNUM *alpha = BN_new();
            BIGNUM *product4 = BN_new();
            BIGNUM *bsegData = BN_new();
            if (!product4 || !bsegData || !alpha) {
                goto cleanup; 
            }

            BN_zero(product4);
            BN_zero(bsegData);
       		BN_zero(alpha);
      		BN_bin2bn(tag->alpha[i], PRIME_LENGTH / 8, alpha);


            BN_bin2bn(data + (j * BLOCK_SIZE) + (i * SEGMENT_SIZE), SEGMENT_SIZE, bsegData);
			BN_mod(bsegData, bsegData, bn_prime, ctx);
            BN_mod_mul(product4, bsegData, alpha, bn_prime, ctx);
            BN_mod_add(sum, sum, product4, bn_prime, ctx);

            BN_free(product4);
            BN_free(bsegData);
			BN_free(alpha);
        }

        BN_mod_mul(product3, sum, coefficients[j], bn_prime, ctx);
        BN_mod_add(sum2, sum2, product3, bn_prime, ctx);

        BN_free(sum);
        BN_free(product3);
    }

    BN_mod_add(sigma2, sum1, sum2, bn_prime, ctx);

    uint8_t sigs[PRIME_LENGTH / 8];
    BN_bn2bin(sigma, sigs);
    ocall_printf("SIGMA (1 and 2): ", 18, 0);
    ocall_printf(sigs, PRIME_LENGTH / 8, 1);
    BN_bn2bin(sigma2, sigs);
    ocall_printf(sigs, PRIME_LENGTH / 8, 1);

    int result = BN_cmp(sigma, sigma2);

cleanup:
    if (coefficients) {
        for (int i = 0; i < numBlocks; i++) {
            BN_free(coefficients[i]);
        }
        free(coefficients);
    }
    BN_free(bn_prime);
    BN_CTX_free(ctx);
    BN_free(sigma);
    BN_free(sigma2);
    BN_free(sum1);
    BN_free(sum2);

    return result;
}

void code_data(int *symbolData, int blocksInGroup, int type)
{
	int groupByteSize = blocksInGroup * BLOCK_SIZE;

	int symSize = 16; // Up to 2^symSize symbols allowed per group.
						// symSize should be a power of 2 in all cases.
	int gfpoly = 0x1100B;
	int fcr = 5;
	int prim = 1; 
	int nroots = (groupByteSize / 2) * ((double) ((double) NUM_TOTAL_SYMBOLS / NUM_ORIGINAL_SYMBOLS) - 1);
	
	int bytesPerSymbol = symSize / 8;
	int symbolsPerSegment = SEGMENT_SIZE / bytesPerSymbol;
	int numDataSymbols = groupByteSize / bytesPerSymbol;
	int totalSymbols = numDataSymbols + nroots;
	int numParityBlocks = ceil( (double) (nroots * bytesPerSymbol) / BLOCK_SIZE); // TODO: * bytesPerSymbols??

	ocall_printint(&blocksInGroup);
	ocall_printint(&groupByteSize);
	ocall_printint(&bytesPerSymbol);
	ocall_printint(&numDataSymbols);
	ocall_printint(&nroots);
	ocall_printint(&numParityBlocks);

	void *rs = init_rs_int(symSize, gfpoly, fcr, prim, nroots, pow(2, symSize) - (totalSymbols + 1));

	if(type == 0) {
		encode_rs_int(rs, symbolData, symbolData + numDataSymbols);
	}
	else if(type == 1) {

		decode_rs_int(rs, symbolData, NULL, 0);
	}
	else {

		// Handle error
	}
	free_rs_int(rs);
}

/*
 * Generate parity. Called by ecall_file_init to generate the parity data after sending the file with tags to storage device.
 *
 *
 *
 */

void ecall_generate_file_parity(int fileNum) 
{

    // generating parity data, encrypting it and sending it to FTL.


    // Generate groups array.
    int numBlocks = files[fileNum].numBlocks;
    int numPages = numBlocks * PAGE_PER_BLOCK;
	int numGroups = files[fileNum].numGroups;
    int numBits = (int)ceil(log2(numPages));

	ocall_init_parity(numBits); /* 
							     * This Does two things:
							     * It initiates the parity mode in the FTL,
							     * and tells it how many bits are being used in the permutation. 
							     */

    uint64_t **groups = get_groups(files[fileNum].sortKey, numBlocks, numGroups);

    int blockNum = 0;
    int pageNum = 0;
    int permutedPageNum = 0;
    int segNum = 0;
    int maxBlocksPerGroup = ceil(numBlocks / numGroups);
    int blocksInGroup = 0;

	uint8_t segData[SEGMENT_SIZE];
    uint8_t groupData[maxBlocksPerGroup * SEGMENT_PER_BLOCK * SEGMENT_SIZE];

	int startPage = 0; // TODO: This should start at start of parity for file in FTL. This can be calculated based on defined values and data in files struct.
    for (int group = 0; group < numGroups; group++) {

		/* 
     	 * porSK.sortKey is the PRP key to get the group. Need different keys for each file??
		 */

		// Generate shared key used when generating file parity, for permutation and encryption.
    	uint8_t keyNonce[KEY_SIZE];
    	uint8_t sharedKey[KEY_SIZE] = {0};

		sgx_read_rand(keyNonce, KEY_SIZE);

		//ocall_printf("Key Nonce:", 12, 0);
		//ocall_printf(keyNonce, KEY_SIZE, 1);

    	ocall_send_nonce(keyNonce);

    	size_t len = KEY_SIZE;
    	hmac_sha1(dh_sharedKey, ECC_PUB_KEY_SIZE, keyNonce, KEY_SIZE, sharedKey, &len);


        blocksInGroup = 0;

        // Initialize groupData to zeros
        for (int segment = 0; segment < maxBlocksPerGroup * SEGMENT_PER_BLOCK; segment++) {
            memset(groupData + (segment * SEGMENT_SIZE), 0, SEGMENT_SIZE); 
        }

        for (int groupBlock = 0; groupBlock < maxBlocksPerGroup; groupBlock++) { 
            blockNum = groups[group][groupBlock];
			// JD_TEST
			//ocall_printf("block number:", 14,0);
            //ocall_printf((uint8_t *)&blockNum, sizeof(uint8_t), 2);
			// END JD_TEST
            if (groups[group][groupBlock] == -1) { // This group is not full (it has less than maxBlocksPerGroup blocks). 
                continue;
            }
            blocksInGroup++;

            for (int blockPage = 0; blockPage < PAGE_PER_BLOCK; blockPage++) {
                pageNum = (blockNum * PAGE_PER_BLOCK) + blockPage;

                permutedPageNum = feistel_network_prp(sharedKey, pageNum, numBits);
				// JD_TEST
				//ocall_printf("page number:", 13,0);
				//ocall_printf((uint8_t *) &pageNum, sizeof(uint8_t), 2);
				//ocall_printf("permuted page number:", 22, 0);
                //ocall_printf((uint8_t *) &permutedPageNum, sizeof(uint8_t), 2);
				// END JD_TEST


                for (int pageSeg = 0; pageSeg < SEGMENT_PER_BLOCK / PAGE_PER_BLOCK; pageSeg++) {
                    segNum = (permutedPageNum * SEGMENT_PER_PAGE) + pageSeg;
                    ocall_get_segment(files[fileNum].fileName, segNum, segData, 0);
					//JD_TEST
					//ocall_printf("--------------------------------------------\n\n\n", 50, 0);
					//ocall_printf("(permuted) segment number:", 27,0);
					//ocall_printf((uint8_t *) &segNum, sizeof(uint8_t), 2);

					//END JD_TEST

                    DecryptData((uint32_t *)sharedKey, segData, SEGMENT_SIZE); 					


					// TODO: Perform an integrity check on the *BLOCKS* as they are received. 
					// This will be challenging, still have to hide location of tags, etc. 
					// This functionality needs to be extracted out of existing code.
					// Maybe there is somefunctionality I can extract from here: get a block and audit it's integrity.

                    // Copy segData into groupData
					int blockOffset = groupBlock * SEGMENT_PER_BLOCK * SEGMENT_SIZE;
					int pageOffset = blockPage * (SEGMENT_PER_BLOCK / PAGE_PER_BLOCK) * SEGMENT_SIZE;
					int segOffset = pageSeg * SEGMENT_SIZE;
                    memcpy(groupData + blockOffset + pageOffset + segOffset, segData, SEGMENT_SIZE);
                }
            }
        }

        // groupData now has group data.

		// Audit group data
		
		// Get sigmas and file tag.
		const int totalSegments = (files[fileNum].numBlocks * SEGMENT_PER_BLOCK);
	    int sigPerSeg = floor((double)SEGMENT_SIZE / ((double)PRIME_LENGTH / 8));
	    int tagSegNum = totalSegments + ceil((double)files[fileNum].numBlocks /(double) sigPerSeg);
		int tagPageNum = floor(tagSegNum / SEGMENT_PER_PAGE);
		// Permute tagPageNum
		permutedPageNum = feistel_network_prp(sharedKey, tagPageNum, numBits);
		tagSegNum = (permutedPageNum * SEGMENT_PER_PAGE) + (tagSegNum % tagPageNum); // note, the tag is after the file, 
																					// so numBits may be wrong

		ocall_get_segment(files[fileNum].fileName, tagSegNum, segData, 0);

			// JD_TEST
		//ocall_printf("Have group data. Audit now.", 28, 0);
		//ocall_printf("Tag page number:", 17, 0);
		//ocall_printf((uint8_t *) &tagPageNum, sizeof(uint8_t), 2);
		//ocall_printf("permuted tag page number:", 26,0);
		//ocall_printf((uint8_t *) &permutedPageNum, sizeof(uint8_t), 2);
		// END JD_TEST

	// JD_TEST 
		//ocall_printf("encrypted tag segment data:", 28, 0);
		//ocall_printf(segData, SEGMENT_SIZE, 1);
		// END JD_TEST

		DecryptData((uint32_t *)sharedKey, segData, SEGMENT_SIZE); 
		// JD_TEST
		//ocall_printf("decrypted tag segment data:", 28, 0);
		//ocall_printf(segData, SEGMENT_SIZE, 1);
		// END JD_TEST



		// Note, I will know that tag and sigmas come from FTL, as they are fully encrypted.
		Tag *tag = (Tag *)malloc(sizeof(Tag));
	    memcpy(tag, segData, sizeof(Tag));
	    decrypt_tag(tag, porSK);

		// Get sigmas
		BIGNUM *sigmas[blocksInGroup];


		for(int i = 0; i < blocksInGroup; i++) {
 		   sigmas[i] = BN_new();
		    BN_zero(sigmas[i]);

		    int startSeg = totalSegments;
		    int sigSegNum = floor(groups[group][i] / sigPerSeg) + startSeg;
		    int sigPageNum = floor(sigSegNum / SEGMENT_PER_PAGE);

		    // Permute sigPageNum
		    permutedPageNum = feistel_network_prp(sharedKey, sigPageNum, numBits);
		    int permutedSigSegNum = (permutedPageNum * SEGMENT_PER_PAGE) + (sigSegNum % SEGMENT_PER_PAGE);



		    uint8_t sigData[SEGMENT_SIZE];
		    ocall_get_segment(files[fileNum].fileName, permutedSigSegNum, sigData, 0);


		    DecryptData((uint32_t *)sharedKey, sigData, SEGMENT_SIZE);
		    int segIndex = groups[group][i] % sigPerSeg;
		    BN_bin2bn(sigData + (segIndex * (PRIME_LENGTH / 8)), PRIME_LENGTH / 8, sigmas[i]);
		}

		// TODO: a lot of repeated code between audit_file and here. This is the same between audit_block_group, and audit_file.
		// Much of this can be refactored to work really well.

		if (audit_block_group(fileNum, blocksInGroup, groups[group], sigmas, tag, groupData) != 0) {
		    ocall_printf("AUDIT FAILED!!", 15, 0);
		} else {
		    ocall_printf("AUDIT SUCCESS!", 15, 0);
		}


		// Setup RS parameters
        int groupByteSize = blocksInGroup * BLOCK_SIZE;

        int symSize = 16; // Up to 2^symSize symbols allowed per group.
						  // symSize should be a power of 2 in all cases.
        int gfpoly = 0x1100B;
		int fcr = 5;
		int prim = 1; 
		int nroots = (groupByteSize / 2) * ((double) ((double) NUM_TOTAL_SYMBOLS / NUM_ORIGINAL_SYMBOLS) - 1);
		
		int bytesPerSymbol = symSize / 8;
		int symbolsPerSegment = SEGMENT_SIZE / bytesPerSymbol;
        int numDataSymbols = groupByteSize / bytesPerSymbol;
        int totalSymbols = numDataSymbols + nroots;
		int numParityBlocks = ceil( (double) (nroots * bytesPerSymbol) / BLOCK_SIZE); // TODO: * bytesPerSymbols??


		int* symbolData = (int*)malloc(totalSymbols * sizeof(int));
		// Copy the data from groupData to symbolData
		for (int currentSeg = 0; currentSeg < blocksInGroup * SEGMENT_PER_BLOCK; currentSeg++) {
    		for (int currentSymbol = currentSeg * symbolsPerSegment; currentSymbol < (symbolsPerSegment * (currentSeg + 1)); currentSymbol++) {
				int symbolStartAddr = currentSymbol * bytesPerSymbol;
        		symbolData[currentSymbol] = (int)(groupData[symbolStartAddr] | (groupData[symbolStartAddr + 1] << 8));
    		}
		}

		code_data(symbolData, blocksInGroup, 0);


		//ocall_printf("parity just after encode:", 26, 0);

		ocall_printf(symbolData, totalSymbols * sizeof(int), 1);
		

		//ocall_printf("decode?", 8, 0);
		//ocall_printf("encode good", 12,0);
		// TODO: just test that all the right data are in the right places in the end
		// TODO: verify this works, add authentication, and refine the locations on this!

		// Place all parity data in tempParityData.
		uint8_t* tempParityData = (uint8_t*)malloc(numParityBlocks * BLOCK_SIZE);
		for(int i = 0; i < numParityBlocks * BLOCK_SIZE; i++) {

			tempParityData[i] = 0;
		}
		for (int currentSymbol = numDataSymbols; currentSymbol < totalSymbols; currentSymbol++) {
			for(int i = 0; i < bytesPerSymbol; i++) {
    			tempParityData[((currentSymbol * bytesPerSymbol) - (numDataSymbols * bytesPerSymbol)) + i] = (symbolData[currentSymbol] >> ((bytesPerSymbol - (i + 1)) * 8)) & 0xFF;
			}
		}

		uint8_t parityData[numParityBlocks + 1][BLOCK_SIZE]; /* The 0th segment of the 0th block contains the following:
															  * Replay resistant signed magic number (To let FTL know what to do)
															  * Number of pages of parity data, 
															  * Nonce for PRF input.
															  * Proof of data source (extracted secret message).
															  */

		// Encrypt parity data and place it in parityData array.
		//ocall_printf("here6", 6,0);

		//ocall_printf("Parity data before encryption:", 31, 0);
		//for(int l = 0; l < numParityBlocks; l++) {

		//	ocall_printf(tempParityData + (l * BLOCK_SIZE), BLOCK_SIZE, 1);
		//}

		EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
		if (!ctx) {
		    // Handle error: Failed to allocate EVP_CIPHER_CTX
		    return;
		}
		const unsigned char iv[] = "0123456789abcdef";
		if (!EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, files[fileNum].sortKey, iv)) {
		    // Handle error: Encryption Initialization failed
		    EVP_CIPHER_CTX_free(ctx);
		    return;
		}
		
		for (int i = 0; i < numParityBlocks; i++) {
		    int out_len;

				//ocall_printf("here5", 6,0);

		    if (!EVP_EncryptUpdate(ctx, parityData[i + 1], &out_len, tempParityData + (i * BLOCK_SIZE), BLOCK_SIZE)) {
		        // Handle error: Encryption Update failed


		        EVP_CIPHER_CTX_free(ctx);
		        return;
		    }
		}

		//ocall_printf("encrypted parity data:", 23, 0);
		//for(int l = 0; l < numParityBlocks; l++) {

		//	ocall_printf(parityData[l + 1], BLOCK_SIZE, 1);
		//}

		EVP_CIPHER_CTX_free(ctx);
		//ocall_printf("here4", 6,0);


		// Prepare parityData[0][0:SEGMENT_SIZE]
		int loc = 0;
		// Magic Number || Nonce || numPages || Proof length || Proof || Signature
		

		// Magic Number
		char *parityIndicator = PARITY_INDICATOR;
		memcpy(parityData[0],parityIndicator, 6);
		loc += 6; // +1 for the null character.

		// Nonce
		uint8_t nonce[KEY_SIZE];
		if(sgx_read_rand(nonce, KEY_SIZE) != SGX_SUCCESS) {
			// Handle Error
		}
		memcpy(parityData[0] + loc, nonce, KEY_SIZE);
		loc += KEY_SIZE;


		// Generate groupKey
		uint8_t groupKey[KEY_SIZE];

		//size_t len = KEY_SIZE;
		hmac_sha1(dh_sharedKey, KEY_SIZE, nonce, KEY_SIZE, groupKey, &len);
		//ocall_printf("here3", 6,0);
		// Number of pages
		int numPages = numParityBlocks * PAGE_PER_BLOCK;
		memcpy(parityData[0] + loc, (uint8_t *) &numPages,sizeof(int));
		loc += sizeof(int);
		// Proof length
		int proofLength = (SECRET_LENGTH / 8) * numPages;
		memcpy(parityData[0] + loc, (uint8_t *) &proofLength, sizeof(int));
		loc += sizeof(int);
		//ocall_printf("proof Length", 13, 0);
		//ocall_printf((int *) &proofLength, sizeof(int), 2);
		//ocall_printf("secret length", 14, 0);
		int secretLength = SECRET_LENGTH;
		//ocall_printf((int *) &secretLength, sizeof(int), 2); 

		// Proof
		// Generate l * log(PAGE_SIZE/l) bit random number for each page, using groupKey.
		uint8_t secretMessage[(SECRET_LENGTH / 8) * numPages];

		for(int i = 0; i < (SECRET_LENGTH / 8) * numPages; i++) {
			secretMessage[i] = 0;
		}
		
		prng_init((uint32_t) groupKey[0]);

		for(int i = 0; i < numPages; i++) {
			int randLen = SECRET_LENGTH * log2((PAGE_SIZE * 8) / SECRET_LENGTH);
			uint8_t pageRands[SECRET_LENGTH];

			int blockNumber = 1 + (int) floor((double) i / PAGE_PER_BLOCK);
			int page_in_block = i % PAGE_PER_BLOCK;

			int current = 0;
			for(int j = 0; j < SECRET_LENGTH; j++) {
				pageRands[j] = (uint8_t) prng_next();
				//ocall_printf(pageRands + j, sizeof(uint8_t), 2);

				int pageIndex = (current + (int) floor(pageRands[j] / 8));
        		int bitIndex = pageRands[j] % 8;
				// add the (current + pageRands[j])th bit in current page to secret_Message, from parityData.
				int messageBit = (i * SECRET_LENGTH) + j;
				int messageByte = (int) floor(messageBit / 8);
				int messageBitIndex = messageBit % 8;


				//ocall_printf("parityD:", 9, 0);
				//ocall_printf(parityData[blockNumber] + (pageIndex + (page_in_block * PAGE_SIZE)), 1, 2);

				secretMessage[messageByte] |= (((parityData[blockNumber][pageIndex + (page_in_block * PAGE_SIZE)] >> (bitIndex)) & 1) << messageBitIndex);

				

				current += 2048 / SECRET_LENGTH;
			}
		}
		//ocall_printf("proof:", 7,0);

		//ocall_printf(secretMessage,  (SECRET_LENGTH / 8) * numPages, 1);

		memcpy(parityData[0] + loc, secretMessage, (SECRET_LENGTH / 8) * numPages);
		loc += (SECRET_LENGTH / 8) * numPages;

		// Signature
		uint8_t signature[KEY_SIZE];
		//ocall_printf("group key", 10, 0);
		//ocall_printf(groupKey, KEY_SIZE, 1);
		hmac_sha1(groupKey, KEY_SIZE, parityData[0], loc, signature, &len);
		memcpy(parityData[0] + loc, signature, KEY_SIZE);
		loc += KEY_SIZE;



		// Now, simply write parityData to FTL. NOTE: no special OCALL required... note, we ARE doing this on a group by group basis.
		// There is also a lot of room for refactorization in this code
		//ocall_printf("here1",6,0);
		uint8_t goodParData[(numParityBlocks + 1) * BLOCK_SIZE];
		for(int i = 0; i < numParityBlocks + 1; i++) {
			memcpy(goodParData + (i * BLOCK_SIZE), parityData[i], BLOCK_SIZE);
		}
		ocall_send_parity(PARITY_START + startPage, goodParData, (numParityBlocks + 1) * BLOCK_SIZE);
		//ocall_printf("Here", 5, 0);

		startPage += numParityBlocks * PAGE_PER_BLOCK;

		if(group == 0){
		//free_rs_int(rs);
    	free(symbolData);
		}
		
		//ocall_printf("block group done", 17,0);

		// read from page 1000 and verify proof verification || signature (it uses groupKey).
		//int verificationPage = feistel_network_prp(sharedKey, 1000, log2(1000));
		//int verificationSegment = verificationPage * SEGMENT_PER_PAGE;
		//ocall_printf("get seg", 8, 0);

		//ocall_get_segment(files[fileNum].fileName, verificationSegment, segData);
		// verification is uint8_t * (KEY_SIZE + 1)
		//uint8_t result[KEY_SIZE + 1] = {0};
		//hmac_sha1(groupKey, KEY_SIZE, result, sizeof(int), result + 1, &len);
		//result[0] = segData[0];
		//hmac_sha1(groupKey, KEY_SIZE, result, sizeof(uint8_t), result + 1, &len); //(NOTE: this line should be used, once FTL is recompiled)

		//if(memcmp(result + 1, segData + 1, KEY_SIZE) != 0) {
		//	ocall_printf("Signature verification failed", 30, 0);
		//}
		//else {
		//	ocall_printf("passed", 7, 0);
		//}
		//ocall_printf(result, KEY_SIZE + 1, 1);
		//ocall_printf(segData, sizeof(uint8_t), 2);
		//ocall_printf(segData + 1, KEY_SIZE, 1);


    }
	ocall_printf("Parity Done", 12, 0);
	
	ocall_init_parity(numBits);
	//ocall_end_genPar();
	return;
}


void ecall_decode_partition(const char *fileName, int blockNum)
{

	int fileNum;
	for(fileNum = 0; fileNum < MAX_FILES; fileNum++) {
		if(strcmp(fileName, files[fileNum].fileName) == 0) {
			break;
		}
	}

	// Get group number
	    int numBlocks = files[fileNum].numBlocks;
    int numPages = numBlocks * PAGE_PER_BLOCK;
	int numGroups = files[fileNum].numGroups;
    int numBits = (int)ceil(log2(numPages));

	ocall_init_parity(numBits); /* 
							     * This Does two things:
							     * It initiates the parity mode in the FTL,
							     * and tells it how many bits are being used in the permutation. 
							     */

    uint64_t **groups = get_groups(files[fileNum].sortKey, numBlocks, numGroups);

    int currBlockNum = 0;
    int pageNum = 0;
    int permutedPageNum = 0;
    int segNum = 0;
    int maxBlocksPerGroup = ceil(numBlocks / numGroups);
    int blocksInGroup = 0;

	int groupNum;
	for(int i = 0; i < numGroups; i++) {
        for(int j = 0; j < maxBlocksPerGroup; j++) {
            if(groups[i][j] == blockNum) {
                groupNum = i; // Returns the group number if the block number is found
            }
        }
    }

	uint8_t segData[SEGMENT_SIZE];
    uint8_t groupData[maxBlocksPerGroup * SEGMENT_PER_BLOCK * SEGMENT_SIZE];

	int startPage = 0; // TODO: This should start at start of parity for file in FTL. This can be calculated based on defined values and data in files struct.

	/* 
	* porSK.sortKey is the PRP key to get the group. Need different keys for each file??
	*/

	// Generate shared key used when generating file parity, for permutation and encryption.
	uint8_t keyNonce[KEY_SIZE];
	uint8_t sharedKey[KEY_SIZE] = {0};

	sgx_read_rand(keyNonce, KEY_SIZE);

	//ocall_printf("Key Nonce:", 12, 0);
	//ocall_printf(keyNonce, KEY_SIZE, 1);

	ocall_send_nonce(keyNonce);

	size_t len = KEY_SIZE;
	hmac_sha1(dh_sharedKey, ECC_PUB_KEY_SIZE, keyNonce, KEY_SIZE, sharedKey, &len);


	blocksInGroup = 0;

	// Initialize groupData to zeros
	for (int segment = 0; segment < maxBlocksPerGroup * SEGMENT_PER_BLOCK; segment++) {
		memset(groupData + (segment * SEGMENT_SIZE), 0, SEGMENT_SIZE); 
	}


	for (int groupBlock = 0; groupBlock < maxBlocksPerGroup; groupBlock++) { 
		currBlockNum = groups[groupNum][groupBlock];
		// JD_TEST
		//ocall_printf("block number:", 14,0);
		//ocall_printf((uint8_t *)&blockNum, sizeof(uint8_t), 2);
		// END JD_TEST
		if (groups[groupNum][groupBlock] == -1) { // This group is not full (it has less than maxBlocksPerGroup blocks). 
			continue; // TODO: why continue here? shouldn't it break or somethn
		}
		blocksInGroup++;

		for (int blockPage = 0; blockPage < PAGE_PER_BLOCK; blockPage++) {
			pageNum = (currBlockNum * PAGE_PER_BLOCK) + blockPage;

			permutedPageNum = feistel_network_prp(sharedKey, pageNum, numBits);
			// JD_TEST
			//ocall_printf("page number:", 13,0);
			//ocall_printf((uint8_t *) &pageNum, sizeof(uint8_t), 2);
			//ocall_printf("permuted page number:", 22, 0);
			//ocall_printf((uint8_t *) &permutedPageNum, sizeof(uint8_t), 2);
			// END JD_TEST


			for (int pageSeg = 0; pageSeg < SEGMENT_PER_BLOCK / PAGE_PER_BLOCK; pageSeg++) {
				segNum = (permutedPageNum * SEGMENT_PER_PAGE) + pageSeg;
				ocall_get_segment(files[fileNum].fileName, segNum, segData, 0);
				//JD_TEST
				//ocall_printf("--------------------------------------------\n\n\n", 50, 0);
				//ocall_printf("(permuted) segment number:", 27,0);
				//ocall_printf((uint8_t *) &segNum, sizeof(uint8_t), 2);

				//END JD_TEST

				DecryptData((uint32_t *)sharedKey, segData, SEGMENT_SIZE); 					


				// TODO: Perform an integrity check on the *BLOCKS* as they are received. 
				// This will be challenging, still have to hide location of tags, etc. 
				// This functionality needs to be extracted out of existing code.
				// Maybe there is somefunctionality I can extract from here: get a block and audit it's integrity.

				// Copy segData into groupData
				int blockOffset = groupBlock * SEGMENT_PER_BLOCK * SEGMENT_SIZE;
				int pageOffset = blockPage * (SEGMENT_PER_BLOCK / PAGE_PER_BLOCK) * SEGMENT_SIZE;
				int segOffset = pageSeg * SEGMENT_SIZE;
				memcpy(groupData + blockOffset + pageOffset + segOffset, segData, SEGMENT_SIZE);
			}
		}
	}
	ocall_init_parity(numBits);
	// Group's data now in groupdata...
	// Get the parity and decode with proper parameters.

	// Setup RS parameters
        int groupByteSize = blocksInGroup * BLOCK_SIZE;

        int symSize = 16; // Up to 2^symSize symbols allowed per group.
						  // symSize should be a power of 2 in all cases.
        int gfpoly = 0x1100B;
		int fcr = 5;
		int prim = 1; 
		int nroots = (groupByteSize / 2) * ((double) ((double) NUM_TOTAL_SYMBOLS / NUM_ORIGINAL_SYMBOLS) - 1);
		
		int bytesPerSymbol = symSize / 8;
		int symbolsPerSegment = SEGMENT_SIZE / bytesPerSymbol;
        int numDataSymbols = groupByteSize / bytesPerSymbol;
        int totalSymbols = numDataSymbols + nroots;
		int numParityBlocks = ceil( (double) (nroots * bytesPerSymbol) / BLOCK_SIZE); // TODO: * bytesPerSymbols??

		ocall_printint(&blocksInGroup);
		ocall_printint(&groupByteSize);
		ocall_printint(&bytesPerSymbol);
		ocall_printint(&numDataSymbols);
		ocall_printint(&nroots);
		ocall_printint(&numParityBlocks);


	int* symbolData = (int*)malloc(totalSymbols * sizeof(int));

	// Copy the data from groupData to symbolData
	for (int currentSeg = 0; currentSeg < blocksInGroup * SEGMENT_PER_BLOCK; currentSeg++) {
		for (int currentSymbol = currentSeg * symbolsPerSegment; currentSymbol < (symbolsPerSegment * (currentSeg + 1)); currentSymbol++) {
			int symbolStartAddr = currentSymbol * bytesPerSymbol;
			symbolData[currentSymbol] = (int)(groupData[symbolStartAddr] | (groupData[symbolStartAddr + 1] << 8));
		}
	}

	uint8_t* parityData = (uint8_t*)malloc(numParityBlocks * BLOCK_SIZE);
	startPage += groupNum * numParityBlocks * PAGE_PER_BLOCK;
	for(int i = 0; i < numParityBlocks * SEGMENT_PER_BLOCK; i++) {
		for(int j = 0; j < SEGMENT_SIZE; j++) {

			parityData[i * SEGMENT_SIZE + j] = 0;
		}
		ocall_get_segment(fileName, (PARITY_START * SEGMENT_PER_PAGE) + (startPage * SEGMENT_PER_PAGE) + i, parityData + (i * SEGMENT_SIZE), 1);
	}

	//ocall_printf("PARITY DATA - encrypted", 24, 0);

	//ocall_printf(parityData, numParityBlocks * BLOCK_SIZE, 1);

	// Read and decrypt parity data.
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (!ctx) {
		// Handle error: Failed to allocate EVP_CIPHER_CTX
		return;
	}
	const unsigned char iv[] = "0123456789abcdef";
	if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, files[fileNum].sortKey, iv)) {
		// Handle error: Encryption Initialization failed
		EVP_CIPHER_CTX_free(ctx);
		return;
	}

// unsigned char buffer[BLOCK_SIZE];
// int final_out_len;

// for(int i = 0; i < numParityBlocks; i++) {
     int out_len;
    ocall_printf("Decrypt", 8, 0);
    if (!EVP_DecryptUpdate(ctx, parityData, &out_len, parityData, BLOCK_SIZE * numParityBlocks)) { // in place decryption
        // Handle error: Encryption Update failed
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
// 	final_out_len = out_len;

// 	memcpy(parityData + (i * BLOCK_SIZE), buffer, BLOCK_SIZE);
//     // Optionally copy the final block back to parityData if necessary
// }

		//ocall_printf("PARITY DATA - decrypted", 24, 0);

	//ocall_printf(parityData, nroots * bytesPerSymbol, 1);

	// We have parity data in parityData.
	// Now, we must add it to symbolData.

	// Copy the data from parityData to symbolData
	// Assuming numDataSymbols is the index where data symbols end in symbolData
int paritySymbolIndex = numDataSymbols; // Start appending after data symbols
for (int currentSymbol = 0; currentSymbol < nroots; currentSymbol++) {
    int symbolStartAddr = currentSymbol * bytesPerSymbol;

    symbolData[paritySymbolIndex] = 0;
    for (int byteIndex = 0; byteIndex < bytesPerSymbol; byteIndex++) {
        // Combining bytes back into a symbol
        symbolData[paritySymbolIndex] |= ((int) parityData[symbolStartAddr + byteIndex] << (8 * ((byteIndex + 1) % 2)));

    }
    paritySymbolIndex++;
}

//ocall_printf(groupData, groupByteSize, 1);

//ocall_printf(symbolData + numDataSymbols, nroots * sizeof(int), 1);

	ocall_printf(symbolData, totalSymbols * sizeof(int), 1);

	// all symbols now in symboldata. decode.

    ocall_printf("HERE0", 6, 0);

	code_data(symbolData, blocksInGroup, 1);

	ocall_printf("HERE1", 6, 0);

	//free_rs_int(rs);

	// Put DATA back in groupData
	for (int currentSymbol = 0; currentSymbol < numDataSymbols; currentSymbol++) {
    	int symbol = symbolData[currentSymbol];
    	int symbolStartAddr = currentSymbol * bytesPerSymbol;

    	// Extracting two bytes from each symbol (assuming 16-bit symbols)
    	groupData[symbolStartAddr] = (uint8_t)(symbol & 0xFF); // Lower 8 bits
    	if (bytesPerSymbol > 1) {
     	   groupData[symbolStartAddr + 1] = (uint8_t)((symbol >> 8) & 0xFF); // Upper 8 bits
    	}
	}

	// There is some attack here. However, the attacker would need a full additional copy of the file to perform this attack.
	// TODO: We need a special write mode here, where the WRITTEN data is encrypted and it's location is permuted.
	// TODO: write data to FTL. 

	//TODO: make magic number convention consistant with paper
	// TODO: lots of reused code in lots of places. refactor a bunch.
	// TODO: make procedures be pretty much same as in paper?
	// TODO: add this ecall to enclave.edl

	ocall_printf("HERE2", 6, 0);

	ocall_write_partition(numBits);

	ocall_printf("HERE3", 6, 0);

	for(int i = 0; i < maxBlocksPerGroup; i++) {

		if (groups[groupNum][i] == -1) { // This group is not full (it has less than maxBlocksPerGroup blocks). 
			continue; // TODO: why continue here? shouldn't it break or somethn
		}

		currBlockNum = groups[groupNum][i];

		for(int j = 0; j < PAGE_PER_BLOCK; j++) {
			int pageNum = (currBlockNum * PAGE_PER_BLOCK) + j;
			pageNum = feistel_network_prp(sharedKey, pageNum, numBits);
			for(int k = 0; k < SEGMENT_PER_PAGE; k++) {
				EncryptData((uint32_t *)sharedKey, groupData + ((i* BLOCK_SIZE) + (j * PAGE_SIZE) + (k * SEGMENT_SIZE)), SEGMENT_SIZE);
			}
			ocall_write_page(pageNum, groupData + (i * BLOCK_SIZE) + (j * PAGE_SIZE));
		}
	}
	ocall_write_partition(numBits);
	ocall_printf("HERE4", 6, 0);


}


/*
* Initialize the enclave.
* This function is called when the enclave is first created.
* It initializes the enclave's private key, public key to communicate with FTL, and exchange FTL public key.
* It also intitializes peers to peers public and private keys, and exchange their public keys.
* It also initializes the files[] array.
*/
void ecall_init() 
{


	// Diffie hellman key exchange with FTL
	uint8_t sgx_privKey[ECC_PRV_KEY_SIZE];
	uint8_t sgx_pubKey[ECC_PUB_KEY_SIZE] = {0};
	uint8_t ftl_pubKey[ECC_PUB_KEY_SIZE] = {0};

    //	ocall_ftl_init(sgx_pubKey, ftl_pubKey);
	// Generate random private key 
    prng_init((0xbad ^ 0xc0ffee ^ 42) | 0xcafebabe | 776);
	for(int i = 0; i < ECC_PRV_KEY_SIZE; ++i) {
		sgx_privKey[i] = prng_next();
	}

	// Generate ecc keypair
	ecdh_generate_keys(sgx_pubKey, sgx_privKey);

	// Print generated keys
	// ocall_printf("SGX Private key: ", 18, 0);
	// ocall_printf(sgx_privKey, ECC_PRV_KEY_SIZE, 1);

	// ocall_printf("SGX Public key: ", 17, 0);
	// ocall_printf(sgx_pubKey, ECC_PUB_KEY_SIZE, 1);
	// Send sgx_pubKey to FTL and get ftl_pubKey from FTL
	ocall_ftl_init(sgx_pubKey, ftl_pubKey);

	// ocall_printf("FTL Public key: ", 17, 0);
	// ocall_printf(ftl_pubKey, ECC_PUB_KEY_SIZE, 1);

	ecdh_shared_secret(sgx_privKey, ftl_pubKey, dh_sharedKey);

	// ocall_printf("DH Shared key: ", 16, 0);
	// ocall_printf(dh_sharedKey, ECC_PUB_KEY_SIZE, 1);

	// Generate keys for auditing and initialize files[]
	porSK = por_init();
	for(int i = 0; i < MAX_FILES; i++) {
		files[i].inUse = 0;
	}

	//ocall_printf("------------------------", 25, 0);



	return;
}
// Amir MM Farid
// void ecall_peer_init(NodeInfo *nodes, uint8_t is_parity_peer) {

	// int fileNum;
	// for(fileNum = 0; fileNum < MAX_FILES; fileNum++) {
	// 	if(strcmp(fileName, files[fileNum].fileName) == 0) {
	// 		break;
	// 	}
	// }
	// files[fileNum].is_parity_peer = is_parity_peer;
	// // 1. Add peers to peer list.
	// files[fileNum].nodes = nodes;

	// if (is_parity_peer) {
		
	// } else { // data peer
	// }
	// TODO:
	// 1. define a key storage for parity peers ( parity chunks get encrypted by the client and then sent to the parity peer )

	// TODO:
	// 2. generate a key pair for the local peer.
	// 3. exchange public keys with the local peer.
	// 4. update peers struct with local peer's public key.
	// 5. update dh_sharedKey with local peer's public key.
	// 6. add local peer to enclave_init.


// }
// end Amir MM Farid

// Initialize the file with PoR Tags and send them to FTL
int ecall_file_init(const char *fileName, Tag *tag, uint8_t *sigma, int numBlocks) 
{

	// Amir MM Farid
	// TODO:

	// 1. define two flow (1- parity chunks) (2- data chunks)
	
	// 2. data chunks flow:
	// 2.1. read data chunks from the file
	// 2.2. intinitlize files struct with data chunks
	// 2.3. generate tags for data chunks
	// 2.4. store the tags in enclave
	// 2.5. store the data chunk in the FTL
	// 2.6. store the tags at the end of the FTL

	// 3. parity chunks flow:
	// 3.1. read parity chunks from the file
	// 3.2. store the parity chunks key from the file
	// 3.3. generate tags for parity chunks and store them in enclave
	// 3.4. generate key for shuffling parity chunks and store the key in enclave
	// 3.5. divide parity chunks into blocks and shuffle them
	// 3.6. store the parity chunks in the FTL
	// 3.7. store the tags at the end of the FTL

	
	// end Amir MM Farid

    int i, j;
    uint8_t blockNum;
    BIGNUM *prime;

    uint8_t *data = (uint8_t *)malloc(BLOCK_SIZE * sizeof(uint8_t));


    for(i = 0; i < MAX_FILES; i++) { // TODO: This maybe should loop through MAX_FILES? it was FILE_NAME_LEN
        if(files[i].inUse == 0) {
            memcpy(files[i].fileName, fileName, strlen(fileName)); // TODO: change inUse to 1 here?? the line was not here.
			files[i].inUse = 1;
            break;
        }
    } // TODO: rename i to fileNum
	files[i].numBlocks = numBlocks;
	files[i].numGroups = 2; // TODO: Come up with some function to determine this value for a given file. For now, it is hardcoded.


	// Generate prime number and key asssotiated with the file
    prime = BN_new();
	BN_zero(prime);
    BN_generate_prime_ex(prime, PRIME_LENGTH, 0, NULL, NULL, NULL);
	sgx_read_rand(files[i].sortKey, KEY_SIZE);
	

	// JD test
	#ifdef TEST_MODE

	testPrime = BN_new();
	BN_zero(testPrime);
	BN_copy(testPrime, prime);
	//printBN(testPrime, PRIME_LENGTH / 8);

	#endif
	// end JD test

    uint8_t *prime_bytes = (uint8_t *) malloc(BN_num_bytes(prime));
    BN_bn2bin(prime, prime_bytes);

    for(j = 0; j < PRIME_LENGTH / 8; j++) {
        files[i].prime[j] = prime_bytes[j];
    }

	// Generate PDP alpha tags.
    gen_file_tag(prime, tag);

    blockNum = 0;


    // Allocate an array of BIGNUMs with the same length as alpha
    BIGNUM *alpha_bn[SEGMENT_PER_BLOCK];
	//ocall_printf("alphas:", 8,0);
    for (j = 0; j < SEGMENT_PER_BLOCK; j++) {
        alpha_bn[j] = BN_new();
		BN_zero(alpha_bn[j]);
        BN_bin2bn(tag->alpha[j], PRIME_LENGTH / 8, alpha_bn[j]);

		// JD_test
		//ocall_printf(tag->alpha[j], PRIME_LENGTH / 8, 1);
		#ifdef TEST_MODE
		
		testAlphas[j] = BN_new();
		BN_zero(testAlphas[j]);
		BN_copy(testAlphas[j], alpha_bn[j]);

		#endif
		// end JD test
    }


	// Read file data. 
    for (j = 0; j < numBlocks; j++) { // Each block

        ocall_get_block(data, SEGMENT_SIZE, SEGMENT_PER_BLOCK, blockNum, fileName);

        BIGNUM *data_bn[SEGMENT_PER_BLOCK];
        for(int k = 0; k < SEGMENT_PER_BLOCK; k++) { // Each Segment in block
            data_bn[k] = BN_new();
			BN_zero(data_bn[k]);
            BN_bin2bn(data + k * SEGMENT_SIZE, SEGMENT_SIZE, data_bn[k]);

			// JD test
			#ifdef TEST_MODE

			testFile[(SEGMENT_PER_BLOCK * j) + k] = BN_new();
			BN_zero(testFile[(SEGMENT_PER_BLOCK * j) + k]);
			BN_copy(testFile[(SEGMENT_PER_BLOCK * j) + k], data_bn[k]);

			#endif
			// end JD test

        }

		// Generate sigma tag for the block.
        BIGNUM *sigma_bn = BN_new();
		BN_zero(sigma_bn);
        // Call get_sigma with the updated argument
		//ocall_printf("rand:", 5,0);
        get_sigma(sigma_bn, data_bn, alpha_bn, blockNum, tag->prfKey, prime);

		// JD test
		#ifdef TEST_MODE

		testSigmas[j] = BN_new();
		BN_zero(testSigmas[j]);
		BN_copy(testSigmas[j], sigma_bn);

		#endif
		// end JD test

        BN_bn2binpad(sigma_bn, sigma + (blockNum * (PRIME_LENGTH/8)), ceil((double)PRIME_LENGTH/8));
		//ocall_printf(sigma + (blockNum * (PRIME_LENGTH/8)),PRIME_LENGTH/8, 1);
        BN_free(sigma_bn);
        for(int k = 0; k < SEGMENT_PER_BLOCK; k++) {
            BN_free(data_bn[k]);
        }
		ocall_printf("----------------------------------------", 42, 0);
		ocall_printf("Sigma for block:", 17, 0);
	// ocall_printint(blockNum);
	// ocall_printf("is", 3, 0);
		ocall_printf(sigma + (blockNum * (PRIME_LENGTH/8)), PRIME_LENGTH/8, 1);

        blockNum++;
    }

	

    // Free the allocated BIGNUMs
    for (j = 0; j < SEGMENT_PER_BLOCK; j++) {
        BN_free(alpha_bn[j]);
    }


    // Process tag (enc and MAC)
    tag->n = blockNum;
    // Encrypt alpha with encKey and perform MAC
	//ocall_printf("prep_tag",9,0);
    prepare_tag(tag, porSK);
	//ocall_printf("done",5,0);

    return i;
}


// Audit the file data integrity.
void ecall_audit_file(const char *fileName, int *ret) 
{
	// Amir MM Farid
	// TODO: (consier the different flows for data and parity chunks) parity chunks should be deshuffled first.
	
	// 1. get the tag segment number

	// end Amir MM Farid

	// Find file in files
	int i;
	for(i = 0; i < MAX_FILES; i++) {
		if(strcmp(fileName, files[i].fileName) == 0) {
			break;
		}
	}

	// First, calculate tag segment number
	const int totalSegments = (files[i].numBlocks * SEGMENT_PER_BLOCK);
	int sigPerSeg = floor((double)SEGMENT_SIZE / ((double)PRIME_LENGTH / 8));
	int tagSegNum = totalSegments + ceil((double)files[i].numBlocks /(double) sigPerSeg);

	// Generate public challenge number
	uint8_t challNum[KEY_SIZE];
	if(sgx_read_rand(challNum, KEY_SIZE) != SGX_SUCCESS) {
		// Handle Error
	}
	ocall_send_nonce(challNum);

	// Generate challenge key using Akagi201/hmac-sha1
	uint8_t challKey[KEY_SIZE] = {0};
	size_t len = KEY_SIZE;
	hmac_sha1(dh_sharedKey, ECC_PUB_KEY_SIZE, challNum, KEY_SIZE, challKey, &len);
										
	// Generate challenge key for tag segment and decrypt Tag
	uint8_t tempKey[KEY_SIZE];
	hmac_sha1(challKey, KEY_SIZE, (uint8_t *)&tagSegNum, sizeof(uint8_t), tempKey, &len);
	



	// Get tag from FTL (Note that tag is always  on final segment. This can be calculated easily)
	uint8_t segData[SEGMENT_SIZE];
	//ocall_printf("HERE??", 7, 0);
	ocall_get_segment(fileName, tagSegNum, segData, 0); // ocall get segment will write segNum to addr 951396 then simply read the segment. it should have first 16 bytes encrypted.

	DecryptData((uint32_t *)tempKey, segData, KEY_SIZE);

	// Call fix_tag(), which will check the MAC, and decrypt alphas and prfKey

	Tag *tag = (Tag *)malloc(sizeof(Tag));

	memcpy(tag, segData, sizeof(Tag));
	
	decrypt_tag(tag, porSK);

	// JD test alphas
	#ifdef TEST_MODE

	for(int j = 0; j < SEGMENT_PER_BLOCK; j++) {
		BIGNUM *alphaTest = BN_new();
		BN_zero(alphaTest);
		BN_bin2bn(tag->alpha[j], PRIME_LENGTH / 8, alphaTest);
		if(BN_cmp(testAlphas[j], alphaTest) != 0) {
			ocall_printf("fail alpha1", 12, 0);
		}
	}

	#endif
	// end JD test
	
	// Call gen_challenge to get {i, Vi}
	uint8_t indices[NUM_CHAL_BLOCKS];
	uint8_t *coefficients = malloc(sizeof(uint8_t) * ((PRIME_LENGTH / 8) * NUM_CHAL_BLOCKS));

	gen_challenge(files[i].numBlocks, indices, coefficients, files[i].prime); // MAYBE?? reduce coeff mod p

	// JD test 
	#ifdef TEST_MODE

	for(int j = 0; j < NUM_CHAL_BLOCKS; j++) {
		BIGNUM *temp = BN_new();
		BN_zero(temp);
		BN_bin2bn(coefficients + j * PRIME_LENGTH / 8, PRIME_LENGTH / 8, temp);
		testCoefficients[j] = BN_new();
		BN_zero(testCoefficients[j]);
		BN_copy(testCoefficients[j], temp);
	}

	#endif
	// end JD test


	//BIGNUM *products[NUM_CHAL_BLOCKS][SEGMENT_PER_BLOCK];
	BIGNUM *bprime = BN_new();
	BN_zero(bprime);
	BN_bin2bn(files[i].prime, PRIME_LENGTH / 8, bprime);

	// JD test prime
	#ifdef TEST_MODE

	if(BN_cmp(testPrime, bprime) != 0) {
		ocall_printf("fail prime1", 12, 0);
	}

	#endif
	// end JD test

	BN_CTX *ctx = BN_CTX_new();

	// Get sigma segments, parse for necessary sigmas and decrypt. calculate Vi * sigmai
	BIGNUM *sigma = BN_new();
	BN_zero(sigma);

	for (int j = 0; j < NUM_CHAL_BLOCKS; j++) {
		BN_CTX_start(ctx);
	    // Calculate the segment number containing the desired sigma
 	   int sigPerSeg = floor(SEGMENT_SIZE / (PRIME_LENGTH / 8));
	   int startSeg = totalSegments;
 	   int sigSeg = floor(indices[j] / sigPerSeg) + startSeg;
 	   int segIndex = indices[j] % sigPerSeg;

 	   hmac_sha1(challKey, KEY_SIZE, (uint8_t *)&sigSeg, sizeof(uint8_t), tempKey, &len);

 	   uint8_t sigData[SEGMENT_SIZE];
 	   ocall_get_segment(fileName, sigSeg, sigData, 0);

 	   DecryptData((uint32_t *)tempKey, sigData, KEY_SIZE);

    	BIGNUM *product1 = BN_CTX_get(ctx);
		BN_zero(product1);
 		BIGNUM *bsigma = BN_CTX_get(ctx);
		BN_zero(bsigma);
  	  	BIGNUM *ccoefficient = BN_CTX_get(ctx);
		BN_zero(ccoefficient);

	    if (!product1 || !bsigma || !ccoefficient) {
 	       // handle error
 	   }

 	   if (!BN_bin2bn(coefficients + (j * (PRIME_LENGTH / 8)), PRIME_LENGTH / 8, ccoefficient)) {
 	       // handle error
 	   }

		 if (!BN_bin2bn(sigData + (segIndex * (PRIME_LENGTH / 8)), PRIME_LENGTH / 8, bsigma)) {
  		      // handle error
   		 }

 	   // JD test sigma and coefficient
	   #ifdef TEST_MODE

    	if (BN_cmp(testSigmas[indices[j]], bsigma) != 0) {
    	    ocall_printf("fail sigma1", 12, 0);
    	}
    	if (BN_cmp(testCoefficients[j], ccoefficient) != 0) {
    	    ocall_printf("fail coefficient1", 18, 0);
    	}

		#endif
    	// JD end test

    	BN_mod_mul(product1, bsigma, ccoefficient, bprime, ctx);
    	BN_mod_add(sigma, sigma, product1, bprime, ctx);
		BN_CTX_end(ctx);
	}



	// BIGNUM sigma now contains master sigma!
	
	BIGNUM *sum1 = BN_new();
	BN_zero(sum1);
	BIGNUM *sum2 = BN_new();
	BN_zero(sum2);
	BIGNUM *sigma2 = BN_new();
	BN_zero(sigma2);

	for(int j = 0; j < NUM_CHAL_BLOCKS; j++) {
		BN_CTX_start(ctx);
		BIGNUM *product2 = BN_CTX_get(ctx);
		BN_zero(product2);
		BIGNUM *blockRand = BN_CTX_get(ctx);
		BN_zero(blockRand);
		BIGNUM *bcoefficient = BN_CTX_get(ctx);
		BN_zero(bcoefficient);

		generate_random_mod_p(tag->prfKey, KEY_SIZE, &indices[j], sizeof(uint8_t), bprime, blockRand);

		// JD test rand
		#ifdef TEST_MODE

		if(BN_cmp(blockRand, testRandoms[indices[j]]) != 0) {
			ocall_printf("fail rand", 11, 0);
		}

		#endif
		// end JD test

		BN_bin2bn(coefficients + (j * (PRIME_LENGTH / 8)), PRIME_LENGTH / 8, bcoefficient);

		// JD test sigma and coefficient
		#ifdef TEST_MODE

		if(BN_cmp(testCoefficients[j], bcoefficient) != 0) {
			ocall_printf("fail coefficient2", 18, 0);
		}

		#endif
		// JD end test

		BN_mod_mul(product2, blockRand, bcoefficient, bprime, ctx);
		BN_mod_add(sum1, sum1, product2, bprime, ctx);
		BN_CTX_end(ctx);
	}
	// We have sum1
	
	// Calculate sum2
	BN_CTX *ctx2 = BN_CTX_new();
	for(int j = 0; j < NUM_CHAL_BLOCKS; j++) {
		BN_CTX_start(ctx2);
		BIGNUM *sum = BN_CTX_get(ctx2);
		BIGNUM *product3 = BN_CTX_get(ctx2);
		BN_zero(product3);
		BIGNUM *bcoefficient1 = BN_CTX_get(ctx2);
		BN_zero(bcoefficient1);
		BN_zero(sum);

		BN_bin2bn(coefficients + (j * (PRIME_LENGTH / 8)), PRIME_LENGTH / 8, bcoefficient1);

		// JD test sigma and coefficient
		#ifdef TEST_MODE

		if(BN_cmp(testCoefficients[j], bcoefficient1) != 0) {
			ocall_printf("fail coefficient3", 18, 0);
		}

		#endif
		// JD end test

		for(int k = 0; k < SEGMENT_PER_BLOCK; k++) {
			BN_CTX_start(ctx);
			// Sum (a_k * m_jk)

			BIGNUM *product4 = BN_CTX_get(ctx);
			BN_zero(product4);
			BIGNUM *alpha = BN_CTX_get(ctx);
			BN_zero(alpha);
			BIGNUM *bsigData = BN_CTX_get(ctx);
			BN_zero(bsigData);
			BN_bin2bn(tag->alpha[k], PRIME_LENGTH / 8, alpha);

			// JD test alphas
			#ifdef TEST_MODE

			if(BN_cmp(alpha, testAlphas[k]) != 0) {
				ocall_printf("fail alpha2", 12, 0);
			}
			// printBN(testAlphas[k], PRIME_LENGTH / 8);
			// printBN(alpha, PRIME_LENGTH / 8);

			#endif
			// end JD test

			// Get segment data
			int segNum = (((uint8_t) indices[j] * SEGMENT_PER_BLOCK)) + k;

	 		hmac_sha1(challKey, KEY_SIZE, (uint8_t *)&segNum, sizeof(uint8_t), tempKey, &len);
	 		ocall_get_segment(fileName, segNum, segData, 0);
	 		DecryptData((uint32_t *)tempKey, segData, KEY_SIZE);
	 		BN_bin2bn(segData, SEGMENT_SIZE, bsigData);

			// JD test segment
			#ifdef TEST_MODE

			if(BN_cmp(bsegData, testFile[segNum]) != 0) {
				ocall_printf("fail data1", 11, 0);
			}

			#endif
			// end JD test
			BN_mod(bsigData, bsigData, bprime, ctx);
			BN_mod_mul(product4, bsigData, alpha, bprime, ctx);
			BN_mod_add(sum, sum, product4, bprime, ctx);
			BN_CTX_end(ctx);
		}
		// Sum v_j * (sum(a_k * m_jk))
		BN_mod_mul(product3, sum, bcoefficient1, bprime, ctx);
		BN_mod_add(sum2, sum2, product3, bprime, ctx);
		BN_CTX_end(ctx2);
	}

	// We have sum2
	BN_CTX_start(ctx);
	BN_mod_add(sigma2, sum1, sum2, bprime, ctx);
	BN_CTX_end(ctx);

	uint8_t sigs[PRIME_LENGTH / 8];
	BN_bn2bin(sigma, sigs);
	ocall_printf("SIGMA (1 and 2): ", 18, 0);
	ocall_printf(sigs, PRIME_LENGTH / 8, 1);
	BN_bn2bin(sigma2, sigs);
	ocall_printf(sigs, PRIME_LENGTH / 8, 1);

	// Compare the two calculations
	*ret = BN_cmp(sigma, sigma2);
}



