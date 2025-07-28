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
#include "gp.h"
/* 
 * TODO: maybe these should be actually installed as C libraries as libfec is.
 * I need to make a list of what exactly is also running in the FTL, So this can be done.
 */
#include "ecdh.h"
#include "cpor.h"
#include "hmac.h"
#include "aes.h"
#include "prp.h"
#include "rs.h"



#include <fec.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <math.h>

// TODO: How should these be stored?
// shared key with ftl
uint8_t dh_sharedKey[ECC_PUB_KEY_SIZE];

// current node chunk id
// if id > k, then it is a parity node
uint8_t current_id;

// porSK
PorSK porSK;
// files
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

// #define pstr(x) ocall_printf(x, sizeof(x), 0)
// #define pInt(&x) ocall_printint(&x)


void printEnclaveError(sgx_status_t ocall_ret){
	if (ocall_ret == SGX_SUCCESS) {
		ocall_printf("ocall_printf failed", 10, 0);
	}else if (ocall_ret == SGX_ERROR_INVALID_PARAMETER)
	{
		ocall_printf("invalid parameter", 10, 0);
	}else if (ocall_ret == SGX_ERROR_OUT_OF_MEMORY)
	{
		ocall_printf("out of memory", 10, 0);
	}else if (ocall_ret == SGX_ERROR_ENCLAVE_LOST)
	{
		ocall_printf("enclave lost", 10, 0);
	}else if (ocall_ret == SGX_ERROR_OUT_OF_EPC){
		ocall_printf("out of epc", 10, 0);
	}else if (ocall_ret == SGX_ERROR_ENCLAVE_CRASHED){
		ocall_printf("enclave crashed", 10, 0);
	}else if (ocall_ret == SGX_ERROR_INVALID_STATE){
		ocall_printf("invalid state", 10, 0);
	}else if (ocall_ret == SGX_ERROR_UNEXPECTED){
		ocall_printf("unexpected error", 10, 0);
	}
}



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

void ecall_generate_file_parity(int fileNum) {

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

		// ------------------------------------------------------------------------------------------------ IMP
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

	return;
}


/*
* Initialize the enclave.
* This function is called when the enclave is first created.
* It initializes the enclave's private key, public key to communicate with FTL, and exchange FTL public key.
* It also intitializes peers to peers public and private keys, and exchange their public keys.
* It also initializes the files[] array.
*/
void ecall_init(FileDataTransfer *fileDataTransfer, int size) 
{	
	double *time_start = malloc(sizeof(double));
	double *time_end = malloc(sizeof(double));


	// ================================ start time ================================
	ocall_test_time(time_start);

	// Diffie hellman key exchange with FTL
	uint8_t sgx_privKey[ECC_PRV_KEY_SIZE];
	uint8_t sgx_pubKey[ECC_PUB_KEY_SIZE] = {0};
	uint8_t ftl_pubKey[ECC_PUB_KEY_SIZE] = {0};

	// Generate random private key 
    prng_init((0xbad ^ 0xc0ffee ^ 42) | 0xcafebabe | 776);
	for(int i = 0; i < ECC_PRV_KEY_SIZE; ++i) {
		sgx_privKey[i] = prng_next();
	}

	// Generate ecc keypair
	ecdh_generate_keys(sgx_pubKey, sgx_privKey);

	// Print generated keys

	ocall_ftl_init(sgx_pubKey, ftl_pubKey);


	ecdh_shared_secret(sgx_privKey, ftl_pubKey, dh_sharedKey);

	// Amir MM Farid

	uint8_t currentPeerPubKey[ECC_PUB_KEY_SIZE];


	int fileNum = 0;
	files[fileNum].nodes = (NodeInfo *)malloc(NUM_NODES * sizeof(NodeInfo));
	for (int j = 0; j < NUM_NODES; j++) {

		memset(files[fileNum].nodes[j].ip, 0, 30);
		for (int k = 0; k < 16; k++) {
			// ocall_printf("Debug 0", 7, 0);

			files[fileNum].nodes[j].ip[k] = fileDataTransfer->nodes[j].ip[k];
		}
		// files[i].nodes[j].ip[15] = '\0';  // Ensure null-termination
		// ocall_printf("Debug 1", 7, 0);
		files[fileNum].nodes[j].port = fileDataTransfer->nodes[j].port;

		files[fileNum].nodes[j].is_parity_peer = fileDataTransfer->nodes[j].is_parity_peer;
		// ocall_printf("Debug 4", 7, 0);
		files[fileNum].nodes[j].socket_fd = fileDataTransfer->nodes[j].socket_fd;
	}

		// ocall_printf("---------------------------------------------------",51, 0);
		// ocall_printf("---------------------------------------------------",51, 0);
		// ocall_printf("---------------------------------------------------",51, 0);


	porSK = por_init();
	for(int i = 0; i < MAX_FILES; i++) {
		files[i].inUse = 0;
	}
	// end Amir MM Farid

	// ================================ end time ================================
	ocall_test_time(time_end);
	
	ocall_printf("==================================================", strlen("=================================================="), 0);
	double total_time = (*time_end - *time_start);
	
	ocall_printf("Total time for Init:", strlen("Total time for Init:"), 0);
	ocall_printdouble(&total_time);

	ocall_log_double("=", 0);
	ocall_log_double("Total time for Init: %f", total_time);
	ocall_log_double("=", 0);
	ocall_printf("==================================================", strlen("=================================================="), 0);
	free(time_start);
	free(time_end);
	return;
}

void ecall_get_currentID(int *chunk_id) {
	
	*chunk_id = files[0].current_chunk_id;
	return;
}

void ecall_set_currentID(int chunk_id) {
	files[0].current_chunk_id = chunk_id;
	return;
}

void ecall_test_encrypt(uint8_t *data, int chunk_size, int n, uint8_t *signatures, int n_signatures, uint8_t *sig_key, uint8_t *PC_KEY) {


	uint8_t *sigtemp = malloc(32);
	size_t len = 32;
	hmac_sha2(sig_key, 32, data, chunk_size, sigtemp, &len);

	uint8_t *data2 = malloc(chunk_size);
	memcpy(data2, data, chunk_size);
	DecryptData(PC_KEY, data2, chunk_size);



	ocall_printf("this is the data", strlen("this is the data"), 0);
	ocall_printf(data2, 40, 1);		
	
	ocall_printf("this is the encryption", strlen("this is the encryption"), 0);
	ocall_printf(data, 40, 1);

	ocall_printf("this is the sigtemp", strlen("this is the sigtemp"), 0);
	ocall_printf(sigtemp, 32, 1);

	free(sigtemp);
	free(data2);
	free(data);
	return;
}

// this function is called by the receiver-peer to initialize the connection with the sender-peer
void ecall_peer_init(uint8_t *current_pubKey, uint8_t *sender_pubKey, const char *ip, int sender_id) {

	double *time_start = malloc(sizeof(double));
	double *time_end = malloc(sizeof(double));

	// TODO: a golobal file ID should be defined for multi-file support
	// this should be send to the receiver-peer for multi-file support

	

	int fileNum = 0;
	ocall_printf("########################################################################################", 88, 0);
	ocall_printf("files[fileNum].current_chunk_id: ", 34, 0);
	ocall_printint(&files[fileNum].current_chunk_id);
	ocall_printf("IP: ", 4, 0);
	ocall_printf(ip,16,0);	
	ocall_printf("########################################################################################", 88, 0);

	uint8_t current_privKey[ECC_PRV_KEY_SIZE] = {0};
	for(int i = 0; i < ECC_PRV_KEY_SIZE; ++i) {
		current_privKey[i] = prng_next();
	}

	ecdh_generate_keys(current_pubKey, current_privKey);


	for(int i = 0; i < NUM_NODES; i++) {
		// if(strcmp(ip, files[fileNum].nodes[i].ip) == 0) {
		// 	ecdh_shared_secret(current_privKey, sender_pubKey, files[fileNum].nodes[i].dh_sharedKey_peer2peer);
		// 	files[fileNum].nodes[i].socket_fd = *socket_fd;
		// 	files[fileNum].nodes[i].chunk_id = current_id;
		// }

		int equal = 1;
		for (int j = 0; j < 16; j++) {
		    if (ip[j] != files[fileNum].nodes[i].ip[j]) {
		        equal = 0;
		        break;
		    }
		}
		if (equal) {
			// files[fileNum].nodes[i].dh_sharedKey_peer2peer = malloc(ECC_PUB_KEY_SIZE * sizeof(uint8_t));
		    ecdh_shared_secret(current_privKey, sender_pubKey, files[fileNum].nodes[i].dh_sharedKey_peer2peer);
			// files[fileNum].nodes[i].socket_fd = socket_fd;
			files[fileNum].nodes[i].chunk_id = sender_id;
		}
	}




	// Authentication
	// 	uint8_t keyNonce[KEY_SIZE];
	// uint8_t sharedKey[KEY_SIZE] = {0};

	// sgx_read_rand(keyNonce, KEY_SIZE);

	// hmac_sha1(dh_sharedKey, ECC_PUB_KEY_SIZE, keyNonce, KEY_SIZE, sharedKey, &KEY_SIZE);

	return;
}



// Initialize the file with PoR Tags and send them to FTL
int ecall_file_init(Tag *tag, uint8_t *sigma, FileDataTransfer *fileDataTransfer, int numBlocks, int size) 
{

	double *time_start = malloc(sizeof(double));
	double *time_end = malloc(sizeof(double));
	double *neg_start_time = malloc(sizeof(double));
	double *neg_end_time = malloc(sizeof(double));
	double *neg_start_time2 = malloc(sizeof(double));
	double *neg_end_time2 = malloc(sizeof(double));
	double total_neg_time = 0;
	double total_neg_time2 = 0;

	// ================================ start time ================================
	ocall_test_time(time_start);

    int i, j;
    uint8_t blockNum;
    BIGNUM *prime;

    uint8_t *data = (uint8_t *)malloc(BLOCK_SIZE * sizeof(uint8_t));


    for(i = 0; i < MAX_FILES; i++) { // TODO: This maybe should loop through MAX_FILES? it was FILE_NAME_LEN
        if(files[i].inUse == 0) {
            memcpy(files[i].fileName, fileDataTransfer->fileName, strlen(fileDataTransfer->fileName)); // TODO: change inUse to 1 here?? the line was not here.
			files[i].inUse = 1;
            break;
        }
    } // TODO: rename i to fileNum
	// files[i].numBlocks = fileDataTransfer->numBlocks;
	int fileNum = i;
	files[fileNum].numGroups = 2; // TODO: Come up with some function to determine this value for a given file. For now, it is hardcoded.

	// Amir MM Farid

	
	files[fileNum].current_chunk_id = fileDataTransfer->current_id;

	files[fileNum].n = fileDataTransfer->n;
	files[fileNum].k = fileDataTransfer->k;
	files[fileNum].current_chunk_id = fileDataTransfer->current_id;
	files[fileNum].is_parity_peer = (fileDataTransfer->current_id > files[fileNum].k)? 1 : 0;
	files[fileNum].numBlocks = fileDataTransfer->numBlocks;
	memcpy(files[fileNum].owner_ip, fileDataTransfer->owner_ip, 16);
	files[fileNum].owner_ip[15] = '\0';
	files[fileNum].owner_port = fileDataTransfer->owner_port;

	// // ================================ start negative time ================================
	// ocall_test_time(neg_start_time);

	// ocall_printf("==================Encalve file init info======================", 64, 0);
	// ocall_printf("the file num is ", 17, 0);
	// ocall_printint(&fileNum);
	// ocall_printf("the file name is ", 17, 0);
	// ocall_printf(files[fileNum].fileName, 30, 0);
	// ocall_printf("the num blocks is ", 17, 0);
	// ocall_printint(&files[fileNum].numBlocks);
	// ocall_printf("the n is ", 17, 0);
	// ocall_printint(&files[fileNum].n);
	// ocall_printf("the ip is ", 17, 0);
	// ocall_printf(files[fileNum].nodes[1].ip, 16, 0);
	// ocall_printf("the port is ", 17, 0);
	// ocall_printint(&files[fileNum].nodes[1].port);
	// ocall_printf("the owner ip is ", 17, 0);
	// ocall_printf(files[fileNum].owner_ip, 16, 0);
	// ocall_printf("the owner port is ", 17, 0);
	// ocall_printint(&files[fileNum].owner_port);
	
	// ocall_printf("========================================", 42, 0);

	// // ================================ end negative time ================================
	// ocall_test_time(neg_end_time);
	// total_neg_time += *neg_end_time - *neg_start_time;

// initialize the nodes keys for peer2peer communication
	for (j = 0; j < NUM_NODES; j++) {

		int is_empty = 1;
		for (int i = 0; i < 64; i++) {
    		if (files[fileNum].nodes[j].dh_sharedKey_peer2peer[i] != 0) {
    		    is_empty = 0;
    		    break;
    		}
		}

		ocall_printf("is_empty: ", 11, 0);
		ocall_printint(&is_empty);

		if (is_empty) {
			// allocate memory for the dh_sharedKey_peer2peer
			
			uint8_t *current_privKey = malloc(ECC_PRV_KEY_SIZE * sizeof(uint8_t));
			uint8_t *current_pubKey = malloc(ECC_PUB_KEY_SIZE * sizeof(uint8_t));
			memset(current_pubKey, 0, ECC_PUB_KEY_SIZE);
			uint8_t *peer_i_pubKey = malloc(ECC_PUB_KEY_SIZE * sizeof(uint8_t));
			memset(peer_i_pubKey, 0, ECC_PUB_KEY_SIZE);
			// generate random private key
			for(int k = 0; k < ECC_PRV_KEY_SIZE; ++k) {
				current_privKey[k] = prng_next();
			}
			ecdh_generate_keys(current_pubKey, current_privKey);
			int *peer_id = malloc(sizeof(int));
			// TODO: change the initilization ID for all nodes
			ocall_peer_init(current_pubKey, peer_i_pubKey, files[fileNum].nodes[j].ip, files[fileNum].nodes[j].port, files[fileNum].current_chunk_id, peer_id);
			files[fileNum].nodes[j].chunk_id = *peer_id;

			// // ================================ start negative time ================================
			// ocall_test_time(neg_start_time);

			// ocall_printf("++++++++++++++++++++++++++++++", 30, 0);
			// ocall_printf("files[fileNum].nodes[j].chunk_id: ", 34, 0);
			// ocall_printint(&files[fileNum].nodes[j].chunk_id);
			// ocall_printf("ip: ", 16, 0);
			// ocall_printf(files[fileNum].nodes[j].ip, 16, 0);
			// ocall_printf("port: ", 4, 0);
			// ocall_printint(&files[fileNum].nodes[j].port);
			// ocall_printf("++++++++++++++++++++++++++++++", 30, 0);

			// // ================================ end negative time ================================
			// ocall_test_time(neg_end_time);
			// total_neg_time += (*neg_end_time - *neg_start_time);


			ecdh_shared_secret(current_privKey, peer_i_pubKey, files[fileNum].nodes[j].dh_sharedKey_peer2peer);
			// files[i].nodes[j].socket_fd = *socket_fd;    	
    		// // size_t len = KEY_SIZE;
    		// // hmac_sha1(dh_sharedKey, ECC_PUB_KEY_SIZE, keyNonce, KEY_SIZE, sharedKey, &len);
			// ocall_printf("dh_sharedKey_peer2peer", 25, 0);
			// ocall_printf(files[i].nodes[j].dh_sharedKey_peer2peer, 46, 1);
			free(current_privKey);
			free(current_pubKey);
			free(peer_i_pubKey);
		}	
	}

	// get keys from data owner
	// if (files[fileNum].is_parity_peer) {
	if (1 == 1) {

		ocall_printf("----------------------------------------", 42, 0);
		ocall_printf("request to owner to send shuffle key", 40, 0);
		uint8_t Shuffle_key[16];
		uint8_t PC_KEY[32];
		uint8_t sig_key[32];

		uint8_t Kexchange_prv_KEY[ECC_PRV_KEY_SIZE];
		uint8_t Kexchange_PUB_KEY[ECC_PUB_KEY_SIZE];
		uint8_t Kexchange_DataOwner_PUB_KEY[ECC_PUB_KEY_SIZE];


		for(int i = 0; i < ECC_PRV_KEY_SIZE; ++i) {
			Kexchange_prv_KEY[i] = prng_next();
		}

		// Generate ecc keypair
		ecdh_generate_keys(Kexchange_PUB_KEY, Kexchange_prv_KEY);

		
		ocall_get_shuffle_key(Shuffle_key, sig_key, Kexchange_PUB_KEY, Kexchange_DataOwner_PUB_KEY, PC_KEY, files[fileNum].owner_ip, files[fileNum].owner_port);


		uint8_t dh_sharedKey_DataOwner [ECC_PUB_KEY_SIZE];
		ecdh_shared_secret(Kexchange_prv_KEY, Kexchange_DataOwner_PUB_KEY, dh_sharedKey_DataOwner);

// 									 TEST
		// ocall_printf("dh_sharedKey_DataOwner: ---------------", 43, 0);
		// ocall_printf(dh_sharedKey_DataOwner, 64, 1);
// 									END TEST

		DecryptData(dh_sharedKey_DataOwner, Shuffle_key, 16);
		DecryptData(dh_sharedKey_DataOwner, PC_KEY, 16);
		DecryptData(dh_sharedKey_DataOwner, sig_key, 32);

		// ================================ start negative time ================================
		ocall_test_time(neg_start_time);

		ocall_printf("Shuffle_key: ", 13, 0);
		ocall_printf(Shuffle_key, 16, 1);
		ocall_printf("PC_KEY: ", 8, 0);
		ocall_printf(PC_KEY, 32, 1);
		ocall_printf("sig_key: ", 9, 0);
		ocall_printf(sig_key, 32, 1);

		// ================================ end negative time ================================
		ocall_test_time(neg_end_time);
		total_neg_time += *neg_end_time - *neg_start_time;


		memcpy(files[fileNum].shuffel_key, Shuffle_key, 16);
		memcpy(files[fileNum].PC_Key, PC_KEY, 16);
		memcpy(files[fileNum].sig_Key, sig_key, 32);
		ocall_printf("----------------------------------------", 42, 0);

	}


	
	double sigma_start_time;
	ocall_test_time(&sigma_start_time);
	// end Amir MM Farid

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
    for (j = 0; j < fileDataTransfer->numBlocks; j++) { // Each block
		// ================================ start negative time ================================
		ocall_test_time(neg_start_time2);

        ocall_get_block(data, SEGMENT_SIZE, SEGMENT_PER_BLOCK, blockNum, fileDataTransfer->fileName);

		// ================================ end negative time ================================
		ocall_test_time(neg_end_time2);
		total_neg_time2 += *neg_end_time2 - *neg_start_time2;

		// store_data(data, blockNum);

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

        blockNum++;
    }

	double sigma_end_time;
	ocall_test_time(&sigma_end_time);
	ocall_log_double("=", 0);
	ocall_log_double("Sigma time: %f", (sigma_end_time - sigma_start_time) - total_neg_time2);
	ocall_log_double("Sigma time: %f", (sigma_end_time - sigma_start_time));
	ocall_log_double("=", 0);
	

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


	// ================================ end time ================================
	ocall_test_time(time_end);
	double total_time = ((*time_end - *time_start) - total_neg_time) - total_neg_time2;
	ocall_printf("==================================================", strlen("=================================================="), 0);
	ocall_printf("Total time for File init:", strlen("Total time for File init:"), 0);
	ocall_printdouble(&total_time);
	ocall_log_double("=", 0);
	ocall_log_double("Total time for File init: %f", total_time);
	ocall_log_double("=", 0);
	ocall_printf("==================================================", strlen("=================================================="), 0);

	free(time_start);
	free(time_end);
	free(neg_start_time);
	free(neg_end_time);
	// free(total_neg_time);


    return i;

}

void ecall_audit_file(const char *fileName, int *ret) 
{

	double start_time;
	double end_time;
	double start_negetive_time;
	double end_negetive_time;

	// Find file in files
	int i;
	for(i = 0; i < MAX_FILES; i++) {
		if(strcmp(fileName, files[i].fileName) == 0) {
			break;
		}
	}
	double total_negetive_time = 0;
	// ================================ Start time  ================================
	ocall_test_time(&start_time);

	// First, calculate tag segment number
	const int totalSegments = (files[i].numBlocks * SEGMENT_PER_BLOCK);
	int sigPerSeg = floor((double)SEGMENT_SIZE / ((double)PRIME_LENGTH / 8));
	int tagSegNum = totalSegments + ceil((double)files[i].numBlocks /(double) sigPerSeg);

	// Generate public challenge number
	uint8_t challNum[KEY_SIZE];
	if(sgx_read_rand(challNum, KEY_SIZE) != SGX_SUCCESS) {
		// Handle Error
	}
	// ================================ negative time  ================================
	ocall_test_time(&start_negetive_time);
	//_______________________ Send nonce to data owner _______________________
	ocall_send_nonce(challNum);
	
	ocall_test_time(&end_negetive_time);
	total_negetive_time += (end_negetive_time - start_negetive_time);
	// ================================ negative time  ================================

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
	// ================================ negative time  ================================
	ocall_test_time(&start_negetive_time);
	ocall_get_segment(fileName, tagSegNum, segData, 0); // ocall get segment will write segNum to addr 951396 then simply read the segment. it should have first 16 bytes encrypted.
	ocall_test_time(&end_negetive_time);
	total_negetive_time += (end_negetive_time - start_negetive_time);
	// ================================ negative time  ================================

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

	double *start_challenge_time = malloc(sizeof(double));
	ocall_test_time(start_challenge_time);

	
	// Call gen_challenge to get {i, Vi}
	uint8_t indices[NUM_CHAL_BLOCKS];
	uint8_t *coefficients = malloc(sizeof(uint8_t) * ((PRIME_LENGTH / 8) * NUM_CHAL_BLOCKS));

	gen_challenge(files[i].numBlocks, indices, coefficients, files[i].prime); // MAYBE?? reduce coeff mod p

	double *end_challenge_time = malloc(sizeof(double));
	ocall_test_time(end_challenge_time);

	ocall_log_double("=", 0);
	ocall_log_double("Challenge time: %f", *end_challenge_time - *start_challenge_time);
	ocall_log_double("=", 0);

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
	   // ================================ negative time  ================================
	   ocall_test_time(&start_negetive_time);
 	   ocall_get_segment(fileName, sigSeg, sigData, 0);
	   ocall_test_time(&end_negetive_time);
	   total_negetive_time += (end_negetive_time - start_negetive_time);
	   // ================================ negative time  ================================

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
			// ================================ negative time  ================================
			ocall_test_time(&start_negetive_time);
	 		ocall_get_segment(fileName, segNum, segData, 0);
			ocall_test_time(&end_negetive_time);
			total_negetive_time += (end_negetive_time - start_negetive_time);
			// ================================ negative time  ================================
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

	// ================================ time calculation  ================================
	ocall_test_time(&end_time);
	ocall_printf("==================================================================", strlen("=================================================================="), 0);
	double total_time = (end_time - start_time) - total_negetive_time;
	ocall_printf("Total time for File audit:", strlen("Total time for File audit:"), 0);
	ocall_printdouble(&total_time);
	ocall_log_double("=", 0);
	ocall_log_double("Total time for File audit: %f", total_time);
	ocall_log_double("=", 0);
	ocall_printf("==================================================================", strlen("=================================================================="), 0);

	// ================================ time calculation  ================================

	uint8_t sigs[PRIME_LENGTH / 8];
	BN_bn2bin(sigma, sigs);
	ocall_printf("SIGMA (1 and 2): ", 18, 0);
	ocall_printf(sigs, PRIME_LENGTH / 8, 1);
	BN_bn2bin(sigma2, sigs);
	ocall_printf(sigs, PRIME_LENGTH / 8, 1);

	// Compare the two calculations
	*ret = BN_cmp(sigma, sigma2);

	return;
}


void getgetsigma(BIGNUM **sigmas, int numSigmas, uint8_t *tempKey, int *indices, uint8_t *fileName) {
	
	BIGNUM *bprime = BN_new();
	BN_zero(bprime);
	BN_bin2bn(files[0].prime, PRIME_LENGTH / 8, bprime);

	uint8_t *coefficients = malloc(sizeof(uint8_t) * ((PRIME_LENGTH / 8) * NUM_CHAL_BLOCKS));

	const int totalSegments = (files[0].numBlocks * SEGMENT_PER_BLOCK);
	int sigPerSeg = floor((double)SEGMENT_SIZE / ((double)PRIME_LENGTH / 8));
	int tagSegNum = totalSegments + ceil((double)files[0].numBlocks /(double) sigPerSeg);
	int tagPageNum = floor(tagSegNum / SEGMENT_PER_PAGE);

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

    	BN_mod_mul(product1, bsigma, ccoefficient, bprime, ctx);
    	BN_mod_add(sigma, sigma, product1, bprime, ctx);
		BN_CTX_end(ctx);
	}



	return;
}

ecall_compare(){

	ocall_printf("debug 17", 8, 0);

	int numBlocks = files[0].numBlocks;
    int numPages = numBlocks * PAGE_PER_BLOCK;
	// int numGroups = files[0].numGroups;
    int numBits = (int)ceil(log2(numPages)) + 1;

	ocall_printf("numBlocks:", 10, 0);
	ocall_printint(&numBlocks);
	ocall_printf("numBits:", 10, 0);
	ocall_printint(&numBits);



	ocall_init_parity(numBits);

	uint8_t keyNonce[KEY_SIZE];
	uint8_t sharedKey[KEY_SIZE] = {0};

	sgx_read_rand(keyNonce, KEY_SIZE);


	ocall_send_nonce(keyNonce);

	size_t len = KEY_SIZE;
	hmac_sha1(dh_sharedKey, ECC_PUB_KEY_SIZE, keyNonce, KEY_SIZE, sharedKey, &len);

	ocall_printf("sharedKey:", 10, 0);
	ocall_printf(sharedKey, KEY_SIZE, 1);



	// int pageNum = (0 * PAGE_PER_BLOCK) + 1;
	// int permutedPageNum = feistel_network_prp(sharedKey, pageNum, numBits);
    // int segNum = (permutedPageNum * SEGMENT_PER_PAGE) + 0;

	int blockNum = 0;
	// int segNum = 0;
	uint8_t segData[SEGMENT_SIZE];
	uint8_t data[BLOCK_SIZE];

	// ocall_get_segment(files[0].fileName, segNum, segData, 0);

    ocall_get_block(data, SEGMENT_SIZE, SEGMENT_PER_BLOCK, blockNum, files[0].fileName);

	// DecryptData((uint32_t *)sharedKey, segData, SEGMENT_SIZE); 	


	uint8_t data2[BLOCK_SIZE];

	for (int i = 0; i < 2; i++)
	{
		int pageNum = (0 * PAGE_PER_BLOCK) + i;
		int permutedPageNum = feistel_network_prp(sharedKey, pageNum, numBits);

		for (int j = 0; j < 4; j++)
		{
			int segNum = (permutedPageNum * SEGMENT_PER_PAGE) + j;
			ocall_get_segment(files[0].fileName, segNum, segData, 0);
			DecryptData((uint32_t *)sharedKey, segData, SEGMENT_SIZE);
			// memcpy(newData, data + ((i+1) * j)* SEGMENT_SIZE), 512);
			memcpy(data2 + ((i * 4 + j) * SEGMENT_SIZE), segData, SEGMENT_SIZE);

		}
	}
					
	uint8_t newData[SEGMENT_SIZE];
	memcpy(newData, data + (4* SEGMENT_SIZE), 512);
	

	if (memcmp(data2, data, BLOCK_SIZE) == 0) {
        ocall_printf("Everything is working correctly!", 31, 0);
    } else {
        ocall_printf("Data mismatch in first 512 bytes!", 31, 0);
    }

	ocall_printf("data2", 10, 0);
	ocall_printf(data2, BLOCK_SIZE, 1);
	ocall_printf("--------------------------------", 10, 0);
	ocall_printf("data", 10, 0);
	ocall_printf(data, BLOCK_SIZE, 1);



	const int totalSegments = (files[0].numBlocks * SEGMENT_PER_BLOCK);
	int sigPerSeg = floor((double)SEGMENT_SIZE / ((double)PRIME_LENGTH / 8));
	int tagSegNum = totalSegments + ceil((double)files[0].numBlocks /(double) sigPerSeg);
	int tagPageNum = floor(tagSegNum / SEGMENT_PER_PAGE);
	ocall_printf("totalSegments:", 10, 0);
	ocall_printint(&totalSegments);
	ocall_printf("sigPerSeg:", 10, 0);
	ocall_printint(&sigPerSeg);
	ocall_printf("tagSegNum:", 10, 0);
	ocall_printint(&tagSegNum);
	ocall_printf("tagPageNum:", 10, 0);
	ocall_printint(&tagPageNum);
		// Permute tagPageNum

// added
	// sgx_read_rand(keyNonce, KEY_SIZE);


	// ocall_send_nonce(keyNonce);

	// hmac_sha1(dh_sharedKey, ECC_PUB_KEY_SIZE, keyNonce, KEY_SIZE, sharedKey, &len);


	int permutedPageNum = feistel_network_prp(sharedKey, tagPageNum, numBits);
	tagSegNum = (permutedPageNum * SEGMENT_PER_PAGE) + (tagSegNum % tagPageNum); // note, the tag is after the file, 
																					// so numBits may be wrong
ocall_printf("tagSegNum2", 10, 0);
	ocall_printint(&tagSegNum);
		ocall_get_segment(files[0].fileName, tagSegNum, segData, 0);


		DecryptData((uint32_t *)sharedKey, segData, SEGMENT_SIZE); 

		Tag *tag = (Tag *)malloc(sizeof(Tag));
	    memcpy(tag, segData, sizeof(Tag));
	    decrypt_tag(tag, porSK);

		// Get sigmas
		BIGNUM *sigmas[1];


		// getgetsigma(sigmas, 1, sharedKey, &blockNum, files[0].fileName);

		// uint8_t sigs[PRIME_LENGTH / 8];
		// BN_bn2bin(sigmas[0], sigs);
		// ocall_printf("SIGMA (1 and 2): ", 18, 0);

		for(int i = 0; i < 1; i++) {
 		   sigmas[i] = BN_new();
		    BN_zero(sigmas[i]);

		    int startSeg = totalSegments;
		    int sigSegNum = floor(blockNum/ sigPerSeg) + startSeg;
		    int sigPageNum = floor(sigSegNum / SEGMENT_PER_PAGE);
			
			ocall_printf("startSeg:", 10, 0);
			ocall_printint(&startSeg);
			ocall_printf("sigSegNum:", 10, 0);
			ocall_printint(&sigSegNum);
			ocall_printf("sigPageNum:", 10, 0);
			ocall_printint(&sigPageNum);

		    // Permute sigPageNum
		    permutedPageNum = feistel_network_prp(sharedKey, sigPageNum, numBits);
		    int permutedSigSegNum = (permutedPageNum * SEGMENT_PER_PAGE) + (sigSegNum % SEGMENT_PER_PAGE);

			ocall_printf("permutedPageNum:", 10, 0);
			ocall_printint(&permutedPageNum);
			ocall_printf("permutedSigSegNum:", 10, 0);
			ocall_printint(&permutedSigSegNum);


		    uint8_t sigData[SEGMENT_SIZE];

		    ocall_get_segment(files[0].fileName, permutedSigSegNum, sigData, 0);



		    DecryptData((uint32_t *)sharedKey, sigData, SEGMENT_SIZE);
		    int segIndex = blockNum% sigPerSeg;

			ocall_printf("sigData:", 10, 0);
			ocall_printf(sigData, 80, 1);

			ocall_printf("-------------------------------------------------", 30, 0);
			ocall_printf("segIndex:", 10, 0);
			ocall_printint(&segIndex);

		    BN_bin2bn(sigData + (segIndex * (PRIME_LENGTH / 8)), PRIME_LENGTH / 8, sigmas[i]);
		}

		int indices[1];
		indices[0] = 0;
		// getgetsigma(sigmas, 1, sharedKey, indices, files[0].fileName);

		ocall_printf("sigmas[0]:", 10, 0);
		ocall_printf(sigmas[0], PRIME_LENGTH / 8, 1);
		ocall_printf("tag:", 10, 0);
		ocall_printf(tag, sizeof(Tag), 1);

	if (audit_block_group(0, 1, indices, sigmas, tag, data2) != 0) {
		    ocall_printf("AUDIT FAILED!!", 15, 0);
		} else {
		    ocall_printf("AUDIT SUCCESS!", 15, 0);
		}

	ocall_init_parity(numBits);

	return;
}


void ecall_check_block(int fileNum, int blockNum,  uint8_t *status, uint8_t *signature, uint8_t *recovered_block, int recovered_block_size, int recovered_block_count){
	
	double time_start;
	double time_end;
	
	// ================================ start time ================================
	ocall_test_time(&time_start);


	check_block(fileNum, blockNum, status, recovered_block);
	EncryptData(&files[fileNum].PC_Key, recovered_block, recovered_block_size);

	ocall_printf("Generating signature", 20, 0);
	int data_len = 32;
	hmac_sha2(files[fileNum].PC_Key, 32, recovered_block, recovered_block_size, signature, &data_len);

	// ================================ end time ================================
	ocall_test_time(&time_end);
	double total_time = (time_end - time_start);
	ocall_printf("==================================================", strlen("=================================================="), 0);
	ocall_printf("Total time for check 1 block (External request):", strlen("Total time for check 1 block (External request):"), 0);
	ocall_printdouble(&total_time);
	ocall_log_double("=", 0);
	ocall_log_double("Total time for check 1 block (External request): %f", total_time);
	ocall_log_double("=", 0);
	ocall_printf("==================================================", strlen("=================================================="), 0);
	return;
}

void check_block(int fileNum, int blockNum,  uint8_t *status, uint8_t *recovered_block){

	
	double time_start;
	double time_end;
	double neg_start_time;
	double neg_end_time;
	double total_neg_time = 0;
	
	
	
	
	ocall_printf("Checking block", 15, 0);


	int numBlocks = files[fileNum].numBlocks;
    int numPages = numBlocks * PAGE_PER_BLOCK;
	// int numGroups = files[0].numGroups;
    int numBits = (int)ceil(log2(numPages)) + 1;

	ocall_printf("numBlocks:", 10, 0);
	ocall_printint(&numBlocks);
	ocall_printf("numBits:", 10, 0);
	ocall_printint(&numBits);



	ocall_init_parity(numBits);

	uint8_t keyNonce[KEY_SIZE];
	uint8_t sharedKey[KEY_SIZE] = {0};


	// ================================ start time ================================
	ocall_test_time(&time_start);

	sgx_read_rand(keyNonce, KEY_SIZE);

	// ================================ neg start time ================================
	ocall_test_time(&neg_start_time);

	ocall_send_nonce(keyNonce);

	// ================================ neg end time ================================
	ocall_test_time(&neg_end_time);
	total_neg_time += (neg_end_time - neg_start_time);

	size_t len = KEY_SIZE;
	hmac_sha1(dh_sharedKey, ECC_PUB_KEY_SIZE, keyNonce, KEY_SIZE, sharedKey, &len);


	// int blockNum = 0;
	uint8_t segData[SEGMENT_SIZE];
	uint8_t data[BLOCK_SIZE];


	

	// uint8_t data2[BLOCK_SIZE];

	for (int i = 0; i < 2; i++)
	{
		int pageNum = (blockNum * PAGE_PER_BLOCK) + i;
		int permutedPageNum = feistel_network_prp(sharedKey, pageNum, numBits);

		for (int j = 0; j < 4; j++)
		{
			// ================================ start neg time ================================
			ocall_test_time(&neg_start_time);
			int segNum = (permutedPageNum * SEGMENT_PER_PAGE) + j;
			ocall_get_segment(files[fileNum].fileName, segNum, segData, 0);
			// ================================ end neg time ================================
			ocall_test_time(&neg_end_time);
			total_neg_time += (neg_end_time - neg_start_time);

			DecryptData((uint32_t *)sharedKey, segData, SEGMENT_SIZE);
			// memcpy(newData, data + ((i+1) * j)* SEGMENT_SIZE), 512);
			memcpy(data + ((i * 4 + j) * SEGMENT_SIZE), segData, SEGMENT_SIZE);

		}
	}

					
// ================================ start neg time ================================
	ocall_test_time(&neg_start_time);

	const int totalSegments = (files[fileNum].numBlocks * SEGMENT_PER_BLOCK);
	int sigPerSeg = floor((double)SEGMENT_SIZE / ((double)PRIME_LENGTH / 8));
	int tagSegNum = totalSegments + ceil((double)files[fileNum].numBlocks /(double) sigPerSeg);
	int tagPageNum = floor(tagSegNum / SEGMENT_PER_PAGE);



	int permutedPageNum = feistel_network_prp(sharedKey, tagPageNum, numBits);
	tagSegNum = (permutedPageNum * SEGMENT_PER_PAGE) + (tagSegNum % tagPageNum); // note, the tag is after the file, so numBits may be wrong
	
		ocall_get_segment(files[fileNum].fileName, tagSegNum, segData, 0);

		// ================================ neg end time ================================
		ocall_test_time(&neg_end_time);
		total_neg_time += (neg_end_time - neg_start_time);

		DecryptData((uint32_t *)sharedKey, segData, SEGMENT_SIZE); 

		Tag *tag = (Tag *)malloc(sizeof(Tag));
	    memcpy(tag, segData, sizeof(Tag));
	    decrypt_tag(tag, porSK);

		// Get sigmas
		BIGNUM *sigmas[1];


		// getgetsigma(sigmas, 1, sharedKey, &blockNum, files[0].fileName);

		// uint8_t sigs[PRIME_LENGTH / 8];
		// BN_bn2bin(sigmas[0], sigs);
		// ocall_printf("SIGMA (1 and 2): ", 18, 0);

		// for(int i = 0; i < 1; i++) {
		// sigma retrieval starts here
 		sigmas[0] = BN_new();
		BN_zero(sigmas[0]);

		uint8_t sigData[SEGMENT_SIZE];
		// ================================ neg start time ================================

		int startSeg = totalSegments;
		int sigSegNum = floor(blockNum/ sigPerSeg) + startSeg;
		int sigPageNum = floor(sigSegNum / SEGMENT_PER_PAGE);
			
			// ocall_printf("startSeg:", 10, 0);
			// ocall_printint(&startSeg);
			// ocall_printf("sigSegNum:", 10, 0);
			// ocall_printint(&sigSegNum);
			// ocall_printf("sigPageNum:", 10, 0);
			// ocall_printint(&sigPageNum);

		    // Permute sigPageNum
		permutedPageNum = feistel_network_prp(sharedKey, sigPageNum, numBits);
		int permutedSigSegNum = (permutedPageNum * SEGMENT_PER_PAGE) + (sigSegNum % SEGMENT_PER_PAGE);

			// ocall_printf("permutedPageNum:", 10, 0);
			// ocall_printint(&permutedPageNum);
			// ocall_printf("permutedSigSegNum:", 10, 0);
			// ocall_printint(&permutedSigSegNum);

		ocall_test_time(&neg_start_time);
		ocall_get_segment(files[fileNum].fileName, permutedSigSegNum, sigData, 0);
		// ================================ neg end time ================================
		ocall_test_time(&neg_end_time);
		total_neg_time += (neg_end_time - neg_start_time);

		DecryptData((uint32_t *)sharedKey, sigData, SEGMENT_SIZE);
		int segIndex = blockNum% sigPerSeg;
		//ocall_printf("sigData:", 10, 0);
		//ocall_printf(sigData, SEGMENT_SIZE, 1);
		//ocall_printf("-------------------------------------------------", 30, 0);
		//ocall_printf("segIndex:", 10, 0);
		//ocall_printint(&segIndex);
		BN_bin2bn(sigData + (segIndex * (PRIME_LENGTH / 8)), PRIME_LENGTH / 8, sigmas[0]);
	
		// sigma retrieval finished

		int indices[1];
		indices[0] = blockNum;
		// getgetsigma(sigmas, 1, sharedKey, indices, files[0].fileName);

		// ================================ neg start time ================================
		ocall_test_time(&neg_start_time);

		ocall_printf("sigmas[0]:", 10, 0);
		ocall_printf(sigmas[0], PRIME_LENGTH / 8, 1);
		ocall_printf("tag:", 10, 0);
		ocall_printf(tag, sizeof(Tag), 1);

		ocall_printf("========================================", 40, 0);
		ocall_printf("I am in the audit block group", 30, 0);

		// ================================ neg end time ================================
		ocall_test_time(&neg_end_time);
		total_neg_time += (neg_end_time - neg_start_time);

	if (audit_block_group(0, 1, indices, sigmas, tag, data) != 0) {
			*status = 1;
		    ocall_printf("AUDIT FAILED!!", 15, 0);
		} else {
			*status = 0;
		    ocall_printf("AUDIT SUCCESS!", 15, 0);
			// memcpy(recovered_block, data, BLOCK_SIZE);
			for (int i = 0; i < BLOCK_SIZE; i++)
			{
				recovered_block[i] = data[i];
			}
			ocall_printf("recovered block: ", 18, 0);
			ocall_printf(recovered_block, 32, 1);
			
		}

		// ================================ end time ================================
		ocall_test_time(&time_end);
		double total_time = (time_end - time_start) - total_neg_time;
		ocall_printf("================================================", strlen("================================================"), 0);
		ocall_printf("Total time for check 1 block:", strlen("Total time for check 1 block:"), 0);
		ocall_printdouble(&total_time);
		ocall_log_double("=", 0);
		ocall_log_double("Total time for check 1 block: %f", total_time);
		ocall_log_double("=", 0);
		ocall_printf("================================================", strlen("================================================"), 0);

	ocall_init_parity(numBits);

	return;
}



void ecall_init_rs_matrix(int k, int n){
	initiate_rs(k, n);
	return;
}



void recover_block(int fileNum, int blockNum, uint8_t *blockData, int *toggle){


	double *time_start = malloc(sizeof(double));
	double *time_end = malloc(sizeof(double));
	double *neg_start_time = malloc(sizeof(double));
	double *neg_end_time = malloc(sizeof(double));
	double total_neg_time = 0;
	


	int k = files[fileNum].k;
	int n = files[fileNum].n;
	int symSize = 16;
	int m = n - k;

	int *erasures = malloc(sizeof(int) * n);
	for (int i = 0; i < n; i++) {
		erasures[i] = -1;
	}

    int *matrix = (int *)malloc(sizeof(int) * m * k);

	// the recovered block
	// divded by 2 because the data is uint16_t
    uint16_t *recovered_data = (uint16_t *)malloc(sizeof(uint16_t) * BLOCK_SIZE / 2);


	uint8_t *code_word = (uint8_t *)malloc(n * BLOCK_SIZE);
	uint8_t *signatures = (uint8_t *)malloc(n * 32);

	uint8_t *recovered_block = (uint8_t *)malloc(BLOCK_SIZE);

	if (!matrix || !recovered_data || !code_word || !recovered_block) {
    	ocall_printf("Memory allocation failed", 8, 0);
    	return;
	}



	int *code_word_index = malloc(n * sizeof(int));
	for (int i = 0; i < n; i++) code_word_index[i] = -1;

	// ================================ start time ================================
	ocall_test_time(time_start);

	NodeInfo *nodes = (NodeInfo *)malloc(NUM_NODES * sizeof(NodeInfo));

	for (int i = 0; i < NUM_NODES; i++) {


		for (int j = 0; j < 16; j++) {
			nodes[i].ip[j] = files[fileNum].nodes[i].ip[j];
		}
		nodes[i].port = files[fileNum].nodes[i].port;
		nodes[i].chunk_id = files[fileNum].nodes[i].chunk_id;
		nodes[i].socket_fd = files[fileNum].nodes[i].socket_fd;
		nodes[i].is_parity_peer = files[fileNum].nodes[i].is_parity_peer;
	}

	// claculate block number in the file
	int total_blocks = files[fileNum].numBlocks * files[fileNum].k;
    int numBits = (int)ceil(log2(total_blocks));


	
	recoverable_block_indicies *rb_indicies = (recoverable_block_indicies *)malloc(sizeof(recoverable_block_indicies) * files[fileNum].n);
	
	// calculate the code word number (the number of code words that blockNum is in)
	// so we know which code word to use (parity)


	int *out_tuple = malloc(sizeof(int) * files[fileNum].k);
	find_tuple_for_digit(files[fileNum].shuffel_key, blockNum, out_tuple, files[fileNum].numBlocks *files[fileNum].k, files[fileNum].k);	


	int code_word_number = out_tuple[0];
	for (int l = 1; l < files[fileNum].k; l++) {
		if (out_tuple[l] < code_word_number) {
			code_word_number = out_tuple[l];
		}
	}
	
	for (int i = 0; i < files[fileNum].k; i++) {
		
		
		if (blockNum ==  out_tuple[i]) {
			rb_indicies[i].is_corrupted = 1;
			erasures[0] = i;
		} else {
			rb_indicies[i].is_corrupted = 0;
		}

		rb_indicies[i].total_blocks_index = out_tuple[i];
		

		// the temp is the internal block index
		rb_indicies[i].node_index = (out_tuple[i] / files[fileNum].numBlocks);

		rb_indicies[i].internal_block_index = out_tuple[i] - (rb_indicies[i].node_index * files[fileNum].numBlocks);
		rb_indicies[i].code_word_number = code_word_number;

		if (rb_indicies[i].node_index == files[fileNum].current_chunk_id) {

			rb_indicies[i].is_local = 1;
		} else {
			rb_indicies[i].is_local = 0;
		}
		// ================================ neg start time ================================
		// ocall_test_time(neg_start_time);
		// ocall_printf("*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=", strlen("*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*="), 0);
		// ocall_printf("the rquested block is:", strlen("the rquested block is:"), 0);
		// ocall_printint(&blockNum);
		// ocall_printf("the I is:", strlen("the I is:"), 0);
		// ocall_printint(&i);
		// ocall_printf("the tmp_index is:", strlen("the tmp_index is:"), 0);
		// ocall_printint(&out_tuple[i]);
		// ocall_printf("**********", strlen("**********"), 0);
		// ocall_printf("the node index is:", strlen("the node index is:"), 0);
		// ocall_printint(&rb_indicies[i].node_index);
		// ocall_printf("the current chunk id is:", strlen("the current chunk id is:"), 0);
		// ocall_printint(&files[fileNum].current_chunk_id);
		// ocall_printf("the internal block index is:", strlen("the internal block index is:"), 0);
		// ocall_printint(&rb_indicies[i].internal_block_index);
		// ocall_printf("the code word number is:", strlen("the code word number is:"), 0);
		// ocall_printint(&rb_indicies[i].code_word_number);
		// ================================ neg end time ================================
		// ocall_test_time(neg_end_time);
		// total_neg_time += *neg_end_time - *neg_start_time;
	}


	
	ocall_printf("*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=", strlen("*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*="), 0);

	int total_parity_blocks = files[fileNum].numBlocks * (files[fileNum].n - files[fileNum].k);

	int numBitsParity = (int)ceil(log2(total_parity_blocks));

	for (int i = files[fileNum].k; i < files[fileNum].n; i++)
	{

		int requested_block = code_word_number + (i - files[fileNum].k) * files[fileNum].numBlocks;

		int tmp_index = feistel_network_prp(files[fileNum].shuffel_key, requested_block, numBitsParity);
		while (tmp_index >= total_parity_blocks) {
			tmp_index = feistel_network_prp(files[fileNum].shuffel_key, tmp_index, numBitsParity);
		}

		rb_indicies[i].is_local = 0;
		
		rb_indicies[i].is_corrupted = 0;


		rb_indicies[i].total_blocks_index = tmp_index;
		int temp_internal_block_index = tmp_index % files[fileNum].numBlocks;
		rb_indicies[i].internal_block_index = temp_internal_block_index;
		rb_indicies[i].node_index = (tmp_index - temp_internal_block_index) / files[fileNum].numBlocks + files[fileNum].k;
		rb_indicies[i].code_word_number = code_word_number;	
	// ocall_printf("*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=", 42, 0);
	// ocall_printf("*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=", 42, 0);
	// ocall_printf("*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=", 42, 0);
	// ocall_printf("this is the i:", 14, 0);
	// ocall_printint(&i);
	// ocall_printf("the requested block is:", 23, 0);
	// ocall_printint(&requested_block);
	// ocall_printf("the total blocks index is:", 26, 0);
	// ocall_printint(&rb_indicies[i].total_blocks_index);
	// ocall_printf("the internal block index is:", 28, 0);
	// ocall_printint(&rb_indicies[i].internal_block_index);
	// ocall_printf("the node index is:", 18, 0);
	// ocall_printint(&rb_indicies[i].node_index);
	// ocall_printf("the code word number is:", 24, 0);
	// ocall_printint(&rb_indicies[i].code_word_number);
	// ocall_printf("*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=", 42, 0);
	// ocall_printf("*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=", 42, 0);
	// ocall_printf("*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=", 42, 0);
	}
	


	// ================================ neg start time ================================
	ocall_test_time(neg_start_time);

	// block number is calculated
	// now we have 
	// 1- the code word number
	// 2- the blocks number belongs to the code word

	// int internal_block_index = blockNumInFile % files[fileNum].numBlocks;
	// int node_index = (blockNumInFile - internal_block_index) / files[fileNum].numBlocks;

	int cw_size = n* BLOCK_SIZE;
	int cw_count = n;

	// int *status = ;
    uint8_t *status = malloc(sizeof(uint8_t));

	char *code_word_tmp = malloc(files[fileNum].n * sizeof(char) * BLOCK_SIZE);
	
	// first we collect the local blocks

	int counter_outside_data = 0;
	for (int i = 0; i < files[fileNum].k; i++) {

		uint8_t *tmpcode_word = (uint8_t *)malloc(BLOCK_SIZE);
		
		if (rb_indicies[i].is_local == 1) {
			if (*toggle) {
				ocall_init_parity(numBits);
				*toggle = 0;
			}
			// ocall_printf("###########################Local Block DETECTED###############################", 78, 0);
			// ocall_printf("the real block index is:", 24, 0);
			// ocall_printint(&rb_indicies[i].total_blocks_index);

			check_block(fileNum, rb_indicies[i].internal_block_index, status, tmpcode_word);


			if (*status == 0) {
				ocall_printf("THE BLOCK IS VALID", 18, 0);
				// if the block is not corrupted, we can directly assign the code word
				for (int j = 0; j < BLOCK_SIZE; j++) {
					code_word[rb_indicies[i].node_index * BLOCK_SIZE + j] = tmpcode_word[j];
					code_word_tmp[i * BLOCK_SIZE + j] = tmpcode_word[j];
				}
			}else{
				ocall_printf("local block is corrupted", 15, 0);
			}
	
		}else{
			code_word_index[i] = 1;
			counter_outside_data++;
		}

		free(tmpcode_word);
	}

	ocall_printf("=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= Request Block =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=", 77, 0);

	sgx_status_t ocall_ret = ocall_get_batch_blocks(fileNum, rb_indicies, sizeof(recoverable_block_indicies), files[fileNum].n, signatures, code_word, code_word_index, nodes, cw_size, cw_count, sizeof(NodeInfo));
	
	printEnclaveError(ocall_ret);
	
	ocall_get_rs_matrix(k, m, symSize, matrix, m*k);

	ocall_printf("=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=  =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=", strlen("=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=  =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-="), 0);
	ocall_printint(&files[fileNum].n);
	ocall_printf("=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=  =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=", strlen("=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=  =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-="), 0);
	for (int i = 0; i < files[fileNum].n; i++) {

		if ( rb_indicies[i].is_local == 1) {
		ocall_printf("# # # # # # ## # # # # # # Local Block # # # # # # ## # # # # # #", strlen("# # # # # # ## # # # # # # Local Block # # # # # # ## # # # # # #"), 0);
		ocall_printf("THIS IS BLOCK INDEX: ", strlen("THIS IS BLOCK INDEX: "), 0);
		ocall_printint(&i);
		ocall_printf("THIS IS BLOCK: ", strlen("THIS IS BLOCK: "), 0);
		ocall_printf(code_word_tmp + i * BLOCK_SIZE, 50, 1);
		}else{
		ocall_printf("# # # # # # ## # # # # # # Foreign Block # # # # # # ## # # # # # #", strlen("# # # # # # ## # # # # # # Foreign Block # # # # # # ## # # # # # #"), 0);
		ocall_printf("THIS IS BLOCK INDEX: ", strlen("THIS IS BLOCK INDEX: "), 0);
		ocall_printint(&i);
		ocall_printf("THIS IS BLOCK: ", strlen("THIS IS BLOCK: "), 0);
		ocall_printf(code_word + i * BLOCK_SIZE, 50, 1);

		ocall_printf("THIS IS Signature: ", strlen("THIS IS Signature: "), 0);
		ocall_printf(signatures + (i * 32), 32, 1);
		
		}
ocall_printf("=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=  =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=", strlen("=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=  =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-="), 0);

	}
	
	// ================================ neg end time ================================
	ocall_test_time(neg_end_time);
	total_neg_time += *neg_end_time - *neg_start_time;

	int counter_index = 0;

	for (int i = 0; i < files[fileNum].n; i++) {
	// ================================ verify signatures ================================
		if (rb_indicies[i].is_local) { ocall_printf("Local Signature", 15, 0); continue;}
		uint8_t signature2[32] = {0};
		ocall_printf("Generating signature", 20, 0);
		size_t data_len2 = 32;

		uint8_t *tmp_for_signature = malloc(32);
		memcpy(tmp_for_signature, signatures + (i * 32), 32);

		hmac_sha2(files[fileNum].sig_Key, 32, code_word + (i * BLOCK_SIZE), BLOCK_SIZE, signature2, &data_len2);

		// ================================ neg start time ================================
		ocall_test_time(neg_start_time);

		ocall_printf("signature2", 10, 0);
		ocall_printf(signature2, 32, 1);
		ocall_printf("tmp_for_signature", 18, 0);
		ocall_printf(tmp_for_signature, 32, 1);

		if (memcmp(tmp_for_signature, signature2, 32) == 0) {
			ocall_printf("Signature match", 15, 0);
			ocall_printint(&i);
		} else {
			ocall_printf("Signature mismatch", 18, 0);
			ocall_printint(&i);
		}
		// ================================ neg end time ================================
		ocall_test_time(neg_end_time);
		total_neg_time += *neg_end_time - *neg_start_time;

		free(tmp_for_signature);
	// ================================ decrypt code word ================================
		
			// ocall_printf(" this is parity",15,0);
			if (code_word_index[i] == -1) {
				uint8_t *tmp_for_decrypt = malloc(BLOCK_SIZE);
				memcpy(tmp_for_decrypt, code_word_tmp + (i * BLOCK_SIZE), BLOCK_SIZE);
				DecryptData(files[fileNum].PC_Key, tmp_for_decrypt, BLOCK_SIZE);
				memcpy(code_word_tmp + (i * BLOCK_SIZE), tmp_for_decrypt, BLOCK_SIZE);
				free(tmp_for_decrypt);
			}else{
				uint8_t *tmp_for_decrypt = malloc(BLOCK_SIZE);
				memcpy(tmp_for_decrypt, code_word+ (i * BLOCK_SIZE), BLOCK_SIZE);
				DecryptData(files[fileNum].PC_Key, tmp_for_decrypt, BLOCK_SIZE);
				memcpy(code_word_tmp + (i * BLOCK_SIZE), tmp_for_decrypt, BLOCK_SIZE);
				free(tmp_for_decrypt);
				counter_index++;
			}

	}
	// ================================ neg start time ================================
	// ocall_test_time(neg_start_time);
	ocall_printf("==================================================", strlen("=================================================="), 0);
	ocall_printf("==================================================", strlen("=================================================="), 0);

	ocall_printf("code_word_tmp 0 ", strlen("code_word_tmp 0 "), 0);
	ocall_printf(code_word_tmp, 32, 1);
	ocall_printf("code_word_tmp 1 ", strlen("code_word_tmp 1 "), 0);
	ocall_printf(code_word_tmp + BLOCK_SIZE, 32, 1);
	ocall_printf("code_word_tmp 2 ", strlen("code_word_tmp 2 "), 0);
	ocall_printf(code_word_tmp + 2 * BLOCK_SIZE, 32, 1);
	ocall_printf("code_word_tmp 3 ", strlen("code_word_tmp 3 "), 0);
	ocall_printf(code_word_tmp + 3 * BLOCK_SIZE, 32, 1);
	ocall_printf("code_word_tmp 4 ", strlen("code_word_tmp 4 "), 0);
	ocall_printf(code_word_tmp + 4 * BLOCK_SIZE, 32, 1);
	ocall_printf("==================================================", strlen("=================================================="), 0);
	ocall_printf("==================================================", strlen("=================================================="), 0);

	// ocall_printf("erasure[0]", strlen("erasure[0]"), 0);
	// ocall_printint(&erasures[0]);
	// // ================================ neg end time ================================
	// ocall_test_time(neg_end_time);
	// total_neg_time += *neg_end_time - *neg_start_time;



	initiate_rs(files[fileNum].k, files[fileNum].n);
	// INJA

	uint16_t *code_word_tmp_uint16 = (uint16_t *)code_word_tmp;
	decode(BLOCK_SIZE, erasures, code_word_tmp_uint16, matrix, files[fileNum].current_chunk_id);

	// ================================ end time ================================
	ocall_test_time(time_end);

	code_word_tmp = (uint8_t *) code_word_tmp_uint16;

	ocall_printf("Recovered block after", strlen("Recovered block after"), 0);
	ocall_printf(code_word_tmp + (erasures[0] * BLOCK_SIZE), 32, 1);
	
	// store the recovered block
	memcpy(blockData, code_word_tmp + (erasures[0] * BLOCK_SIZE), BLOCK_SIZE);

	// ================================ end time ================================
	ocall_printf("==================================================", strlen("=================================================="), 0);
	ocall_printf("Total time : RECOVERY", strlen("Total time : RECOVERY"), 0);
	double total_time = (*time_end - *time_start) - total_neg_time;
	ocall_printdouble(&total_time);
	ocall_log_double("=", 0);
	ocall_log_double("Total time in recovery: %f", total_time);
	ocall_log_double("=", 0);
	ocall_printf("==================================================", strlen("=================================================="), 0);
	return;
}



void ecall_small_corruption(const char *fileName, int blockNum) {


	double *time_start = malloc(sizeof(double));
	double *time_end = malloc(sizeof(double));
	double *time_ocall1_start = malloc(sizeof(double));
	double *time_ocall1_end = malloc(sizeof(double));
	double *time_ocall2_start = malloc(sizeof(double));
	double *time_ocall2_end = malloc(sizeof(double));
	double *time_ocall3_start = malloc(sizeof(double));
	double *time_ocall3_end = malloc(sizeof(double));
	double *negative_time = malloc(sizeof(double));
	*negative_time = 0;



	int fileNum;
	for(fileNum = 0; fileNum < MAX_FILES; fileNum++) {
		if(strcmp(fileName, files[fileNum].fileName) == 0) {
			break;
		}
	}


	int numBlocks = files[fileNum].numBlocks;
    int numPages = numBlocks * PAGE_PER_BLOCK;
    int numBits = (int)ceil(log2(numPages)) + 1;


	int *toggle = malloc(sizeof(int));
	*toggle = 1;
	ocall_init_parity(numBits);

	// Generate shared key used when generating file parity, for permutation and encryption.
	uint8_t keyNonce[KEY_SIZE];
	uint8_t sharedKey[KEY_SIZE] = {0};

	sgx_read_rand(keyNonce, KEY_SIZE);

	ocall_send_nonce(keyNonce);

// ================================ START TIME ================================
	ocall_test_time(time_start);

	size_t len = KEY_SIZE;
	hmac_sha1(dh_sharedKey, ECC_PUB_KEY_SIZE, keyNonce, KEY_SIZE, sharedKey, &len);

// 	// TODO:


	int requestedBlock;
    int pageNum = 0;
    int permutedPageNum = 0;
    int segNum = 0;

	uint8_t segData[SEGMENT_SIZE];
	uint8_t blockData[BLOCK_SIZE];

	if(files[fileNum].is_parity_peer) {
		requestedBlock = feistel_network_prp(files[fileNum].shuffel_key, blockNum, numBits);
	}else{
		requestedBlock = blockNum;
	}

	for (int page = 0; page < PAGE_PER_BLOCK; page++) {

		int pageNum = (requestedBlock * PAGE_PER_BLOCK) + page;
		int permutedPageNum = feistel_network_prp(sharedKey, pageNum, numBits);

		for (int segment = 0; segment < SEGMENT_PER_BLOCK / PAGE_PER_BLOCK; segment++) {

			segNum = (permutedPageNum * SEGMENT_PER_PAGE) + segment;
			// ================================ negative time ================================
			ocall_test_time(time_ocall1_start);
			ocall_get_segment(files[fileNum].fileName, segNum, segData, 0);
			ocall_test_time(time_ocall1_end);
			*negative_time = *negative_time + (*time_ocall1_end - *time_ocall1_start);
			// ================================ negative time ================================
			DecryptData((uint32_t *)sharedKey, segData, SEGMENT_SIZE); 					
			

			int offset = ((page * (SEGMENT_PER_BLOCK / PAGE_PER_BLOCK) ) + segment)* SEGMENT_SIZE;
			memcpy(blockData + offset, segData, SEGMENT_SIZE);
		}
	}



	// ================================ negative time ================================
		ocall_test_time(time_ocall2_start);
		const int totalSegments = (files[fileNum].numBlocks * SEGMENT_PER_BLOCK);
	    int sigPerSeg = floor((double)SEGMENT_SIZE / ((double)PRIME_LENGTH / 8));
	    int tagSegNum = totalSegments + ceil((double)files[fileNum].numBlocks /(double) sigPerSeg);
		int tagPageNum = floor(tagSegNum / SEGMENT_PER_PAGE);
		// Permute tagPageNum
		permutedPageNum = feistel_network_prp(sharedKey, tagPageNum, numBits);
		tagSegNum = (permutedPageNum * SEGMENT_PER_PAGE) + (tagSegNum % tagPageNum); // note, the tag is after the file, 
																					// so numBits may be wrong

		ocall_get_segment(files[fileNum].fileName, tagSegNum, segData, 0);
		ocall_test_time(time_ocall2_end);
		*negative_time = *negative_time + (*time_ocall2_end - *time_ocall2_start);
		// ================================ negative time ================================
		DecryptData((uint32_t *)sharedKey, segData, SEGMENT_SIZE); 


		// Note, I will know that tag and sigmas come from FTL, as they are fully encrypted.
		Tag *tag = (Tag *)malloc(sizeof(Tag));
	    memcpy(tag, segData, sizeof(Tag));
	    decrypt_tag(tag, porSK);

		// Get sigmas
		BIGNUM *sigmas[1];


		// for(int i = 0; i < 1; i++) {
 		   sigmas[0] = BN_new();
		    BN_zero(sigmas[0]);
			// ================================ negative time ================================
			ocall_test_time(time_ocall3_start);	
		    int startSeg = totalSegments;
		    int sigSegNum = floor(blockNum/ sigPerSeg) + startSeg;
		    int sigPageNum = floor(sigSegNum / SEGMENT_PER_PAGE);

		    // Permute sigPageNum
		    permutedPageNum = feistel_network_prp(sharedKey, sigPageNum, numBits);
		    int permutedSigSegNum = (permutedPageNum * SEGMENT_PER_PAGE) + (sigSegNum % SEGMENT_PER_PAGE);



		    uint8_t sigData[SEGMENT_SIZE];
		    ocall_get_segment(files[fileNum].fileName, permutedSigSegNum, sigData, 0);
			ocall_test_time(time_ocall3_end);
			*negative_time = *negative_time + (*time_ocall3_end - *time_ocall3_start);
			// ================================ negative time ================================



		    DecryptData((uint32_t *)sharedKey, sigData, SEGMENT_SIZE);
		    int segIndex = blockNum% sigPerSeg;
		    BN_bin2bn(sigData + (segIndex * (PRIME_LENGTH / 8)), PRIME_LENGTH / 8, sigmas[0]);
		// }

	uint8_t Datatest[BLOCK_SIZE];
	memcpy(Datatest, blockData, BLOCK_SIZE);

	if (blockNum == 1) {
		blockData[0] = 0x00;
		blockData[1] = 0x00;
	}



	if (audit_block_group(fileNum, 1, &blockNum, sigmas, tag, blockData) != 0) {

	// ================================ time calculation ================================
		ocall_test_time(time_end);
		ocall_printf("Total time : SMALL CORRUPTION CHECK FOR CORRUPTED DATA", strlen("Total time : SMALL CORRUPTION CHECK FOR CORRUPTED DATA"), 0);
		double total_time = (*time_end - *time_start) - *negative_time;
		ocall_printdouble(&total_time);
		ocall_log_double("=", 0);
		ocall_log_double("Total time in small corruption check for corrupted data: %f", total_time);
		ocall_log_double("=", 0);
		ocall_printf("****************************************", 40, 0);
		ocall_printf("******************************", 30, 0);
		ocall_printf("********************", 20, 0);
		ocall_printf("**********", 10, 0);
	// ================================ time calculation ================================


		    ocall_printf("AUDIT FAILED!!", 15, 0);
		    ocall_printf("==================================================", 50, 0);
		    ocall_printf("recovering block", 15, 0);
			uint8_t Datatest2[BLOCK_SIZE];

			int blockNumInFile2 = (files[fileNum].numBlocks * files[fileNum].current_chunk_id) + blockNum;

			recover_block(fileNum, blockNumInFile2, Datatest2, toggle);

			ocall_printf("recieved block", strlen("recieved block"), 0);
			ocall_printf(Datatest2, 32, 1);
			ocall_printf("actual block", strlen("actual block"), 0);
			ocall_printf(Datatest, 32, 1);

			if (memcmp(Datatest, Datatest2, BLOCK_SIZE) == 0) {
				ocall_printf("Everything is working correctly!", 31, 0);
			} else {
				ocall_printf("Data mismatch in first 512 bytes!", 31, 0);
			}

		} else {
		// ================================ time calculation ================================
			ocall_test_time(time_end);
			ocall_printf("==================================================", strlen("=================================================="), 0);
			ocall_printf("Total time : SMALL CORRUPTION CHECK FOR VALID DATA", strlen("Total time : SMALL CORRUPTION CHECK FOR VALID DATA"), 0);
			double total_time = (*time_end - *time_start) - *negative_time;
			ocall_printdouble(&total_time);
			ocall_log_double("=", 0);
			ocall_log_double("Total time in small corruption check for valid data: %f", total_time);
			ocall_log_double("=", 0);
			ocall_printf("==================================================", strlen("=================================================="), 0);
		// ================================ time calculation ================================

		    ocall_printf("AUDIT SUCCESS!", 15, 0);
		}

	if (*toggle) ocall_init_parity(numBits);


	BN_free(sigmas[0]);
	free(toggle);
	free(tag);
	free(time_start);
	free(time_end);
	free(time_ocall1_start);
	free(time_ocall1_end);
	free(time_ocall2_start);
	free(time_ocall2_end);
	free(time_ocall3_start);
	free(time_ocall3_end);
	free(negative_time);
	

	return;
}


void local_code_words(int fileNum, int code_word_id, uint8_t *blockData, int *toggle){


	double *neg_start_time = malloc(sizeof(double));
	double *neg_end_time = malloc(sizeof(double));
	double *total_neg_time = malloc(sizeof(double));

	double *Blocks_retrieval_start_time = malloc(sizeof(double));
	double *Blocks_retrieval_end_time = malloc(sizeof(double));
	double *total_Blocks_retrieval_time = malloc(sizeof(double));



	int k = files[fileNum].k;
	int n = files[fileNum].n;
	int symSize = 16;
	int m = n - k;

	int *erasures = malloc(sizeof(int) * n);
	for (int i = 0; i < n; i++) {
		erasures[i] = -1;
	}

    uint16_t *recovered_data = (uint16_t *)malloc(sizeof(uint16_t) * BLOCK_SIZE / 2);

	uint8_t *code_word = (uint8_t *)malloc(n * BLOCK_SIZE);
	uint8_t *signatures = (uint8_t *)malloc(n * 32);
	uint8_t *recovered_block = (uint8_t *)malloc(BLOCK_SIZE);

	if (!recovered_data || !code_word || !recovered_block) {
    	ocall_printf("Memory allocation failed", 8, 0);
    	return;
	}


	int *code_word_index = malloc(n * sizeof(int));
	for (int i = 0; i < n; i++) code_word_index[i] = -1;

	
	// this is the nodes that will be used to recover the block
	NodeInfo *nodes = (NodeInfo *)malloc(NUM_NODES * sizeof(NodeInfo));

	for (int i = 0; i < NUM_NODES; i++) {
		for (int j = 0; j < 16; j++) {
			nodes[i].ip[j] = files[fileNum].nodes[i].ip[j];
		}
		nodes[i].port = files[fileNum].nodes[i].port;
		nodes[i].chunk_id = files[fileNum].nodes[i].chunk_id;
		nodes[i].socket_fd = files[fileNum].nodes[i].socket_fd;
		nodes[i].is_parity_peer = files[fileNum].nodes[i].is_parity_peer;
	}

	// claculate block number in the file
	int total_blocks = files[fileNum].numBlocks * files[fileNum].k;
    int numBits = (int)ceil(log2(total_blocks));


	
	recoverable_block_indicies *rb_indicies = (recoverable_block_indicies *)malloc(sizeof(recoverable_block_indicies) * files[fileNum].n);
	
	// calculate the code word number (the number of code words that blockNum is in)
	// so we know which code word to use (parity)


	int *out_tuple = malloc(sizeof(int) * files[fileNum].k);
	find_tuple_for_digit(files[fileNum].shuffel_key, code_word_id, out_tuple, files[fileNum].numBlocks *files[fileNum].k, files[fileNum].k);	


	int code_word_number = out_tuple[0];
	for (int l = 1; l < files[fileNum].k; l++) {
		if (out_tuple[l] < code_word_number) {
			code_word_number = out_tuple[l];
		}
	}
	
	for (int i = 0; i < files[fileNum].k; i++) {
		
		
		if (code_word_id ==  out_tuple[i]) {
			rb_indicies[i].is_corrupted = 1;
			erasures[0] = i;
		} else {
			rb_indicies[i].is_corrupted = 0;
		}

		rb_indicies[i].total_blocks_index = out_tuple[i];
		

		// the temp is the internal block index
		rb_indicies[i].node_index = (out_tuple[i] / files[fileNum].numBlocks);

		rb_indicies[i].internal_block_index = out_tuple[i] - (rb_indicies[i].node_index * files[fileNum].numBlocks);
		rb_indicies[i].code_word_number = code_word_number;

		if (rb_indicies[i].node_index == files[fileNum].current_chunk_id) {

			rb_indicies[i].is_local = 1;
		} else {
			rb_indicies[i].is_local = 0;
		}
		// ================================ neg start time ================================
		// ocall_test_time(neg_start_time);
		// ocall_printf("*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=", strlen("*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*="), 0);
		// ocall_printf("the rquested block is:", strlen("the rquested block is:"), 0);
		// ocall_printint(&blockNum);
		// ocall_printf("the I is:", strlen("the I is:"), 0);
		// ocall_printint(&i);
		// ocall_printf("the tmp_index is:", strlen("the tmp_index is:"), 0);
		// ocall_printint(&out_tuple[i]);
		// ocall_printf("**********", strlen("**********"), 0);
		// ocall_printf("the node index is:", strlen("the node index is:"), 0);
		// ocall_printint(&rb_indicies[i].node_index);
		// ocall_printf("the current chunk id is:", strlen("the current chunk id is:"), 0);
		// ocall_printint(&files[fileNum].current_chunk_id);
		// ocall_printf("the internal block index is:", strlen("the internal block index is:"), 0);
		// ocall_printint(&rb_indicies[i].internal_block_index);
		// ocall_printf("the code word number is:", strlen("the code word number is:"), 0);
		// ocall_printint(&rb_indicies[i].code_word_number);
		// ================================ neg end time ================================
		// ocall_test_time(neg_end_time);
		// total_neg_time += *neg_end_time - *neg_start_time;
	}


	
	ocall_printf("*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=", strlen("*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*="), 0);

	int total_parity_blocks = files[fileNum].numBlocks * (files[fileNum].n - files[fileNum].k);

	int numBitsParity = (int)ceil(log2(total_parity_blocks));

	for (int i = files[fileNum].k; i < files[fileNum].n; i++)
	{

		int requested_block = code_word_number + (i - files[fileNum].k) * files[fileNum].numBlocks;

		int tmp_index = feistel_network_prp(files[fileNum].shuffel_key, requested_block, numBitsParity);
		while (tmp_index >= total_parity_blocks) {
			tmp_index = feistel_network_prp(files[fileNum].shuffel_key, tmp_index, numBitsParity);
		}

		rb_indicies[i].is_local = 0;
		
		rb_indicies[i].is_corrupted = 0;


		rb_indicies[i].total_blocks_index = tmp_index;
		int temp_internal_block_index = tmp_index % files[fileNum].numBlocks;
		rb_indicies[i].internal_block_index = temp_internal_block_index;
		rb_indicies[i].node_index = (tmp_index - temp_internal_block_index) / files[fileNum].numBlocks + files[fileNum].k;
		rb_indicies[i].code_word_number = code_word_number;	
	// ocall_printf("*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=", 42, 0);
	// ocall_printf("*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=", 42, 0);
	// ocall_printf("*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=", 42, 0);
	// ocall_printf("this is the i:", 14, 0);
	// ocall_printint(&i);
	// ocall_printf("the requested block is:", 23, 0);
	// ocall_printint(&requested_block);
	// ocall_printf("the total blocks index is:", 26, 0);
	// ocall_printint(&rb_indicies[i].total_blocks_index);
	// ocall_printf("the internal block index is:", 28, 0);
	// ocall_printint(&rb_indicies[i].internal_block_index);
	// ocall_printf("the node index is:", 18, 0);
	// ocall_printint(&rb_indicies[i].node_index);
	// ocall_printf("the code word number is:", 24, 0);
	// ocall_printint(&rb_indicies[i].code_word_number);
	// ocall_printf("*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=", 42, 0);
	// ocall_printf("*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=", 42, 0);
	// ocall_printf("*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=", 42, 0);
	}



	// block number is calculated
	// now we have 
	// 1- the code word number
	// 2- the blocks number belongs to the code word

	// int internal_block_index = blockNumInFile % files[fileNum].numBlocks;
	// int node_index = (blockNumInFile - internal_block_index) / files[fileNum].numBlocks;

	int cw_size = n* BLOCK_SIZE;
	int cw_count = n;

	// int *status = ;
    uint8_t *status = malloc(sizeof(uint8_t));
	// retrive local data
	// this fucntion should be decoupled from the ecall and become local function
	// uint8_t *code_word_tmp = malloc(files[fileNum].n * sizeof(uint8_t) * BLOCK_SIZE);
	char *code_word_tmp = malloc(files[fileNum].n * sizeof(char) * BLOCK_SIZE);
	// first we collect the local blocks
	int counter_outside_data = 0;
	for (int i = 0; i < files[fileNum].k; i++) {
		uint8_t *tmpcode_word = (uint8_t *)malloc(BLOCK_SIZE);
		

		if (rb_indicies[i].is_local == 1) {

			// ================================ neg start time ================================
			ocall_test_time(neg_start_time);
			if (*toggle == 1) {
				ocall_init_parity(numBits);
				*toggle = 0;
			}
			ocall_printf("###########################Local Block DETECTED###############################", 78, 0);
			ocall_printf("the real block index is:", 24, 0);
			ocall_printint(&rb_indicies[i].total_blocks_index);

			check_block(fileNum, rb_indicies[i].internal_block_index, status, tmpcode_word);
			// ================================ neg end time ================================
			ocall_test_time(neg_end_time);
			*total_neg_time += *neg_end_time - *neg_start_time;

			if (*status == 0) {
				ocall_printf("THE BLOCK IS VALID", 18, 0);
				// if the block is not corrupted, we can directly assign the code word
				for (int j = 0; j < BLOCK_SIZE; j++) {
					code_word[rb_indicies[i].node_index * BLOCK_SIZE + j] = tmpcode_word[j];
					code_word_tmp[i * BLOCK_SIZE + j] = tmpcode_word[j];
				}
			}else{
			
				ocall_printf("local block is corrupted", 15, 0);
			}
	
		}else{
			code_word_index[i] = 1;
			counter_outside_data++;
		}

		free(tmpcode_word);
	}

	ocall_printf("=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-NODE INDEX=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=", 60, 0);


		// ================================ neg start time ================================
		ocall_test_time(neg_start_time);

	
		// if (counter_outside_data > 0) {
		sgx_status_t ocall_ret = ocall_get_batch_blocks(fileNum, rb_indicies, sizeof(recoverable_block_indicies), files[fileNum].n, signatures, code_word, code_word_index, nodes, cw_size, cw_count, sizeof(NodeInfo));
		printEnclaveError(ocall_ret);
		// }

		// ================================ neg end time ================================
		ocall_test_time(neg_end_time);
		*total_neg_time += *neg_end_time - *neg_start_time;


	for (int i = 0; i < files[fileNum].n; i++) {
	// ================================ verify signatures ================================
		if (rb_indicies[i].is_local) { ocall_printf("Local Signature", 15, 0); continue;}
		uint8_t signature2[32] = {0};
		ocall_printf("Generating signature", 20, 0);
		size_t data_len2 = 32;

		uint8_t *tmp_for_signature = malloc(32);
		memcpy(tmp_for_signature, signatures + (i * 32), 32);

		hmac_sha2(files[fileNum].sig_Key, 32, code_word + (i * BLOCK_SIZE), BLOCK_SIZE, signature2, &data_len2);

		// ================================ neg start time ================================
		ocall_test_time(neg_start_time);

		ocall_printf("signature2", 10, 0);
		ocall_printf(signature2, 32, 1);
		ocall_printf("tmp_for_signature", 18, 0);
		ocall_printf(tmp_for_signature, 32, 1);

		if (memcmp(tmp_for_signature, signature2, 32) == 0) {
			ocall_printf("Signature match", 15, 0);
			ocall_printint(&i);
		} else {
			ocall_printf("Signature mismatch", 18, 0);
			ocall_printint(&i);
		}
		// ================================ neg end time ================================
		ocall_test_time(neg_end_time);
		*total_neg_time += *neg_end_time - *neg_start_time;


	// ================================ decrypt code word ================================

		// get block

		if (code_word_index[i] == -1) {
			uint8_t *tmp_for_decrypt = malloc(BLOCK_SIZE);
			memcpy(tmp_for_decrypt, code_word_tmp + (i * BLOCK_SIZE), BLOCK_SIZE);
			DecryptData(files[fileNum].PC_Key, tmp_for_decrypt, BLOCK_SIZE);
			memcpy(code_word_tmp + (i * BLOCK_SIZE), tmp_for_decrypt, BLOCK_SIZE);
			free(tmp_for_decrypt);
		}else{
			uint8_t *tmp_for_decrypt = malloc(BLOCK_SIZE);
			memcpy(tmp_for_decrypt, code_word+ (i * BLOCK_SIZE), BLOCK_SIZE);
			DecryptData(files[fileNum].PC_Key, tmp_for_decrypt, BLOCK_SIZE);
			memcpy(code_word_tmp + (i * BLOCK_SIZE), tmp_for_decrypt, BLOCK_SIZE);
			free(tmp_for_decrypt);
			// counter_index++;
		}
		
		

	}
	// ================================ neg start time ================================
	// ocall_test_time(neg_start_time);

	// ocall_printf("code_word_tmp 0 ", 23, 0);
	// ocall_printf(code_word_tmp, BLOCK_SIZE, 1);
	// ocall_printf("code_word_tmp 1 ", 23, 0);
	// ocall_printf(code_word_tmp + BLOCK_SIZE, BLOCK_SIZE, 1);
	// ocall_printf("code_word_tmp 2 ", 23, 0);
	// ocall_printf(code_word_tmp + 2 * BLOCK_SIZE, BLOCK_SIZE, 1);
	// ocall_printf("code_word_tmp 3 ", 23, 0);
	// ocall_printf(code_word_tmp + 3 * BLOCK_SIZE, BLOCK_SIZE, 1);
	// ocall_printf("code_word_tmp 4 ", 23, 0);
	// ocall_printf(code_word_tmp + 4 * BLOCK_SIZE, BLOCK_SIZE, 1);
	// ================================ neg end time ================================
	// ocall_test_time(neg_end_time);
	// *total_neg_time += *neg_end_time - *neg_start_time;

	// ocall_printint(&erasures[0]);
	// ocall_printint(&erasures[1]);
	// ocall_printint(&erasures[2]);
	// ocall_printint(&erasures[3]);
	// ocall_printint(&erasures[4]);
    // int *matrix = (int *)malloc(sizeof(int) * m * k);

	// decode(BLOCK_SIZE, code_word_index, recovered_block, code_word, matrix, files[fileNum].current_chunk_id, recovered_block);
	// decode(BLOCK_SIZE, erasures, code_word_tmp, matrix, files[fileNum].current_chunk_id);
	// decode(int chunk_size, int *erasures, uint16_t *code_word, int *matrix, int current_chunk_id, uint16_t *recovered_data) {

	// ================================ neg start time ================================
	ocall_test_time(neg_start_time);
	ocall_printf("=======================THIS ALL data IN a code word========================", strlen("=======================THIS ALL data IN a code word========================"), 0);
	ocall_printf(code_word_tmp, k *BLOCK_SIZE, 1);
	// ================================ neg end time ================================
	ocall_test_time(neg_end_time);
	*total_neg_time += *neg_end_time - *neg_start_time;
	
	// store the recovered block
	memcpy(blockData, code_word_tmp, k * BLOCK_SIZE);



	free(code_word_tmp);
	free(code_word_index);
	free(rb_indicies);
	free(signatures);
	free(code_word);
	free(status);
	// free(toggle);

	// total neg time
	ocall_printf("==================================================", strlen("=================================================="), 0);
	ocall_printf("Total neg time", strlen("Total neg time"), 0);
	ocall_printdouble(total_neg_time);
	ocall_log_double("=", *total_neg_time);
	ocall_log_double("Total neg time in local code words: - %f", *total_neg_time);
	ocall_log_double("=", *total_neg_time);
	
	ocall_printf("==================================================", strlen("=================================================="), 0);

	free(neg_start_time);
	free(neg_end_time);
	free(total_neg_time);

	return;
}


// TODO: fileNum should be removed to file name or unique identifier
void ecall_local_code_words(int fileNum, int code_word_id, uint8_t *data, int cw_size, uint8_t *signature, int sig_count) {

	double *start_time = malloc(sizeof(double));
	double *end_time = malloc(sizeof(double));


	int *toggle = malloc(sizeof(int));
	*toggle = 0;
	// ================================ start time ================================
	ocall_test_time(start_time);
	ocall_log_double("=", 0);

	local_code_words(fileNum, code_word_id, data, toggle);

	uint8_t *tmp_for_encrypt = malloc(files[fileNum].k * BLOCK_SIZE);
	memcpy(tmp_for_encrypt, data, files[fileNum].k * BLOCK_SIZE);
	EncryptData(files[fileNum].PC_Key, tmp_for_encrypt, files[fileNum].k * BLOCK_SIZE);
	memcpy(data, tmp_for_encrypt, files[fileNum].k * BLOCK_SIZE);
	free(tmp_for_encrypt);

	uint8_t *signature_tmp = malloc(files[fileNum].k * 32);
	size_t data_len2 = 32;
	hmac_sha2(files[fileNum].sig_Key, 32, data, files[fileNum].k * BLOCK_SIZE, signature_tmp, &data_len2);
	memcpy(signature, signature_tmp, files[fileNum].k * 32);
	free(signature_tmp);
	// ================================ end time ================================
	ocall_test_time(end_time);
	double total_time = *end_time - *start_time;
	ocall_printf("===============================================", strlen("==============================================="), 0);
	ocall_printf("Total time For local code words (in external request):", strlen("Total time For local code words (in external request):"), 0);
	ocall_printdouble(&total_time);
	ocall_log_double("=", 0);
	ocall_log_double("Total time For local code words (in external request): %f", total_time);
	ocall_log_double("=", 0);
	ocall_printf("===============================================", strlen("==============================================="), 0);

	free(start_time);
	free(end_time);
	// free(toggle);
	return;
}

void ecall_retrieve_File(const char *fileName) {

	double *start_time = malloc(sizeof(double));
	double *end_time = malloc(sizeof(double));
	double *neg_start_time = malloc(sizeof(double));
	double *neg_end_time = malloc(sizeof(double));
	double *neg_code_word_start_time = malloc(sizeof(double));
	double *neg_code_word_end_time = malloc(sizeof(double));
	double *total_neg_time = malloc(sizeof(double));
	double section_time_1;
	double section_time_2;



	// ================================ start time ================================
	ocall_test_time(start_time);


	int *toggle = malloc(sizeof(int));
	*toggle = 0;

	int fileNum;
	for(fileNum = 0; fileNum < MAX_FILES; fileNum++) {
		if(strcmp(fileName, files[fileNum].fileName) == 0) {
			break;
		}
	}

	// cache the reperirve info to avoid multiple retrieval requests
	int k_cached = files[fileNum].k;
	int n_cached = files[fileNum].n;
	int numBlocks_cached = files[fileNum].numBlocks;

    int numBits = (int)ceil(log2(numBlocks_cached * k_cached));

	uint8_t *data = (uint8_t *)malloc(numBlocks_cached * BLOCK_SIZE * sizeof(uint8_t) * k_cached);

	int num_code_words = numBlocks_cached;
	int num_retrieval_rq_per_peer = num_code_words / NUM_NODES;
	// int num_retrieval_rq_per_peer = num_code_words / k_cached;

	int remainder = num_code_words % NUM_NODES;
	// int remainder = num_code_words % k_cached;
		
	int nodes_count = NUM_NODES;
	NodeInfo *nodes = (NodeInfo *)malloc(sizeof(NodeInfo) * NUM_NODES);

	int data_tmp_count = numBlocks_cached *  k_cached;
	int data_tmp_size = BLOCK_SIZE;
	uint8_t *data_tmp = (uint8_t *)malloc( sizeof(uint8_t) * BLOCK_SIZE * data_tmp_count);
	uint8_t *signiture_tmp = (uint8_t *)malloc( sizeof(uint8_t) * 32 * data_tmp_count);

	uint8_t *print_local_data_tmp = (uint8_t *)malloc(BLOCK_SIZE * sizeof(uint8_t) * k_cached * num_retrieval_rq_per_peer);


	int num_code_words_counter = 0;

	// -------------------------------- start time for bench marking SECTION CODEWORD -------------------------------- 
	double *section_time_codeword = malloc(sizeof(double));
	ocall_test_time(section_time_codeword);

	for(int i = 0; i < NUM_NODES; i++) {

		// -------------------------------- request code words from local SSD -------------------------------- 
		if (i == 0) {
			// -------------------------------- get the counter for sleep time of the local SSD (LPC) -------------------------------- 
			int sleep_counter1;
			int sleep_counter2;
			ocall_get_counter(&sleep_counter1);
			double codeword_time_start;
			double codeword_time_end;
			ocall_test_time(&codeword_time_start);
			for(int j = 0; j < num_retrieval_rq_per_peer; j++) {
				
				uint8_t *local_data_tmp = (uint8_t *)malloc(BLOCK_SIZE * sizeof(uint8_t) * k_cached);
				local_code_words(fileNum, j, local_data_tmp, toggle);

				memcpy(print_local_data_tmp + (j * BLOCK_SIZE * k_cached), local_data_tmp, k_cached * BLOCK_SIZE);
				
				free(local_data_tmp);
				num_code_words_counter++;
			}
			ocall_test_time(&codeword_time_end);
			double codeword_time = codeword_time_end - codeword_time_start;
			ocall_log_double("=", 0);
			ocall_log_double("codeword time: %f", codeword_time);
			ocall_log_double("=", 0);
			ocall_get_counter(&sleep_counter2);
			ocall_log_double("-**==**-**==**-**==**-**==**-**==**-**==**-**==**-**==**", 0);
			ocall_log_double("Sleep time: - %f", (double)(sleep_counter2 - sleep_counter1) * 0.1);
			ocall_log_double("-**==**-**==**-**==**-**==**-**==**-**==**-**==**-**==**", 0);
			continue;
		}


		// -------------------------------- copy the node info for request other peers -------------------------------- 
		for (int j = 0; j < 16; j++) nodes[i].ip[j] = files[fileNum].nodes[i].ip[j];
		nodes[i].chunk_id = files[fileNum].nodes[i].chunk_id;
		nodes[i].port = files[fileNum].nodes[i].port;
		nodes[i].is_parity_peer = files[fileNum].nodes[i].is_parity_peer;
		nodes[i].socket_fd = files[fileNum].nodes[i].socket_fd;
	
	}
	

	// -------------------------------- End time for bench marking SECTION 1 -------------------------------- 
	double *end_section_1 = malloc(sizeof(double));
	ocall_test_time(end_section_1);

	// -------------------------------- request code words from other peers -------------------------------- 
	ocall_retrieve_code_words(fileNum, nodes, sizeof(NodeInfo), nodes_count, signiture_tmp, data_tmp, data_tmp_size, data_tmp_count, num_retrieval_rq_per_peer, num_code_words_counter, num_code_words, remainder);

	// -------------------------------- start time for bench marking SECTION 2 -------------------------------- 
	double *start_section_2 = malloc(sizeof(double));
	ocall_test_time(start_section_2);

	// -------------------------------- decrypt the code words -------------------------------- 
	for (int i = num_retrieval_rq_per_peer; i < num_code_words; i++) {

		uint8_t new_signiture [32 * k_cached];

		size_t data_len2 = 32 * k_cached;

		uint8_t tmp_for_signature [32 * k_cached];
		memcpy(tmp_for_signature, signiture_tmp + (i * 32 * k_cached), k_cached * 32);

		hmac_sha2(files[fileNum].sig_Key, 32, data_tmp + (i * BLOCK_SIZE * k_cached), BLOCK_SIZE * k_cached, new_signiture, &data_len2);

		// ================================ neg start time ================================
		ocall_test_time(neg_start_time);

		ocall_printf("signature2", 10, 0);
		ocall_printf(new_signiture, 32 * k_cached, 1);
		ocall_printf("tmp_for_signature", 18, 0);
		ocall_printf(tmp_for_signature, 32 * k_cached, 1);

		if (memcmp(tmp_for_signature, new_signiture, 32 * k_cached) == 0) {
			ocall_printf("Signature match", 15, 0);
			ocall_printint(&i);
		} else {
			ocall_printf("Signature mismatch", 18, 0);
			ocall_printint(&i);
		}


		uint8_t *tmp_decrypted_data = malloc(BLOCK_SIZE * sizeof(uint8_t) * k_cached);
		memcpy(tmp_decrypted_data, data_tmp + (i * BLOCK_SIZE * k_cached), k_cached * BLOCK_SIZE);
		DecryptData(files[fileNum].PC_Key, tmp_decrypted_data, k_cached * BLOCK_SIZE);
		memcpy(data_tmp + (i * BLOCK_SIZE * k_cached), tmp_decrypted_data, k_cached * BLOCK_SIZE);
		free(tmp_decrypted_data);

	}

	// -------------------------------- wiret the recovered data in the correct place  -------------------------------- 
	for (int i = 0; i < numBlocks_cached; i++) {
		
		int *out_tuple = malloc(sizeof(int) * files[fileNum].k);
		find_tuple_for_digit(files[fileNum].shuffel_key, i, out_tuple, files[fileNum].numBlocks *files[fileNum].k, files[fileNum].k);

		for (int l = 0; l < files[fileNum].k; l++) {

			if (i < num_retrieval_rq_per_peer ) {
				for (int j = 0; j < BLOCK_SIZE; j++) {
					data[out_tuple[l] * BLOCK_SIZE + j] = print_local_data_tmp[((i * files[fileNum].k)+l) * BLOCK_SIZE + j];
				}
			}else{
				for (int j = 0; j < BLOCK_SIZE; j++) {
					data[out_tuple[l] * BLOCK_SIZE + j] = data_tmp[((i * files[fileNum].k)+l) * BLOCK_SIZE + j];
				}
			}
			
		}
	}
	
	// -------------------------------- wiret the recovered data to the file  -------------------------------- 
	ocall_write_recovered_file(data, numBlocks_cached * BLOCK_SIZE * k_cached);


	if (*toggle == 1) {
		ocall_init_parity(numBits);
		ocall_printf("Recovered file", 15, 0);


	}

	// -------------------------------- end time for bench marking -------------------------------- 
	ocall_test_time(end_time);

	// -------------------------------- log info -------------------------------- 
	double total_time = ((*end_time - *start_section_2) + (*end_section_1 - *start_time));
	ocall_printf("===============================================", strlen("==============================================="), 0);
	ocall_printf("Total time For retrieve Entire file", strlen("Total time For retrieve Entire file"), 0);
	ocall_printdouble(&total_time);
	ocall_log_double("=", 0);
	ocall_log_double("Total time For retrieve Entire file before: %f", (*end_time - *start_section_2));
	ocall_log_double("Total time For retrieve Entire file after: %f", (*end_section_1 - *start_time));
	ocall_log_double("codeword time: %f", (*end_section_1 - *section_time_codeword));

	ocall_log_double("=", 0);
	ocall_printf("===============================================", strlen("==============================================="), 0);


	// -------------------------------- free memory -------------------------------- 
	free(start_time);
	free(end_time);
	free(neg_start_time);
	free(neg_end_time);
	free(total_neg_time);
	free(neg_code_word_start_time);
	free(neg_code_word_end_time);


	return;
}



void get_plain_data(int fileNum, int numBlocks_cached, uint8_t *data) {

	data = (uint8_t *)malloc(numBlocks_cached * BLOCK_SIZE * sizeof(uint8_t));

	for (int i = 0; i < numBlocks_cached; i++) {
		uint8_t *tmpBlock = (uint8_t *)malloc(BLOCK_SIZE);
		int *status;

		check_block(fileNum, i, status, tmpBlock);
		if (*status == 0) {
			ocall_printf("THE BLOCK IS VALID", 18, 0);
			// if the block is not corrupted, we can directly assign the code word
			for (int j = 0; j < BLOCK_SIZE; j++) {
				data[i * BLOCK_SIZE + j] = tmpBlock[j];
			}
		}else{
			ocall_printf("local block is corrupted", 15, 0);
		}
	
	}

}

void ecall_get_plain_data(int fileNum, int numBlocks_cached, uint8_t *data, uint8_t *signiture_tmp) {

	uint8_t *data_tmp;
	uint8_t *tmp_decrypted_data = malloc(BLOCK_SIZE * sizeof(uint8_t) * numBlocks_cached);


	get_plain_data(fileNum, numBlocks_cached, data_tmp);


	memcpy(tmp_decrypted_data, data_tmp, numBlocks_cached * BLOCK_SIZE);
	EncryptData(files[fileNum].PC_Key, tmp_decrypted_data, numBlocks_cached * BLOCK_SIZE);
	memcpy(data, tmp_decrypted_data, numBlocks_cached * BLOCK_SIZE);

	uint8_t new_signiture [32];
	size_t len = 32;
	hmac_sha2(files[fileNum].sig_Key, 32, tmp_decrypted_data, BLOCK_SIZE * numBlocks_cached, new_signiture, &len);


	memcpy(signiture_tmp, new_signiture, 32);

	free(data_tmp);
	free(tmp_decrypted_data);
}

void ecall_retrieve_plain_File(const char *fileName) {

	double *start_time = malloc(sizeof(double));
	double *end_time = malloc(sizeof(double));
	double *neg_start_time = malloc(sizeof(double));
	double *neg_end_time = malloc(sizeof(double));
	double *neg_code_word_start_time = malloc(sizeof(double));
	double *neg_code_word_end_time = malloc(sizeof(double));
	double *total_neg_time = malloc(sizeof(double));
	double section_time_1;
	double section_time_2;



	// ================================ start time ================================
	ocall_test_time(start_time);


	int *toggle = malloc(sizeof(int));
	*toggle = 0;

	int fileNum;
	for(fileNum = 0; fileNum < MAX_FILES; fileNum++) {
		if(strcmp(fileName, files[fileNum].fileName) == 0) {
			break;
		}
	}

	// cache the reperirve info to avoid multiple retrieval requests
	int k_cached = files[fileNum].k;
	int n_cached = files[fileNum].n;
	int numBlocks_cached = files[fileNum].numBlocks;

	uint8_t *data = (uint8_t *)malloc(numBlocks_cached * BLOCK_SIZE * sizeof(uint8_t) * k_cached);
	
	for (int i = 0; i < k_cached; i++) {
		NodeInfo *node = (NodeInfo *)malloc(sizeof(NodeInfo));
		uint8_t *data_tmp;
		uint8_t *tmp_decrypted_data = malloc(BLOCK_SIZE * sizeof(uint8_t) * numBlocks_cached);
		uint8_t *signiture_tmp = (uint8_t *)malloc( sizeof(uint8_t) * 32);

		
		if (i == 0) {
			get_plain_data(fileNum, numBlocks_cached, data_tmp);
		}else{
			for (int j = 0; j < 16; j++) node->ip[j] = files[fileNum].nodes[i].ip[j];
			node->chunk_id = files[fileNum].nodes[i].chunk_id;
			node->port = files[fileNum].nodes[i].port;
			node->is_parity_peer = files[fileNum].nodes[i].is_parity_peer;
			node->socket_fd = files[fileNum].nodes[i].socket_fd;
			ocall_get_plain_data(fileNum, numBlocks_cached, data_tmp, signiture_tmp, node, sizeof(NodeInfo));


			uint8_t new_signiture [32];
			size_t len = 32;
			uint8_t tmp_for_signature [32];
			memcpy(tmp_for_signature, signiture_tmp + (i * 32), 32);

			hmac_sha2(files[fileNum].sig_Key, 32, data_tmp + (i * BLOCK_SIZE * numBlocks_cached), BLOCK_SIZE * numBlocks_cached, new_signiture, &len);


			memcpy(tmp_decrypted_data, data_tmp + (i * BLOCK_SIZE * numBlocks_cached), numBlocks_cached * BLOCK_SIZE);
			DecryptData(files[fileNum].PC_Key, tmp_decrypted_data, numBlocks_cached * BLOCK_SIZE);
			memcpy(data_tmp + (i * BLOCK_SIZE * numBlocks_cached), tmp_decrypted_data, numBlocks_cached * BLOCK_SIZE);
		}

		memcpy(data + (i * numBlocks_cached * BLOCK_SIZE), data_tmp, numBlocks_cached * BLOCK_SIZE);
		free(data_tmp);
		free(node);
		free(tmp_decrypted_data);
	}

	ocall_write_recovered_file(data, numBlocks_cached * BLOCK_SIZE * k_cached);


	// -------------------------------- end time for bench marking -------------------------------- 
	ocall_test_time(end_time);

	// -------------------------------- log info -------------------------------- 
	// double total_time = ((*end_time - *start_section_2) + (*end_section_1 - *start_time));
	ocall_printf("===============================================", strlen("==============================================="), 0);
	ocall_printf("Total time For retrieve Entire file", strlen("Total time For retrieve Entire file"), 0);
	// ocall_printdouble(&total_time);
	ocall_log_double("=", 0);
	// ocall_log_double("Total time For retrieve Entire file before: %f", (*end_time - *start_section_2));
	// ocall_log_double("Total time For retrieve Entire file after: %f", (*end_section_1 - *start_time));
	// ocall_log_double("codeword time: %f", (*end_section_1 - *section_time_codeword));

	ocall_log_double("=", 0);
	ocall_printf("===============================================", strlen("==============================================="), 0);


	// -------------------------------- free memory -------------------------------- 
	free(start_time);
	free(end_time);
	free(neg_start_time);
	free(neg_end_time);
	free(total_neg_time);
	free(neg_code_word_start_time);
	free(neg_code_word_end_time);


	return;
}
