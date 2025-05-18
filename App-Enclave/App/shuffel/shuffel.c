// Amir M M Farid

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <stdint.h>
#include "prp.h"


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