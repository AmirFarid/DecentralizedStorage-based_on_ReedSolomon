#include <stdint.h>
// #include <stdio.h>
// #include <stdlib.h>
#include <string.h>
// #include <gf_rand.h>
// #include "jerasure.h"
// #include "jerasure/reed_sol.h"
#include <math.h>
#include "galois.h"
#define BLOCK_SIZE 4096


// I may not use these 
#define PAGE_SIZE 2048
#define SEGMENT_SIZE 512
#define PAGE_PER_BLOCK (BLOCK_SIZE / PAGE_SIZE)
#define SEGMENT_PER_BLOCK (BLOCK_SIZE / SEGMENT_SIZE)
#define SEGMENT_PER_PAGE (PAGE_SIZE / SEGMENT_SIZE)

#define talloc(type, num) ((type *) malloc((num) * sizeof(type)))

static double total_memcpy_bytes = 0;
static double total_xor_bytes = 0;
static double total_gf_bytes = 0;
long fileSize;
int K;
int N;

static const int my_matrix[3][4] = {
    {1, 1, 1, 34820}, // N = 4 , k = 2
    {1, 1, 1, 1},
    {1, 1, 1, 1}
};


int *erasures_to_erased(int k, int m, int *erasures)
{

  int td;
  int t_non_erased;
  int *erased;
  int i;

  td = k+m;
  erased = talloc(int, td);
  if (erased == NULL) return NULL;
  t_non_erased = td;

  for (i = 0; i < td; i++) erased[i] = 0;

  for (i = 0; erasures[i] != -1; i++) {
    //   ocall_printint(&i);
    // ocall_printint(&erasures[i]);
    // If the drive is erased, set it to 1
    if (erased[erasures[i]] == 0) {
      erased[erasures[i]] = 1;
      t_non_erased--;
      // If there are less than k non-erased drives, return NULL
      if (t_non_erased < k) {
        free(erased);
        return NULL;
      }
    }
  }
  return erased;
}



int invert_matrix(int *mat, int *inv, int rows, int w)
{
  int cols, i, j, k, x, rs2;
  int row_start, tmp, inverse;
 
  cols = rows;

  k = 0;
  for (i = 0; i < rows; i++) {
    for (j = 0; j < cols; j++) {
      inv[k] = (i == j) ? 1 : 0;
      k++;
    }
  }

  /* First -- convert into upper triangular  */
  for (i = 0; i < cols; i++) {
    row_start = cols*i;

    /* Swap rows if we ave a zero i,i element.  If we can't swap, then the 
       matrix was not invertible  */

    if (mat[row_start+i] == 0) { 
      for (j = i+1; j < rows && mat[cols*j+i] == 0; j++) ;
      if (j == rows) return -1;
      rs2 = j*cols;
      for (k = 0; k < cols; k++) {
        tmp = mat[row_start+k];
        mat[row_start+k] = mat[rs2+k];
        mat[rs2+k] = tmp;
        tmp = inv[row_start+k];
        inv[row_start+k] = inv[rs2+k];
        inv[rs2+k] = tmp;
      }
    }
 
    /* Multiply the row by 1/element i,i  */
    tmp = mat[row_start+i];
    if (tmp != 1) {
      inverse = galois_single_divide(1, tmp, w);
      for (j = 0; j < cols; j++) { 
        mat[row_start+j] = galois_single_multiply(mat[row_start+j], inverse, w);
        inv[row_start+j] = galois_single_multiply(inv[row_start+j], inverse, w);
      }
    }

    /* Now for each j>i, add A_ji*Ai to Aj  */
    k = row_start+i;
    for (j = i+1; j != cols; j++) {
      k += cols;
      if (mat[k] != 0) {
        if (mat[k] == 1) {
          rs2 = cols*j;
          for (x = 0; x < cols; x++) {
            mat[rs2+x] ^= mat[row_start+x];
            inv[rs2+x] ^= inv[row_start+x];
          }
        } else {
          tmp = mat[k];
          rs2 = cols*j;
          for (x = 0; x < cols; x++) {
            mat[rs2+x] ^= galois_single_multiply(tmp, mat[row_start+x], w);
            inv[rs2+x] ^= galois_single_multiply(tmp, inv[row_start+x], w);
          }
        }
      }
    }
  }

  /* Now the matrix is upper triangular.  Start at the top and multiply down  */

  for (i = rows-1; i >= 0; i--) {
    row_start = i*cols;
    for (j = 0; j < i; j++) {
      rs2 = j*cols;
      if (mat[rs2+i] != 0) {
        tmp = mat[rs2+i];
        mat[rs2+i] = 0; 
        for (k = 0; k < cols; k++) {
          inv[rs2+k] ^= galois_single_multiply(tmp, inv[row_start+k], w);
        }
      }
    }
  }
  return 0;
}

int make_decoding_matrix(int k, int m, int w, int *matrix, int *erased, int *decoding_matrix, int *dm_ids)
{
  int i, j, *tmpmat;

  j = 0;
  for (i = 0; j < k; i++) {
    if (erased[i] == 0) {
      dm_ids[j] = i;
      j++;
    }
  }

  tmpmat = talloc(int, k*k);
  if (tmpmat == NULL) { return -1; }
  for (i = 0; i < k; i++) {
    if (dm_ids[i] < k) {
      for (j = 0; j < k; j++) tmpmat[i*k+j] = 0;
      tmpmat[i*k+dm_ids[i]] = 1;
    } else {
      for (j = 0; j < k; j++) {
        tmpmat[i*k+j] = matrix[(dm_ids[i]-k)*k+j];
      }
    }
  }

  i = invert_matrix(tmpmat, decoding_matrix, k, w);
  free(tmpmat);
  return i;
}



void matrix_dotprod(int k, int w, int *matrix_row, int *src_ids, int dest_id, char **data_ptrs, char **coding_ptrs, int size)
{
  int init;
  char *dptr, *sptr;
  int i;

  if (w != 1 && w != 8 && w != 16 && w != 32) {
    // fprintf(stderr, "ERROR: jerasure_matrix_dotprod() called and w is not 1, 8, 16 or 32\n");
    // assert(0);
  }



  init = 0;

  dptr = (dest_id < k) ? data_ptrs[dest_id] : coding_ptrs[dest_id-k];


  /* First copy or xor any data that does not need to be multiplied by a factor */

  for (i = 0; i < k; i++) {
    if (matrix_row[i] == 1) {
      if (src_ids == NULL) {
        sptr = data_ptrs[i];
      } else if (src_ids[i] < k) {
        sptr = data_ptrs[src_ids[i]];
      } else {
        sptr = coding_ptrs[src_ids[i]-k];
      }

      if (init == 0) {
        memcpy(dptr, sptr, size);
        total_memcpy_bytes += size;
        init = 1;
      } else {
        galois_region_xor(sptr, dptr, size);
        total_xor_bytes += size;
      }
    }
  }


  /* Now do the data that needs to be multiplied by a factor */

  for (i = 0; i < k; i++) {

    if (matrix_row[i] != 0 && matrix_row[i] != 1) {
      if (src_ids == NULL) {
        sptr = data_ptrs[i];
      } else if (src_ids[i] < k) {
        sptr = data_ptrs[src_ids[i]];
      } else {
        sptr = coding_ptrs[src_ids[i]-k];
      }
      switch (w) {
        case 8:  galois_w08_region_multiply(sptr, matrix_row[i], size, dptr, init); break;
        case 16: galois_w16_region_multiply(sptr, matrix_row[i], size, dptr, init); break;
        case 32: galois_w32_region_multiply(sptr, matrix_row[i], size, dptr, init); break;
      }
      total_gf_bytes += size;
      init = 1;
    }
  }
}

/**
 * @brief Decode the data using the coding matrix erasures
 * 
 * @param k the number of data chunks
 * @param m the number of coding chunks
 * @param w the size of the field
 * @param matrix the coding matrix
 * @param erasures the erasures
 * @param data_ptrs the data pointers
 * @param coding_ptrs the coding pointers
 * @param size the size of the symbol
 * @return int | 0 if success, -1 if failed
 */
int matrix_decode(int k, int m, int w, int *matrix, int *erasures, char **data_ptrs, char **coding_ptrs, int size) {
    int i, edd, lastdrive;
    int *tmpids;
    int *erased, *decoding_matrix, *dm_ids;
    int row_k_ones = 1;

    if (w != 8 && w != 16 && w != 32) return -1;


    erased = erasures_to_erased(k, m, erasures);
    if (erased == NULL) return -1;

    /* Find the number of data drives failed */

    lastdrive = k;

    edd = 0;
    for (i = 0; i < k; i++) {
      if (erased[i]) {
        edd++;
            lastdrive = i;
          }
        }
    if (!row_k_ones || erased[k]) lastdrive = k;

      dm_ids = NULL;
      decoding_matrix = NULL;

      if (edd > 1 || (edd > 0 && (!row_k_ones || erased[k]))) {
        dm_ids = talloc(int, k);
        if (dm_ids == NULL) {
          free(erased);
          return -1;
        }

        decoding_matrix = talloc(int, k*k);
        if (decoding_matrix == NULL) {
          free(erased);
          free(dm_ids);
          return -1;
        }

        if (make_decoding_matrix(k, m, w, matrix, erased, decoding_matrix, dm_ids) < 0) {
          free(erased);
          free(dm_ids);
          free(decoding_matrix);
          return -1;
        }
      }

      /* Decode the data drives.  
         If row_k_ones is true and coding device 0 is intact, then only decode edd-1 drives.
         This is done by stopping at lastdrive.
         We test whether edd > 0 so that we can exit the loop early if we're done.
       */

      for (i = 0; edd > 0 && i < lastdrive; i++) {
        if (erased[i]) {
          matrix_dotprod(k, w, decoding_matrix+(i*k), dm_ids, i, data_ptrs, coding_ptrs, size);
          edd--;
        }
      }


      /* Then if necessary, decode drive lastdrive */

      if (edd > 0) {
        tmpids = talloc(int, k);
        if (!tmpids) {
          free(erased);
          free(dm_ids);
          free(decoding_matrix);
          return -1;
        }
        for (i = 0; i < k; i++) {
          tmpids[i] = (i < lastdrive) ? i : i+1;
        }

        matrix_dotprod(k, w, matrix, tmpids, lastdrive, data_ptrs, coding_ptrs, size);
        free(tmpids);
      }

      /* Finally, re-encode any erased coding devices */

      for (i = 0; i < m; i++) {
        if (erased[k+i]) {
          matrix_dotprod(k, w, matrix+(i*k), NULL, i+k, data_ptrs, coding_ptrs, size);
        }
      }


      free(erased);
      if (dm_ids != NULL) free(dm_ids);
      if (decoding_matrix != NULL) free(decoding_matrix);


      return 0;
}







// void decode(int chunk_size, int *erasures, uint16_t *code_word, int *matrix, int current_chunk_id, uint16_t *recovered_data) {
void decode(int chunk_size, int *erasures, uint16_t *code_word, int *matrix, int current_chunk_id) {


    int m = N - K;
    // ocall_printint(K);
    int symSize = 16;

    matrix[0] = 1;
	  matrix[1] = 1;
	  matrix[2] = 1;
	  matrix[3] = 1;
	  matrix[4] = 24578;
	  matrix[5] = 40964;
	  matrix[6] = 1;
	  matrix[7] = 61477;
	  matrix[8] = 61476;



    ocall_printf("-------------------------- Decoding --------------------------", 62, 0);

    char **data_ptrs = (char **)malloc(sizeof(char *) * K);
    char **coding_ptrs = (char **)malloc(sizeof(char *) * (N-K));
    
    for (int i = 0; i < K; i++) {
        data_ptrs[i] = (char *)malloc(sizeof(uint16_t));
    }
    for (int i = 0; i < N-K; i++) {
        coding_ptrs[i] = (char *)malloc(sizeof(uint16_t));
    }


    // Process each symbol
    for (int s = 0; s < 2048; s++) {
        // Read available chunks
        for (int i = 0; i < N; i++) {

            int is_erased = 0;
            for (int j = 0; erasures[j] != -1; j++) {
                if (erasures[j] == i) {
                    is_erased = 1;
                    break;
                }
            }
            if (!is_erased) {


                if (i < K) {
                    *((uint16_t *)data_ptrs[i]) = code_word [ (i * 2048) + s];
                    // *((char *)data_ptrs[i]) = 1;

                } else {                  
                    *((uint16_t *)coding_ptrs[i-K]) = code_word [ i * 2048 + s];
                    // *((char *)coding_ptrs[i-K]) = 0;

                } 
            }
        }
        // Decode
        // int ret = jerasure_matrix_decode(K, N-K, symSize, matrix, 1, erasures, data_ptrs, coding_ptrs, sizeof(uint16_t));
        int ret = matrix_decode(K, N-K, symSize, matrix, erasures, data_ptrs, coding_ptrs, sizeof(uint16_t));

        if (ret == 0) {

            for (int i = 0; erasures[i] != -1; i++) {
                int idx = erasures[i];
                    // ocall_printint(&idx);
                if (idx < K) {
                    // ocall_printint(&data_ptrs[idx]);
                    // recovered_data[s] = *((uint16_t *)data_ptrs[idx]);
                    code_word[(i * 2048) + s] = *((uint16_t *)data_ptrs[idx]);
                } else {
                    // recovered_data[s] = *((uint16_t *)coding_ptrs[idx-K]);
                    code_word[(i * 2048) +s] = *((uint16_t *)coding_ptrs[idx-K]);
                }
            }

        } else {
	          ocall_printf("Decoding failed for symbol", 28, 0);
            ocall_printint(s);
        }
    }
    // ocall_printf("debug ECC 5", 12, 0);
    // Cleanup
    for (int i = 0; i < K; i++) {
        free(data_ptrs[i]);
    }
    for (int i = 0; i < N-K; i++) {
        free(coding_ptrs[i]);
    }
    free(data_ptrs);
    free(coding_ptrs);
    free(matrix);
}


void initiate_rs(int k, int n){
    N = n;
    K = k;
    
}

