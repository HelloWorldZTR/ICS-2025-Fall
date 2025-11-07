/*
 * trans.c - Matrix transpose B = A^T
 *
 * Each transpose function must have a prototype of the form:
 * void trans(int M, int N, int A[N][M], int B[M][N]);
 *
 * A transpose function is evaluated by counting the number of misses
 * on a 1KB direct mapped cache with a block size of 32 bytes.
 */
#include <stdio.h>
#include "cachelab.h"
#include "contracts.h"

int is_transpose(int M, int N, int A[N][M], int B[M][N]);
void swap(int* a, int* b);

/*
 * transpose_submit - This is the solution transpose function that you
 *     will be graded on for Part B of the assignment. Do not change
 *     the description string "Transpose submission", as the driver
 *     searches for that string to identify the transpose function to
 *     be graded. The REQUIRES and ENSURES from 15-122 are included
 *     for your convenience. They can be removed if you like.
 */
char transpose_submit_desc[] = "Transpose submission";
void transpose_submit(int M, int N, int A[N][M], int B[M][N])
{
    REQUIRES(M > 0);
    REQUIRES(N > 0);
    //1kb = 32b * 32sets
    int i;
    int j;
    int x;
    int y;

    int blockSize = 16;

    if (M == 32 && N == 32) {
        blockSize = 8;
    } else if (M == 64 && N == 64) {
        blockSize = 4;
    } else {
        blockSize = 8;
    }

    for (i = 0; i < N; i += blockSize) {
        for (j = 0; j < M; j += blockSize) {
            // block from A[i][j] to A[i+15][j+15]
            for (x = i; x < i + blockSize && x < N; x++) {
                for (y = j; y < j + blockSize && y < M; y++) {
                    if (x != y) {
                        B[y][x] = A[x][y];
                    }
                }
                if (i == j) {
                    B[x][x] = A[x][x];
                }
            }
        }
    }

    ENSURES(is_transpose(M, N, A, B));
}

char transpose_block_4_desc[] = "Transpose with block size 4";
void transpose_block_4(int M, int N, int A[N][M], int B[M][N])
{
    REQUIRES(M > 0);
    REQUIRES(N > 0);
    //1kb = 32b * 32sets
    int i;
    int j;
    int x;
    int y;
    int blockSize = 4;
    for (i = 0; i < N; i += blockSize) {
        for (j = 0; j < M; j += blockSize) {
            // block from A[i][j] to A[i+3][j+3]
            for (x = i; x < i + blockSize && x < N; x++) {
                for (y = j; y < j + blockSize && y < M; y++) {
                    if (x != y) {
                        B[y][x] = A[x][y];
                    }
                }
                if (i == j) {
                    B[x][x] = A[x][x];
                }
            }
        }
    }

    ENSURES(is_transpose(M, N, A, B));
}

char transpose_block_8_desc[] = "Transpose with block size 8";
void transpose_block_8(int M, int N, int A[N][M], int B[M][N])
{
    REQUIRES(M > 0);
    REQUIRES(N > 0);
    //1kb = 32b * 32sets
    int i;
    int j;
    int x;
    int y;
    int blockSize = 8;
    for (i = 0; i < N; i += blockSize) {
        for (j = 0; j < M; j += blockSize) {
            // block from A[i][j] to A[i+15][j+15]
            for (x = i; x < i + blockSize && x < N; x++) {
                for (y = j; y < j + blockSize && y < M; y++) {
                    if (x != y) {
                        B[y][x] = A[x][y];
                    }
                }
                if (i == j) {
                    B[x][x] = A[x][x];
                }
            }
        }
    }

    ENSURES(is_transpose(M, N, A, B));
}

char transpose_block_8b_desc[] = "Transpose with block size 8 (desync)";
void transpose_block_8b(int M, int N, int A[N][M], int B[M][N])
{
    REQUIRES(M > 0);
    REQUIRES(N > 0);
    //1kb = 32b * 32sets
    int i;
    int j;
    int x;
    int y;
    int blockSize = 4;
    for (i = 0; i < N; i += blockSize) {
        for (j = 0; j < M; j += blockSize) {
            if (i != j) {
                for (x = i; x < i + blockSize && x < N; x++) {
                    for (y = j; y < j + blockSize && y < M; y++) {
                            B[y][x] = A[x][y];
                    }
                }
            } else { // diagonal block
                for (x = i; x < i + blockSize && x < N; x++) {
                    for (y = j; y < j + blockSize && y < M; y++) {
                        if (x != y) {
                            B[y][x] = A[x][y];
                        }
                    }
                    B[x][x] = A[x][x];
                }
            }
        }
    }

    ENSURES(is_transpose(M, N, A, B));
}

char transpose_block_16_desc[] = "Transpose with block size 16";
void transpose_block_16(int M, int N, int A[N][M], int B[M][N])
{
    REQUIRES(M > 0);
    REQUIRES(N > 0);
    //1kb = 32b * 32sets
    int i;
    int j;
    int x;
    int y;
    int blockSize = 16;
    for (i = 0; i < N; i += blockSize) {
        for (j = 0; j < M; j += blockSize) {
            // block from A[i][j] to A[i+15][j+15]
            for (x = i; x < i + blockSize && x < N; x++) {
                for (y = j; y < j + blockSize && y < M; y++) {
                    if (x != y) {
                        B[y][x] = A[x][y];
                    }
                }
                if (i == j) {
                    B[x][x] = A[x][x];
                }
            }
        }
    }

    ENSURES(is_transpose(M, N, A, B));
}

/*
 * You can define additional transpose functions below. We've defined
 * a simple one below to help you get started.
 */

 /*
  * trans - A simple baseline transpose function, not optimized for the cache.
  */
char trans_desc[] = "Simple row-wise scan transpose";
void trans(int M, int N, int A[N][M], int B[M][N])
{
    int i, j, tmp;

    REQUIRES(M > 0);
    REQUIRES(N > 0);

    for (i = 0; i < N; i++) {
        for (j = 0; j < M; j++) {
            tmp = A[i][j];
            B[j][i] = tmp;
        }
    }

    ENSURES(is_transpose(M, N, A, B));
}

/*
 * registerFunctions - This function registers your transpose
 *     functions with the driver.  At runtime, the driver will
 *     evaluate each of the registered functions and summarize their
 *     performance. This is a handy way to experiment with different
 *     transpose strategies.
 */
void registerFunctions()
{
    /* Register your solution function */
    registerTransFunction(transpose_submit, transpose_submit_desc);

    /* Register any additional transpose functions */
    // registerTransFunction(trans, trans_desc);
    // registerTransFunction(transpose_block_4, transpose_block_4_desc);
    // registerTransFunction(transpose_block_8, transpose_block_8_desc);
    // registerTransFunction(transpose_block_16, transpose_block_16_desc);
    // registerTransFunction(transpose_block_8b, transpose_block_8b_desc);
}

/*
 * is_transpose - This helper function checks if B is the transpose of
 *     A. You can check the correctness of your transpose by calling
 *     it before returning from the transpose function.
 */
int is_transpose(int M, int N, int A[N][M], int B[M][N])
{
    int i, j;

    for (i = 0; i < N; i++) {
        for (j = 0; j < M; ++j) {
            if (A[i][j] != B[j][i]) {
                return 0;
            }
        }
    }
    return 1;
}

/*
 * swap - Swap the values of two integers.
*/
void swap(int *a, int *b) {
    int temp = *a;
    *a = *b;
    *b = temp;
}

