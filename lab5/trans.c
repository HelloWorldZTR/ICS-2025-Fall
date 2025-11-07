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
    int t0, t1, t2, t3, t4, t5, t6, t7;

    if (M == 32 && N == 32) {
        // block size 8
        for (i = 0; i < N; i += 8) {
            for (j = 0; j < M; j += 8) {
                // block from A[i][j] to A[i+15][j+15]
                for (x = i; x < i + 8 && x < N; x++) {
                    for (y = j; y < j + 8 && y < M; y++) {
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
    } else if (M == 64 && N == 64) {
        // block size 8 + 4 x 4 row optimize
        for (i = 0; i < N; i += 8) {
            for (j = 0; j < M; j += 8) {

                for (x = i; x < i + 4; x++) {
                    t0 = A[x][j + 0];
                    t1 = A[x][j + 1];
                    t2 = A[x][j + 2];
                    t3 = A[x][j + 3];
                    t4 = A[x][j + 4];
                    t5 = A[x][j + 5];
                    t6 = A[x][j + 6];
                    t7 = A[x][j + 7];

                    B[j + 0][x] = t0;
                    B[j + 1][x] = t1;
                    B[j + 2][x] = t2;
                    B[j + 3][x] = t3;
                    B[j + 0][x + 4] = t4;
                    B[j + 1][x + 4] = t5;
                    B[j + 2][x + 4] = t6;
                    B[j + 3][x + 4] = t7;
                }
                // Do it row-wise to minimize cache miss
                for (y = j + 4; y < j + 8; y++) {
                    t0 = B[y - 4][i + 4];
                    t1 = B[y - 4][i + 5];
                    t2 = B[y - 4][i + 6];
                    t3 = B[y - 4][i + 7];

                    t4 = A[i + 4][y - 4];
                    t5 = A[i + 5][y - 4];
                    t6 = A[i + 6][y - 4];
                    t7 = A[i + 7][y - 4];

                    B[y - 4][i + 4] = t4;
                    B[y - 4][i + 5] = t5;
                    B[y - 4][i + 6] = t6;
                    B[y - 4][i + 7] = t7;

                    B[y][i + 0] = t0;
                    B[y][i + 1] = t1;
                    B[y][i + 2] = t2;
                    B[y][i + 3] = t3;
                }

                for (x = i + 4; x < i + 8; x++) {
                    t0 = A[x][j + 4];
                    t1 = A[x][j + 5];
                    t2 = A[x][j + 6];
                    t3 = A[x][j + 7];

                    B[j + 4][x] = t0;
                    B[j + 5][x] = t1;
                    B[j + 6][x] = t2;
                    B[j + 7][x] = t3;
                }
            }
        }
    } else {
        // block size 8
        for (i = 0; i < N; i += 8) {
            for (j = 0; j < M; j += 8) {
                // block from A[i][j] to A[i+15][j+15]
                for (x = i; x < i + 8 && x < N; x++) {
                    for (y = j; y < j + 8 && y < M; y++) {
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



char transpose_block_8b_desc[] = "Transpose with block size 4x2";
void transpose_block_8b(int M, int N, int A[N][M], int B[M][N])
{
    REQUIRES(M > 0);
    REQUIRES(N > 0);
    //1kb = 32b * 32sets
    int i;
    int j;
    // int x;
    // int y;
    int blockSize = 4;
    for (i = 0; i < N / blockSize; i ++) {
        for (j = 0; j < M / blockSize; j ++) {
            int t00 = A[i*blockSize + 0][j*blockSize + 0];
            int t01 = A[i*blockSize + 0][j*blockSize + 1];
            int t02 = A[i*blockSize + 0][j*blockSize + 2];
            int t03 = A[i*blockSize + 0][j*blockSize + 3];
            int t10 = A[i*blockSize + 1][j*blockSize + 0];
            int t11 = A[i*blockSize + 1][j*blockSize + 1];
            int t12 = A[i*blockSize + 1][j*blockSize + 2];
            int t13 = A[i*blockSize + 1][j*blockSize + 3];

            B[j*blockSize + 0][i*blockSize + 0] = t00;
            B[j*blockSize + 0][i*blockSize + 1] = t10;
            B[j*blockSize + 1][i*blockSize + 0] = t01;
            B[j*blockSize + 1][i*blockSize + 1] = t11;
            B[j*blockSize + 2][i*blockSize + 0] = t02;
            B[j*blockSize + 2][i*blockSize + 1] = t12;
            B[j*blockSize + 3][i*blockSize + 0] = t03;
            B[j*blockSize + 3][i*blockSize + 1] = t13;

            t00 = A[i*blockSize + 2][j*blockSize + 0];
            t01 = A[i*blockSize + 2][j*blockSize + 1];
            t02 = A[i*blockSize + 2][j*blockSize + 2];
            t03 = A[i*blockSize + 2][j*blockSize + 3];
            t10 = A[i*blockSize + 3][j*blockSize + 0];
            t11 = A[i*blockSize + 3][j*blockSize + 1];
            t12 = A[i*blockSize + 3][j*blockSize + 2];
            t13 = A[i*blockSize + 3][j*blockSize + 3];

            B[j*blockSize + 0][i*blockSize + 2] = t00;
            B[j*blockSize + 0][i*blockSize + 3] = t10;
            B[j*blockSize + 1][i*blockSize + 2] = t01;
            B[j*blockSize + 1][i*blockSize + 3] = t11;
            B[j*blockSize + 2][i*blockSize + 2] = t02;
            B[j*blockSize + 2][i*blockSize + 3] = t12;
            B[j*blockSize + 3][i*blockSize + 2] = t03;
            B[j*blockSize + 3][i*blockSize + 3] = t13;
        }
    }

    ENSURES(is_transpose(M, N, A, B));
}




char transpose_block_8c_desc[] = "Transpose with block size (8x4)";
void transpose_block_8c(int M, int N, int A[N][M], int B[M][N])
{
    REQUIRES(M > 0);
    REQUIRES(N > 0);
    //1kb = 32b * 32sets
    int i;
    int j;
    int x;
    int y;
    int t0, t1, t2, t3, t4, t5, t6, t7;
    for (i = 0; i < N; i += 8) {
        for (j = 0; j < M; j += 8) {

            for (x = i; x < i + 4; x++) {
                t0 = A[x][j + 0];
                t1 = A[x][j + 1];
                t2 = A[x][j + 2];
                t3 = A[x][j + 3];
                t4 = A[x][j + 4];
                t5 = A[x][j + 5];
                t6 = A[x][j + 6];
                t7 = A[x][j + 7];

                B[j + 0][x] = t0;
                B[j + 1][x] = t1;
                B[j + 2][x] = t2;
                B[j + 3][x] = t3;
                B[j + 0][x + 4] = t4;
                B[j + 1][x + 4] = t5;
                B[j + 2][x + 4] = t6;
                B[j + 3][x + 4] = t7;
            }
            // Do it row-wise to minimize cache miss
            for (y = j + 4; y < j + 8; y++) {
                t0 = B[y - 4][i + 4];
                t1 = B[y - 4][i + 5];
                t2 = B[y - 4][i + 6];
                t3 = B[y - 4][i + 7];

                t4 = A[i + 4][y - 4];
                t5 = A[i + 5][y - 4];
                t6 = A[i + 6][y - 4];
                t7 = A[i + 7][y - 4];

                B[y - 4][i + 4] = t4;
                B[y - 4][i + 5] = t5;
                B[y - 4][i + 6] = t6;
                B[y - 4][i + 7] = t7;

                B[y][i + 0] = t0;
                B[y][i + 1] = t1;
                B[y][i + 2] = t2;
                B[y][i + 3] = t3;
            }

            for (x = i + 4; x < i + 8; x++) {
                t0 = A[x][j + 4];
                t1 = A[x][j + 5];
                t2 = A[x][j + 6];
                t3 = A[x][j + 7];

                B[j + 4][x] = t0;
                B[j + 5][x] = t1;
                B[j + 6][x] = t2;
                B[j + 7][x] = t3;
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
    // registerTransFunction(transpose_block_8c, transpose_block_8c_desc);
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

