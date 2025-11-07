#include <stdio.h>

void transpose_block_8d(int M, int N, int A[N][M], int B[M][N])
{
    //1kb = 32b * 32sets
    int i;
    int j;
    int x;
    int y;
    int t0, t1, t2, t3, t4, t5, t6, t7;
    for (i = 0; i < 64; i += 8) {
        for (j = 0; j < 56; j += 8) {

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

                if (i + 8 < 68) {
                    t4 = A[i + 4][y - 4];
                    t5 = A[i + 5][y - 4];
                    t6 = A[i + 6][y - 4];
                    t7 = A[i + 7][y - 4];

                    B[y - 4][i + 4] = t4;
                    B[y - 4][i + 5] = t5;
                    B[y - 4][i + 6] = t6;
                    B[y - 4][i + 7] = t7;
                }

                B[y][i + 0] = t0;
                B[y][i + 1] = t1;
                B[y][i + 2] = t2;
                B[y][i + 3] = t3;
            }

            if (i + 8 < 68) {
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
    }
    // Handle the remaining rows and columns using 4 x 4 block transpose
    for (i = 0; i < 68; i += 4) {
        for (j = 0; j < 60; j += 4) {
            if (i < 64 && j < 56) {
                continue;
            }
            for (x = i; x < i + 4 && x < N; x++) {
                for (y = j; y < j + 4 && y < M; y++) {
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


int main() {
    int i, j, x, y;
    int N = 68, M = 60;
    int B[60][68];
    int A[68][60];
    for (i = 0; i< 68; i++) {
        for (j = 0; j < 60; j++) {
            A[i][j] = i*60 + j;
        }
    }
    transpose_block_8d(M, N, A, B);
    
    for(i = 0; i < 60; i++) {
        for (j = 0; j < 68; j++) {
            printf("%3d ", B[i][j]);
        }
        puts("");
    }
}