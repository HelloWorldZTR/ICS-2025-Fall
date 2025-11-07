#include <stdio.h>

int main() {
    int i, j, x, y;
    int N = 16, M = 16;
    int B[16][16];
    int A[16][16];
    for (i = 0; i< 16; i++) {
        for (j = 0; j < 16; j++) {
            A[i][j] = i*16 + j;
        }
    }
    for (i = 0; i < N / 8; i ++) {
        for (j = 0; j < M / 8; j ++) {
            // copy block from A to B
            for (x = 0; x < 8; x++) {
                for (y = 0; y < 8; y++) {
                    B[j*8 + y][i*8 + x] = A[i*8 + x][j*8 + y];
                }
            }
            // for (x = 0; x < 8; x++) {
            //     for (y = 0; y < 8; y++) {
            //         int t = B[j*8 + x][i*8 + y];
            //         B[j*8 + x][i*8 + y] = B[j*8 + y][i*8 + x];
            //         B[j*8 + y][i*8 + x] = t;
            //     }
            // }
        }
    }
    for(i = 0; i < 16; i++) {
        for (j = 0; j < 16; j++) {
            printf("%3d ", B[i][j]);
        }
        puts("");
    }
}