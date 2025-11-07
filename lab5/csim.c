/**
 * 张庭瑞 2400017786
 * csim.c - Cache Simulator
 * Command line parameters:
 * -s <s> : number of set index bits
 * -E <E> : number of lines per set
 * -b <b> : number of block offset bits
 * -t <tracefile> : name of the valgrind trace to replay
 * -v : optional verbose flag
 * -h : optional help flag
 * Usage: ./csim-ref [-hv] -s <s> -E <E> -b <b> -t <tracefile>
 */
#include <getopt.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include "cachelab.h"

typedef int bool;
typedef unsigned long addr_t;

#define verbose_log(arg, ...) \
    do { \
        if (arg.flag_v) { \
            printf(__VA_ARGS__); \
        } \
    } while (0)

#define true 1
#define false 0
#define MAX_FILE_LEN 100

typedef struct _args
{
    bool flag_h;
    bool flag_v;
    int s;
    int E;
    int b;
    char tracefile[MAX_FILE_LEN];
} Args;

typedef struct _line
{
    int valid;
    int tag;
    int lu_time;
} Line;

typedef struct _set
{
    Line* lines;
} Set;


typedef struct _cache
{
    int S, s;
    int E;
    int B, b;
    Set* sets;
} Cache;

/**
 * Initialize memory structure for cache
 */
Cache* initalizeCache(int s, int E, int b) {
    Cache* cache = (Cache*) malloc (sizeof(Cache));
    cache->s = s;
    cache->E = E;
    cache->b = b;
    cache->S = 1 << s;
    cache->B = 1 << b;
    cache->sets = (Set*) malloc (cache->S * sizeof(Set));
    for (int i = 0; i < cache->S; i++) {
        cache->sets[i].lines = (Line*) malloc (E * sizeof(Line));
        for (int j = 0; j < E; j++) {
            cache->sets[i].lines[j].valid = 0;
            cache->sets[i].lines[j].tag = -1;
            cache->sets[i].lines[j].lu_time = 0;
        }
    }
    return cache;
}

/**
 * Free cache
 */
void freeCache(Cache* cache) {
    for (int i = 0; i < cache->S; i++) {
        free(cache->sets[i].lines);
    }
    free(cache->sets);
    free(cache);
}

/**
 * Read command line parameters
 */
Args parseArgs(int argc, char* argv[]) {
    Args arg;
    int opt;
    // Set default value for -h and -v
    arg.flag_h = false;
    arg.flag_v = false;
    while ((opt = getopt(argc, argv, "s:E:b:t:hv")) != -1) {
        switch (opt)
        {
        case 's':
            arg.s = atoi(optarg);
            break;
        case 'E':
            arg.E = atoi(optarg);
            break;
        case 'b':
            arg.b = atoi(optarg);
            break;
        case 't':
            strncpy(arg.tracefile, optarg, MAX_FILE_LEN);
            break;
        case 'h':
            arg.flag_h = true;
            break;
        case 'v':
            arg.flag_v = true;
            break;
        case '?':
        default:
            printf("Usage: ./csim-ref [-hv] -s <s> -E <E> -b <b> -t <tracefile>\n");
            break;
        }
    }
    return arg;
}

int main(int argc, char *argv[]) {
    // == parse args ==
    Args arg = parseArgs(argc, argv);
    FILE *trace_fp = fopen(arg.tracefile, "r");
    if (trace_fp == NULL) {
        printf("Error opening trace file: %s\n", arg.tracefile);
        return 1;
    }
    // == simulation stuff ==
    Cache* cache = initalizeCache(arg.s, arg.E, arg.b);
    char line_buf[100];
    char op;
    addr_t addr;
    int size;
    // == counters
    int miss_cnt = 0;
    int hit_cnt = 0;
    int evict_cnt = 0;
    int cyc = 0;
    // == params sketch pad ==
    int b = arg.b;          // block offset bits
    int s = arg.s;          // set bits
    int S = 1 << s;
    int E = arg.E;
    int s_mask = (1 << s) - 1;
    Set* set_p;
    Line* line_p;
    
    while (fgets(line_buf, sizeof(line_buf), trace_fp) != NULL) {
        if (line_buf[0] == 'I') continue; // no instruction cache

        sscanf(line_buf+1, "%c %lx,%d", &op, &addr, &size);
        verbose_log(arg, "%c %lx,%d", op, addr, size);

        int tag = addr >> (s + b);
        int set_idx = (addr >> b) & s_mask;
        set_idx = set_idx % S;
        set_p = &cache->sets[set_idx];

        bool hit = false;
        for (int i = 0; i < E; i++) {
            line_p = &set_p->lines[i];
            if (line_p->valid && line_p->tag == tag) {
                hit = true;
                hit_cnt++;
                line_p->lu_time = cyc;
            }
        }
        verbose_log(arg, "%s", hit ? " hit" : " miss");
        if (!hit) {
            miss_cnt ++;
            // look for empty line
            bool placed = false;
            for (int i = 0; i < E; i++) {
                line_p = &set_p->lines[i];
                if (!line_p->valid) {
                    placed = true;
                    line_p->valid = 1;
                    line_p->tag = tag;
                    line_p->lu_time = cyc;
                    break;
                }
            }
            if (!placed) {
                // need to evict
                evict_cnt++;
                verbose_log(arg, " eviction");
                int lru_idx = 0;
                int lru = INT_MAX;
                for (int i = 0; i < E; i++) {
                    line_p = &set_p->lines[i];
                    if (line_p->lu_time < lru) {
                        lru = line_p->lu_time;
                        lru_idx = i;
                    }
                }
                line_p = &set_p->lines[lru_idx];
                line_p->tag = tag;
                line_p->lu_time = cyc;
                line_p->valid = 1; // does nothing
            }
        }
        if (op == 'M') {
            // M is a load followed by a store, so always a hit at the end
            hit_cnt++;
            verbose_log(arg, " hit");
        }
        verbose_log(arg, "\n");
        cyc++;
    }
    printSummary(hit_cnt, miss_cnt, evict_cnt);
    // == clean up ==
    fclose(trace_fp);
    freeCache(cache); // It was against my will
    return 0;
}