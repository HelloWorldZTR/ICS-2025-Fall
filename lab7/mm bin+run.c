/*
 * mm.c
 * 
 * This malloc implementation uses seperate policies for small and large objects.
 * for object smaller than 4kB, use bin + run to manage them, which will improve
 * latency.
 * bins contain objects of size [8, 16, 24 ..., 4096]
 * for object larger than 4kB, use segregated free lists to manage them
 * chunks contain objects of size [4096, 8192, 12288, ...] where each chunk size doubles
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "mm.h"
#include "memlib.h"

/* If you want debugging output, use the following macro.  When you hand
 * in, remove the #define DEBUG line. */
#define DEBUG
#ifdef DEBUG
# define dbg_printf(...) printf(__VA_ARGS__)
#else
# define dbg_printf(...)
#endif

/* do not change the following! */
#ifdef DRIVER
/* create aliases for driver tests */
#define malloc mm_malloc
#define free mm_free
#define realloc mm_realloc
#define calloc mm_calloc
#endif /* def DRIVER */

/* Define constants */
/* single word (4) or double word (8) alignment */
#define ALIGNMENT 8
/* rounds up size to the nearest multiple of ALIGNMENT */
#define ALIGN_SIZE(size) (((size) + (ALIGNMENT-1)) & ~(ALIGNMENT-1))
/* rounds up pointer to the nearest multiple of ALIGNMENT */
#define ALIGN_PTR(p) ((void*)(((size_t)(p) + (ALIGNMENT-1)) & ~(ALIGNMENT-1)))
/* object below size threshold will be handled using bins*/
#define SIZE_THRESHOLD (1 << 12) 
#define BIN_CNT (SIZE_THRESHOLD / ALIGNMENT)
/* a run is the size of 1 page (4kB)*/
#define RUN_SIZE (1 << 12)
/* a page is 4kB */
#define PAGE_SIZE (1 << 12)

typedef size_t word_t;
typedef __uint8_t byte_t;
typedef __uint32_t uint32_t;
typedef __uint64_t uint64_t;
typedef int bool;
#define true 1
#define false 0

/* Helper struct and functions */

#define TSMALL 1
#define TLARGE 2
#define TEMPTY 0

typedef uint32_t page_type_t;

typedef struct page_types_t {
    uint32_t block_size;
    page_type_t type;
} page_types_t;

typedef struct l3_pagetable_t {
    page_types_t types[512]; // is this small or large object?
} l3_pagetable_t;

typedef struct l2_pagetable_t {
    l3_pagetable_t* pages[512];
} l2_pagetable_t;

typedef struct l1_pagetable_t {
    l2_pagetable_t* pages[512];
} l1_pagetable_t;

l1_pagetable_t* l1_pagetable = NULL;

/*
Get the page type from a pointer
ptr = l1_pagetable + offset
offset in [0, 2^32-1]
VPN = offset >> 12

4+8+8 = 20 bits
l3_index = VPN & 0xFF
l2_index = VPN >> 8 & 0xFF
l1_index = VPN >> 16 & 0xF
*/
static inline page_types_t getPtrType(void* ptr) {
    size_t offset = (size_t)((char*)ptr - (char*)mem_heap_lo());
    size_t VPN = offset >> 12;
    size_t l3_index = VPN & 0x1FF;  // 9 bits: 0-511
    size_t l2_index = (VPN >> 9) & 0x1FF;  // 9 bits: 0-511
    size_t l1_index = (VPN >> 18) & 0x1FF;  // 9 bits: 0-511
    if (l1_pagetable->pages[l1_index] == NULL || 
        l1_pagetable->pages[l1_index]->pages[l2_index] == NULL) {
        page_types_t empty = {0, TEMPTY};
        return empty;
    }
    return l1_pagetable->pages[l1_index]->pages[l2_index]->types[l3_index];
}


/* 
Allocate a page of memory and mark what its for 
*/
static void* allocate_page(uint32_t page_type, uint32_t block_size) {
    void* ptr = mem_sbrk(PAGE_SIZE);
    if (ptr == (void*)(-1)) {
        return NULL; // unable to allocate memory
    }
    memset(ptr, 0, PAGE_SIZE);
    size_t offset = (size_t)((char*)ptr - (char*)mem_heap_lo());
    size_t VPN = offset >> 12;
    size_t l3_index = VPN & 0x1FF;  // 9 bits: 0-511
    size_t l2_index = (VPN >> 9) & 0x1FF;  // 9 bits: 0-511
    size_t l1_index = (VPN >> 18) & 0x1FF;  // 9 bits: 0-511
    
    // Allocate l2_pagetable if needed
    if (l1_pagetable->pages[l1_index] == NULL) {
        l2_pagetable_t* l2_pagetable = (l2_pagetable_t*)mem_sbrk(PAGE_SIZE);
        if (l2_pagetable == (l2_pagetable_t*)(-1)) {
            return NULL; // unable to allocate memory
        }
        memset(l2_pagetable, 0, PAGE_SIZE);
        l1_pagetable->pages[l1_index] = l2_pagetable;
    }
    l2_pagetable_t* l2_pagetable = l1_pagetable->pages[l1_index];
    
    // Allocate l3_pagetable if needed
    if (l2_pagetable->pages[l2_index] == NULL) {
        l3_pagetable_t* l3_pagetable = (l3_pagetable_t*)mem_sbrk(PAGE_SIZE);
        if (l3_pagetable == (l3_pagetable_t*)(-1)) {
            return NULL; // unable to allocate memory
        }
        memset(l3_pagetable, 0, PAGE_SIZE);
        l2_pagetable->pages[l2_index] = l3_pagetable;
    }
    l3_pagetable_t* l3_pagetable = l2_pagetable->pages[l2_index];
    
    l3_pagetable->types[l3_index].type = page_type;
    l3_pagetable->types[l3_index].block_size = block_size;
    return ptr;
}

/* Run manages a list of slots, which contains blocks of a certain size*/
typedef struct run_t {
    struct run_t *next;
    uint32_t slots_cnt;
    uint32_t slots_used;
    size_t block_size;
    byte_t* bitmap;
    void* slots;
} run_t;

/* 
A bin contains blocks of a certain size,
and manage them using runs.
*/
typedef struct bin_t {
    size_t block_size;
    struct run_t *runs;
} bin_t;

static bin_t* bins; 

/* Helper functions for runs */
/* Check if a run is empty */
static inline bool isRunEmpty(run_t* run) {
    for (uint32_t i = 0; i < run->slots_cnt; i += 8) {
        byte_t tmp = run->bitmap[i >> 3];
        if (tmp != 0)
            return false;
    }
    return true;
}
/* Check if a slot is empty */
static inline bool isSlotEmpty(run_t* run, size_t nth) {
    byte_t tmp = run->bitmap[nth >> 3];
    return (tmp & (1 << (nth & 7))) == 0;
}
/* Change a slot to be used or free */
static inline void modifySlot(run_t* run, size_t nth, size_t value) {
    if (value) // set n-th slot to be used
        run->bitmap[nth >> 3] |= (1 << (nth & 7));
    else // set n-th slot to be free
        run->bitmap[nth >> 3] &= ~(1 << (nth & 7));
}

/* Get the pointer to the n-th slot */
static inline void* getSlotPtr(run_t* run, size_t nth, size_t block_size) {
    return (void*)((byte_t*)run->slots + nth * block_size);
}

/* Get the run_t pointer from object pointer */
static inline run_t* getRunFromPtr(void* ptr) {
    return (run_t*)((size_t)ptr & ~(RUN_SIZE - 1));
}


/* Initialize a run */
static void initializeRun(run_t* run, size_t block_size) {
    // Calculate bitmap size: need 1 bit per slot, rounded up to bytes
    uint32_t max_slots = RUN_SIZE / block_size;
    uint32_t bitmapSize = (max_slots + 7) / 8;  // Round up to bytes
    bitmapSize = ALIGN_SIZE(bitmapSize);  // Align bitmap size to 8 bytes

    // Place bitmap right after run_t structure, aligned
    run->bitmap = ALIGN_PTR((byte_t*)run + sizeof(run_t));
    memset(run->bitmap, 0, bitmapSize); // initialize bitmap
    
    // Place slots after bitmap, aligned to 8 bytes
    run->slots = ALIGN_PTR((byte_t*)run->bitmap + bitmapSize);
    
    // Calculate how many slots fit in remaining space
    size_t slots_start = (size_t)run->slots - (size_t)run;
    run->slots_cnt = (RUN_SIZE - slots_start) / block_size;
    run->slots_used = 0;
    run->block_size = block_size;
}

static run_t* freed_runs_head = NULL; // head of the linked list of freed runs

/* Add a run to the linked list of freed runs */
static void addRunToFreedList(run_t* run) {
    run->next = freed_runs_head;
    freed_runs_head = run;
}

/* Remove a run from the head of the linked list of freed runs */
static run_t* removeRunFromFreedList() {
    if (freed_runs_head == NULL)
        return NULL;
    run_t* run = freed_runs_head;
    freed_runs_head = run->next;
    return run;
}

/* Remove a run from a bin's run list */
static void removeRunFromBin(bin_t* bin, run_t* run) {
    if (bin->runs == run) {
        // Run is at the head
        bin->runs = run->next;
    } else {
        // Find the run in the list
        run_t* curr = bin->runs;
        while (curr != NULL && curr->next != run) {
            curr = curr->next;
        }
        if (curr != NULL) {
            curr->next = run->next;
        }
    }
    run->next = NULL;  // Clear the next pointer
}

/* Place an object in a bin */
static void* placeInBin(bin_t* bin) {
    run_t* curr_run = bin->runs;
    // search for a free slot in existing runs
    while (curr_run != NULL) {
        for (size_t i = 0; i < curr_run->slots_cnt; i++) {
            if (isSlotEmpty(curr_run, i)) {
                // found a free slot
                modifySlot(curr_run, i, 1); // mark as used
                curr_run->slots_used++;
                return getSlotPtr(curr_run, i, bin->block_size);
            }
        }
        curr_run = curr_run->next;
    }
    // no free slot found, need to allocate a new page for run
    run_t* run = removeRunFromFreedList();
    if (run == NULL) {
        void* run_mem = allocate_page(TSMALL, bin->block_size);
        if (run_mem == NULL)  
            return NULL;
        run = (run_t*)run_mem;
    }
    initializeRun(run, bin->block_size);
    // insert new run at the beginning of the bin's run list
    run->next = bin->runs;
    bin->runs = run;
    // allocate the first slot in the new run
    modifySlot(run, 0, 1); // mark as used
    run->slots_used++;
    return run->slots;
}
/* End helper functions for runs */

static inline size_t roundToPage(size_t size) {
    return (size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
}

/*
 * Initialize: return -1 on error, 0 on success.
 */
int mm_init(void) {
    // step -1. reset the heap
    mem_reset_brk();
    // step 0. initialize page tables
    l1_pagetable = mem_sbrk(PAGE_SIZE);
    if (l1_pagetable == (l1_pagetable_t*)(-1)) {
        return -1; // unable to allocate memory
    }
    memset(l1_pagetable, 0, PAGE_SIZE);

    // step 1. initialize bins
    // allocate array bin_t bins[BIN_CNT] 
    size_t bin_size = BIN_CNT * sizeof(bin_t);
    // Round up bin_size to page boundary for alignment
    size_t required_size = roundToPage(bin_size);

    void* ptr = mem_sbrk(required_size);
    if (ptr == (void *)-1)
        return -1; // unable to allocate memory
    bins = (bin_t*)ptr;

    // initialize each bin
    for (size_t i = 0; i < BIN_CNT; i++) {
        // each bin handles blocks of size (i + 1) * ALIGNMENT
        bins[i].block_size = (i + 1) * ALIGNMENT;
        bins[i].runs = NULL;
    }

    // step 2. initialize segregated free lists for large blocks

    // step 3. unset freed_runs_head
    freed_runs_head = NULL;
    return 0;
}

/*
 * malloc
 */
void *malloc (size_t size) {
    if (size <= 0)
        return NULL;
    // Round up size to 8-byte alignment
    size_t aligned_size = ALIGN_SIZE(size);
    
    // if is small object, handle using bins
    if (aligned_size < SIZE_THRESHOLD) {
        // bin_index = (aligned_size / ALIGNMENT) - 1
        // bin 0 handles size 8, bin 1 handles size 16, etc.
        size_t bin_index = (aligned_size / ALIGNMENT) - 1;
        if (bin_index >= BIN_CNT) {
            // Shouldn't happen if SIZE_THRESHOLD is correct, but safety check
            bin_index = BIN_CNT - 1;
        }
        return placeInBin(&bins[bin_index]);
    }
    // if is big object, handle using segregated free lists
    else {
        // TODO: place in segregated free lists
        return NULL;
    }
}

/*
 * free
 */
void free (void *ptr) {
    if(!ptr) return;
    page_types_t t = getPtrType(ptr);
    if (t.type == TSMALL) {
        run_t* run = getRunFromPtr(ptr);
        size_t block_size = run->block_size;
        size_t nth = ((byte_t*)ptr - (byte_t*)run->slots) / block_size;
        modifySlot(run, nth, 0);
        run->slots_used--;
        // if all slots are free, remove from bin and add to freed list
        if (run->slots_used == 0) {
            // Find which bin this run belongs to
            size_t bin_index = (block_size / ALIGNMENT) - 1;
            if (bin_index < BIN_CNT) {
                removeRunFromBin(&bins[bin_index], run);
            }
            addRunToFreedList(run);
        }
    }
    else {
        // TODO: free from segregated free lists
    }
}

/*
 * realloc - you may want to look at mm-naive.c
 */
void *realloc(void *oldptr, size_t size) {
    return NULL;
}

/*
 * calloc - you may want to look at mm-naive.c
 * This function is not tested by mdriver, but it is
 * needed to run the traces.
 */
void *calloc (size_t nmemb, size_t size) {
    void* ptr = malloc(nmemb * size);
    if (ptr == NULL)
        return NULL;
    memset(ptr, 0, nmemb * size);
    return ptr;
}


/*
 * Return whether the pointer is in the heap.
 * May be useful for debugging.
 */
static int in_heap(const void *p) {
    return p <= mem_heap_hi() && p >= mem_heap_lo();
}

/*
 * Return whether the pointer is aligned.
 * May be useful for debugging.
 */
static int aligned(const void *p) {
    return (size_t)ALIGN_PTR(p) == (size_t)p;
}

/*
 * mm_checkheap
 */
void mm_checkheap(int lineno) {
}
