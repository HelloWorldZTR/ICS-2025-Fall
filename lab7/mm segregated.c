/* 
 * Simple, 32-bit and 64-bit clean allocator based on implicit free
 * lists, first-fit placement, and boundary tag coalescing, as described
 * in the CS:APP3e text. Blocks must be aligned to doubleword (8 byte) 
 * boundaries. Minimum block size is 16 bytes. 
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "mm.h"
#include "memlib.h"


// #define DEBUG
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

/* Basic constants and macros */
#define WSIZE       4       /* Word and header/footer size (bytes) */ 
#define DSIZE       8       /* Double word size (bytes) */
#define CHUNKSIZE  (1<<12)  /* Extend heap by this amount (bytes) */  

#define MAX(x, y) ((x) > (y)? (x) : (y))  

/* Pack a size and allocated bit into a word */
#define PACK(size, alloc)  ((size) | (alloc)) 

/* Read and write a word at address p */
#define GET(p)       (*(unsigned int *)(p))            
#define PUT(p, val)  (*(unsigned int *)(p) = (val))    

/* Read the size and allocated fields from address p */
#define GET_SIZE(p)  (GET(p) & ~0x7)                   
#define GET_ALLOC(p) (GET(p) & 0x1)                    

/* Given block ptr bp, compute address of its header and footer */
#define HDRP(bp)       ((char *)(bp) - WSIZE)                      
#define FTRP(bp)       ((char *)(bp) + GET_SIZE(HDRP(bp)) - DSIZE) 

typedef struct payload_t
{
    char* prev_bp;
    char* next_bp;
    char payload[0];
} payload_t;

#define BLOCK_OVERHEAD sizeof(payload_t)
#define NEXT(bp)  (*(char **)(bp))
#define PREV(bp)  (*(char **)((char *)(bp) + sizeof(char*)))

/* Given block ptr bp, compute address of next and previous blocks */
#define NEXT_BLKP(bp)  ((char *)(bp) + GET_SIZE(((char *)(bp) - WSIZE))) 
#define PREV_BLKP(bp)  ((char *)(bp) - GET_SIZE(((char *)(bp) - DSIZE))) 

/* Global variables */
static char *heap_listp = 0;  /* Pointer to first block */  
#ifdef NEXT_FIT
static char *rover;           /* Next fit rover */
#endif

/* Function prototypes for internal helper routines */
static void *extend_heap(size_t words);
static void place(void *bp, size_t asize);
static void *find_fit(size_t asize);
static void *coalesce(void *bp);
static void add_block(void *bp, int lineno);
static void remove_block(void *bp, int lineno);


static const size_t size_classes[] = {
    8, 16, 24, 32, 48, 56, 72, 96, 128, 192, 256, 512,
    1024, (size_t)-1 // for objects larger than 1024, use the same bin
};
static const int NUM_CLASSES = sizeof(size_classes) / sizeof(size_classes[0]);

typedef struct free_bin_t {
    char* head;
    char* rover;
} free_bin_t;
free_bin_t* bins;

static int bin_index(size_t size){
    size = MAX(size, 8);
    for (int i = 0; i < NUM_CLASSES; i++) {
        if (size <= size_classes[i]) {
            return i;
        }
    }
    return NUM_CLASSES - 1;
};

/* 
 * mm_init - Initialize the memory manager 
 */
int mm_init(void) 
{
    /* reset free lists */
    size_t bins_size = sizeof(free_bin_t) * NUM_CLASSES;
    if ((bins = (free_bin_t*)mem_sbrk(bins_size)) == (void *)(-1))
        return -1;

    for (int i = 0; i < NUM_CLASSES; i++) {
        bins[i].head = NULL;
        bins[i].rover = NULL;
    }
    

    /* Create the initial empty heap */
    if ((heap_listp = mem_sbrk(4*WSIZE)) == (void *)-1) 
        return -1;
    PUT(heap_listp, 0);                          /* Alignment padding */
    PUT(heap_listp + (1*WSIZE), PACK(DSIZE, 1)); /* Prologue header */ 
    PUT(heap_listp + (2*WSIZE), PACK(DSIZE, 1)); /* Prologue footer */ 
    PUT(heap_listp + (3*WSIZE), PACK(0, 1));     /* Epilogue header */
    heap_listp += (2*WSIZE);                     

#ifdef NEXT_FIT
    rover = heap_listp;
#endif

    /* Extend the empty heap with a free block of CHUNKSIZE bytes */
    if (extend_heap(CHUNKSIZE/WSIZE) == NULL) 
        return -1;
    return 0;
}

/* 
 * malloc - Allocate a block with at least size bytes of payload 
 */
void *malloc(size_t size) 
{
    size_t asize;      /* Adjusted block size */
    size_t extendsize; /* Amount to extend heap if no fit */
    char *bp;      

    if (heap_listp == 0){
        mm_init();
    }
    /* Ignore spurious requests */
    if (size == 0)
        return NULL;

    /* Adjust block size to include overhead and alignment reqs. */
    if (size <= DSIZE)                                          
        asize = 2*DSIZE;                                        
    else
        asize = DSIZE * ((size + (DSIZE) + (DSIZE-1)) / DSIZE); 
    asize += BLOCK_OVERHEAD;

    /* Search the free list for a fit */
    if ((bp = find_fit(asize)) != NULL) {
        remove_block(bp, __LINE__);  
        place(bp, asize);

        dbg_printf("a %p (%zu b)\n", bp, asize);                  
        return (char*)bp + BLOCK_OVERHEAD;
    }

    /* No fit found. Get more memory and place the block */
    extendsize = MAX(asize,CHUNKSIZE);                 
    if ((bp = extend_heap(extendsize/WSIZE)) == NULL)  
        return NULL;
    remove_block(bp, __LINE__);                                  
    place(bp, asize); // if split occurs, the remainder block is added to free list               
    
    dbg_printf("a %p (%zu b)\n", bp, asize);

    return (char*)bp + BLOCK_OVERHEAD;
} 

/* 
 * free - Free a block 
 */
void free(void *bp)
{

    dbg_printf("f %p\n", bp);

    if (bp == 0) 
        return;

    /* convert back to text book style */
    bp = (char*)bp - BLOCK_OVERHEAD;

    size_t size = GET_SIZE(HDRP(bp));
    if (heap_listp == 0){
        mm_init();
    }

    PUT(HDRP(bp), PACK(size, 0));
    PUT(FTRP(bp), PACK(size, 0));
    coalesce(bp);
}

/*
 * realloc - Naive implementation of realloc
 */
void *realloc(void *ptr, size_t size)
{
    size_t oldsize;
    void *newptr;
    size_t asize;

    /* If size == 0 then this is just free, and we return NULL. */
    if(size == 0) {
        free(ptr);
        return 0;
    }

    /* If oldptr is NULL, then this is just malloc. */
    if(ptr == NULL) {
        return malloc(size);
    }

    char *old_bp = (char *)ptr - BLOCK_OVERHEAD;
    oldsize = GET_SIZE(HDRP(old_bp));

    /* Adjust block size to include overhead and alignment reqs. */
    if (size <= DSIZE)                                          
        asize = 2*DSIZE;                                        
    else
        asize = DSIZE * ((size + (DSIZE) + (DSIZE-1)) / DSIZE); 
    asize += BLOCK_OVERHEAD;

    if (oldsize >= asize) {
        return ptr;
    }

    /* Try to coalesce with next block if it is free */
    char *next_bp = NEXT_BLKP(old_bp);
    size_t next_alloc = GET_ALLOC(HDRP(next_bp));
    size_t next_size = GET_SIZE(HDRP(next_bp));

    if (!next_alloc && (oldsize + next_size >= asize)) {
        remove_block(next_bp, __LINE__);
        size_t new_size = oldsize + next_size;
        PUT(HDRP(old_bp), PACK(new_size, 1));
        PUT(FTRP(old_bp), PACK(new_size, 1));
        return ptr;
    }

    newptr = malloc(size);

    /* If realloc() fails the original block is left untouched  */
    if(!newptr) {
        return 0;
    }

    /* Copy the old data. */
    size_t copy_size = oldsize - DSIZE - BLOCK_OVERHEAD;
    if (size < copy_size) copy_size = size;
    memcpy(newptr, ptr, copy_size);

    /* Free the old block. */
    free(ptr);

    return newptr;
}

/* 
 * mm_checkheap - Check the heap for correctness. Helpful hint: You
 *                can call this function using mm_checkheap(__LINE__);
 *                to identify the line number of the call site.
 */
void mm_checkheap(int lineno)  
{ 
    lineno = lineno; /* keep gcc happy */
    if (1) {
        /* print free list info */
        for (int i = 0; i < NUM_CLASSES; i++) {
            char* bp = bins[i].head;

            if (bp == NULL) {
                continue;
            }

            dbg_printf("Bin %d: ", i);

            while (bp != NULL) {
                dbg_printf("%p (%zu) -> ", bp, GET_SIZE(HDRP(bp)));
                bp = NEXT(bp);
            }

            dbg_printf("NULL\n");
        }
    }
}

/* 
 * The remaining routines are internal helper routines 
 */

/* 
 * extend_heap - Extend heap with free block and return its block pointer
 * add the new free block to free list
 */
static void *extend_heap(size_t words) 
{
    char *bp;
    size_t size;

    /* Allocate an even number of words to maintain alignment */
    size = (words % 2) ? (words+1) * WSIZE : words * WSIZE; 
    if ((long)(bp = mem_sbrk(size)) == -1)  
        return NULL;                                        

    /* Initialize free block header/footer and the epilogue header */
    PUT(HDRP(bp), PACK(size, 0));         /* Free block header */   
    PUT(FTRP(bp), PACK(size, 0));         /* Free block footer */   
    PUT(HDRP(NEXT_BLKP(bp)), PACK(0, 1)); /* New epilogue header */ 

    /* Coalesce if the previous block was free */
    return coalesce(bp);                                          
}

/*
 * coalesce - Boundary tag coalescing. Return ptr to coalesced block
 * add coalseced block to free list
 */
static void *coalesce(void *bp) 
{
    size_t prev_alloc = GET_ALLOC(FTRP(PREV_BLKP(bp)));
    size_t next_alloc = GET_ALLOC(HDRP(NEXT_BLKP(bp)));
    size_t size = GET_SIZE(HDRP(bp));

    if (prev_alloc && next_alloc) {            /* Case 1 */
        
        add_block(bp, __LINE__);

        return bp;
    }

    else if (prev_alloc && !next_alloc) {      /* Case 2 */
        remove_block(NEXT_BLKP(bp), __LINE__);

        size += GET_SIZE(HDRP(NEXT_BLKP(bp)));
        PUT(HDRP(bp), PACK(size, 0));
        PUT(FTRP(bp), PACK(size,0));

        add_block(bp, __LINE__);
    }

    else if (!prev_alloc && next_alloc) {      /* Case 3 */
        remove_block(PREV_BLKP(bp), __LINE__);

        size += GET_SIZE(HDRP(PREV_BLKP(bp)));
        PUT(FTRP(bp), PACK(size, 0));
        PUT(HDRP(PREV_BLKP(bp)), PACK(size, 0));

        bp = PREV_BLKP(bp);
        add_block(bp, __LINE__);
    }

    else {                                     /* Case 4 */
        remove_block(PREV_BLKP(bp), __LINE__);
        remove_block(NEXT_BLKP(bp), __LINE__);

        size += GET_SIZE(HDRP(PREV_BLKP(bp))) + 
            GET_SIZE(FTRP(NEXT_BLKP(bp)));
        PUT(HDRP(PREV_BLKP(bp)), PACK(size, 0));
        PUT(FTRP(NEXT_BLKP(bp)), PACK(size, 0));

        bp = PREV_BLKP(bp);
        add_block(bp, __LINE__);
    }
#ifdef NEXT_FIT
    /* Make sure the rover isn't pointing into the free block */
    /* that we just coalesced */
    if ((rover > (char *)bp) && (rover < NEXT_BLKP(bp))) 
        rover = bp;
#endif
    return bp;
}

/* 
 * place - Place block of asize bytes at start of free block bp 
 *         and split if remainder would be at least minimum block size
 *         and add the remainder to free list if split occurs
 */
static void place(void *bp, size_t asize)
{
    size_t csize = GET_SIZE(HDRP(bp));   

    if ((csize - asize) >= (2*DSIZE + BLOCK_OVERHEAD)) { 
        PUT(HDRP(bp), PACK(asize, 1));
        PUT(FTRP(bp), PACK(asize, 1));
        bp = NEXT_BLKP(bp);
        PUT(HDRP(bp), PACK(csize-asize, 0));
        PUT(FTRP(bp), PACK(csize-asize, 0));
        add_block(bp, __LINE__);
    }
    else { 
        PUT(HDRP(bp), PACK(csize, 1));
        PUT(FTRP(bp), PACK(csize, 1));
    }
}

/* 
 * find_fit - Find a fit for a block with asize bytes 
 */
static void *find_fit(size_t asize)
{
    /* First-fit search */
    void *bp;

#ifdef DEBUG
    mm_checkheap(__LINE__);
#endif

    int bin_idx = bin_index(asize);

    bp = bins[bin_idx].head;
    while (bp != NULL) {
        if (asize <= GET_SIZE(HDRP(bp))) {
            return bp;
        }
        bp = NEXT(bp);
    }

    /* No fit in this bin */
    for(bin_idx = bin_idx + 1; bin_idx < NUM_CLASSES; bin_idx++) {
        bp = bins[bin_idx].head;
        if(bp != NULL) {
            return bp;
        }
    }

    return NULL; /* No fit */
}

/*
add a block to free list 
*/
static void add_block(void *bp, int lineno)
{
#ifdef DEBUG
    dbg_printf("+ Blk %p to free list\n", bp);
    mm_checkheap(lineno);
    dbg_printf("\n");
#endif
    int bin_idx = bin_index(GET_SIZE(HDRP(bp)));

    NEXT(bp) = bins[bin_idx].head;
    PREV(bp) = NULL;

    if (bins[bin_idx].head != NULL)
    {
        PREV(bins[bin_idx].head) = bp;
    }
    bins[bin_idx].head = bp;
}

/*
remove a block from free list 
*/
static void remove_block(void *bp, int lineno)
{
#ifdef DEBUG
    dbg_printf("- Blk %p from free list\n", bp);
    mm_checkheap(lineno);
    dbg_printf("\n");
#endif
    int bin_idx = bin_index(GET_SIZE(HDRP(bp)));

    if (PREV(bp))
    {
        NEXT(PREV(bp)) = NEXT(bp);
    }
    else
    {
        /* is the first in free list */
        bins[bin_idx].head = NEXT(bp);
    }
    if (NEXT(bp))
    {
        PREV(NEXT(bp)) = PREV(bp);
    }
    NEXT(bp) = NULL;
    PREV(bp) = NULL;

    bins[bin_idx].rover = bins[bin_idx].head;
}