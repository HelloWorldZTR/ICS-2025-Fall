/*
 * mm.c
 *
 * struct for block:
 * - header 8B    (packed size and allocated bit)
 * - prev   8B    (pointer to the previous free block)
 * - next   8B    (pointer to the next free block)
 * - data   (size Bytes, round to 8)
 * - footer 8B    (packed size and allocated bit)
 */
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "memlib.h"
#include "mm.h"

/* If you want debugging output, use the following macro.  When you hand
 * in, remove the #define DEBUG line. */
// #define DEBUG
#ifdef DEBUG
#define dbg_printf(...) printf(__VA_ARGS__)
#else
#define dbg_printf(...)
#endif

#define ASSERT(cond, msg)                                            \
	do                                                               \
	{                                                                \
		if (!(cond))                                                 \
		{                                                            \
			fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, msg); \
			errno = 1;                                               \
		}                                                            \
	} while (0)

/* do not change the following! */
#ifdef DRIVER
/* create aliases for driver tests */
#define malloc mm_malloc
#define free mm_free
#define realloc mm_realloc
#define calloc mm_calloc
#endif /* def DRIVER */

/* single word (4) or double word (8) alignment */
#define ALIGNMENT 8

/* rounds up to the nearest multiple of ALIGNMENT */
#define ALIGN(p) (((size_t)(p) + (ALIGNMENT - 1)) & ~0x7)
#define ROUND(size) ((size + (ALIGNMENT - 1)) & ~(ALIGNMENT - 1))

/* define types for convenience */
typedef int bool;
#define true 1
#define false 0
typedef size_t packed_t;
int errno;
#define GET(x) (*x)
#define SET(x, v) (*((packed_t*)x) = (v))
/* pack size and allocated*/
#define PACK(size, alloc) ((size) | (alloc))
#define GET_SIZE(packed) (size_t)(packed & ~0x7)
#define GET_ALLOC(packed) (bool)(packed & 0x1)

#define HSIZE sizeof(block_t)
#define FSIZE sizeof(packed_t)
/* p is a block_t pointer, get the header of the current block, which is
 * meaningless */
#define HDPT(bp) ((packed_t *)bp)
/* p is a block_t pointer, get the footer of the current block */
#define FTPT(bp) ((packed_t *)((char *)bp + HSIZE + GET_SIZE(*HDPT(bp))))
/* assuming p is a block_t pointer, get the footer of the previous block */
#define PREV_FTPT(p) ((packed_t *)((char *)p - FSIZE))
/* assuming p is a block_t pointer, get the header of the previous block */
#define PREV_HDPT(p)                                           \
	((block_t *)((char *)p - HSIZE - GET_SIZE(*PREV_FTPT(p)) - \
				 FSIZE))
/* assuming p is a block_t pointer, get the header of the next block */
#define NEXT_HDPT(p)                                       \
	((block_t *)((char *)p + HSIZE + GET_SIZE(p->header) + \
				 FSIZE))
/* get block header by data pointer*/
#define HDPT_BY_DATA(p) ((block_t *)((char *)p - HSIZE))

/* struct for a free block in free chain */
typedef struct block_t
{
	packed_t header;
	struct block_t *next;
	struct block_t *prev;
	void *data[0];
} block_t;

/* struct for a bin, which contains blocks that are of a particular size range
 */
typedef struct bin_t
{
	struct block_t *head;
} bin_t;

/* global bins array pointer, stored at the beginning of the heap */
static bin_t *bins;

/* bins are classified using the size rules*/
static const size_t size_classes[] = {
	8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128,
	160, 192, 224, 256, 320, 384, 448, 512, 640, 768, 896, 1024,
	(size_t)-1 // for objects larger than 1024, use the same bin
};
static const int NUM_CLASSES = sizeof(size_classes) / sizeof(size_classes[0]);
static const size_t MIN_BLOCK_SIZE = 64;

/* sentinel blocks are used to mark the beginning and end of the block arena */
static block_t *sentinel_block1;
static block_t *sentinel_block2;

/* bin helper functions */
static int setup_bins();
static size_t bin_index(size_t size);
static void insert_block(block_t *block, size_t bin_idx);
static void remove_block(block_t *block, size_t bin_idx);
static block_t *split_block(block_t *old_block, size_t size);
static block_t* coalesce(block_t *block_ptr);

static void dump_heap(int lineno);

/*
 * Initialize: return -1 on error, 0 on success.
 */
int mm_init(void)
{
	/* reset heap size */
	mem_reset_brk();

	/* setup bins */
	if (setup_bins() != 0)
	{
		return -1; // unable to setup bins
	}

	/* install sentinel blocks */
	size_t sentinel_size = sizeof(block_t) + sizeof(packed_t);
	void *mem_ptr = mem_sbrk(sentinel_size);
	if (mem_ptr == (void *)(-1))
	{
		return -1; // unable to allocate memory
	}
	sentinel_block1 = mem_ptr;
	*HDPT(sentinel_block1) = PACK(0, true);
	*FTPT(sentinel_block1) = PACK(0, true);
	/* install sentinel block 2*/
	mem_ptr = mem_sbrk(sentinel_size);
	if (mem_ptr == (void *)(-1))
	{
		return -1; // unable to allocate memory
	}
	sentinel_block2 = (block_t *)mem_ptr;
	*HDPT(sentinel_block2) = PACK(0, true);
	*FTPT(sentinel_block2) = PACK(0, true);

#ifdef DEBUG
	mm_checkheap(__LINE__);
#endif

	return 0;
}

/*
Try to split the block, and modify their headers and footers accordingly
and modify their corresponding free list in bin to reflect the change

if the block is too small to accommodate both the old and new blocks
(because header and footer took 4 words), simply mark the block as alloced
and remove the block from free list
*/
static block_t *split_block(block_t *old_block, size_t size)
{
	/* round the size up to ALIGNMENT */
	size = ROUND(size);

	size_t old_size = GET_SIZE(*HDPT(old_block));
	if (old_size - size <= MIN_BLOCK_SIZE)
	{
		/* remove the block from the bin and register it as allocated */
		*HDPT(old_block) = PACK(old_size, true);
		*FTPT(old_block) = PACK(old_size, true);
		remove_block(old_block, bin_index(old_size));
		return old_block;
	}

	/* split the block into size + newsize blocks */
	/*
	|--*old_blk--|---------------------old_size----------------------|---old_footer--|
	|--*old_blk--|--size--|--old_footer--|--*new_block--|--new_size--|---new_footer--|
	*/
	*HDPT(old_block) = PACK(size, true);
	*FTPT(old_block) = PACK(size, true);

	/* create a new block for the remaining part */
	long new_size = old_size - size - HSIZE - FSIZE;

    assert(new_size >= 0);

	block_t *new_block =
		(block_t *)((char *)old_block->data + size + FSIZE); // footer

	*HDPT(new_block) = PACK(new_size, false);
	*FTPT(new_block) = PACK(new_size, false);
	
	remove_block(old_block, bin_index(old_size));
    insert_block(new_block, bin_index(new_size));

	return old_block;
}

/*
 * malloc
 * we first find the bin that the `size` belongs to, and take the first free
 * block from the bin, because this should always fit the object required
 * we only need to split the block if it is too large, and return the remainder
 * to its corresponding bin
 * if no fit is found, we allocate a new block, and return the pointer to the
 * data we also need to adjust the right sentinel block2
 */
void *malloc(size_t size)
{
#ifdef DEBUG
	mm_checkheap(__LINE__);
#endif

    size = ROUND(size);

	size_t bin_idx = bin_index(size);

	/* search free list in bin for a fit */
	block_t *curr = bins[bin_idx].head;
	while (curr != NULL)
	{
		/* first fit*/
		if (GET_SIZE(*HDPT(curr)) >= size)
		{
			/* split the block and return the desired block */
			curr = split_block(curr, size);
			return curr->data;
		}
		curr = curr->next;
	}

	/* no fit found, allocate a new block */
	size_t new_block_size = ROUND(size);
	size_t block_overhead =
		HSIZE + sizeof(packed_t); // header + footer
	size_t sentinel_size = HSIZE + sizeof(packed_t);
	size_t total_size = new_block_size + block_overhead;

	/* Allocate space for the new block and the sentinel block2 */
	void *ptr = mem_sbrk(total_size);
	if (ptr == (void *)(-1))
	{
		return NULL;
	}

	block_t *new_block = (block_t *)(char *)(ptr - sentinel_size);

	/* Update sentinel_block2 to be after the new block */
	sentinel_block2 = (block_t *)((char *)new_block + total_size);
	*HDPT(sentinel_block2) = PACK(0, true);
	*FTPT(sentinel_block2) = PACK(0, true);

#ifdef DEBUG
	mm_checkheap(__LINE__);
#endif

    new_block = coalesce(new_block);
    new_block_size = GET_SIZE(*HDPT(new_block));
    remove_block(new_block, bin_index(new_block_size));
    *HDPT(new_block) = PACK(new_block_size, true);
    *FTPT(new_block) = PACK(new_block_size, true);

	return new_block->data;
}

/*
 * free
 * simply mark the block as not allocated, and coalesce if possible
 */
void free(void *ptr)
{
	/* ignore free(NULL) */
	if (!ptr)
		return;

	/* find the block pointer by data pointer */
	block_t *block_ptr = HDPT_BY_DATA(ptr);

#ifdef DEBUG
	mm_checkheap(__LINE__);
#endif

	coalesce(block_ptr);

#ifdef DEBUG
	mm_checkheap(__LINE__);
#endif
}

/*
 * realloc
 * TODO: Implement expansion
 */
void *realloc(void *oldptr, size_t size)
{
#ifdef DEBUG
	mm_checkheap(__LINE__);
#endif

	size_t oldsize;
	void *newptr;

	/* If size == 0 then this is just free, and we return NULL. */
	if (size == 0)
	{
		free(oldptr);
		return 0;
	}

	/* If oldptr is NULL, then this is just malloc. */
	if (oldptr == NULL)
	{
		return malloc(size);
	}

	/* try to combine the block on the right */
	block_t *block_ptr = HDPT_BY_DATA(oldptr);
	block_t *next_block = NEXT_HDPT(block_ptr);
	if (!GET_ALLOC(next_block->header) && GET_SIZE(next_block->header) + GET_SIZE(block_ptr->header) >= size)
	{
		/* remove the next block from the bin */
		remove_block(next_block, bin_index(GET_SIZE(next_block->header)));
		/* combine the two blocks */
		size_t new_size = GET_SIZE(next_block->header) + GET_SIZE(block_ptr->header) + sizeof(packed_t) + sizeof(block_t);
		*HDPT(block_ptr) = PACK(new_size, true);
		*FTPT(block_ptr) = PACK(new_size, true);
		return block_ptr->data;
	}
	else
	{
		/* failed to combine, fall back to naive implementation */
		newptr = malloc(size);

		/* If realloc() fails the original block is left untouched  */
		if (!newptr)
		{
			return 0;
		}

		/* Copy the old data. */
		block_t *block_ptr = HDPT_BY_DATA(oldptr);
		oldsize = GET_SIZE(block_ptr->header);

		if (size < oldsize)
			oldsize = size;
		memcpy(newptr, oldptr, oldsize);

		/* Free the old block. */
		free(oldptr);
	}

#ifdef DEBUG
	mm_checkheap(__LINE__);
#endif

	return newptr;
}

/*
 * calloc - you may want to look at mm-naive.c
 * initialize a nmemb * size block of memory to 0
 */
void *calloc(size_t nmemb, size_t size)
{
	size_t bytes = nmemb * size;
	void *newptr;

	newptr = malloc(bytes);
	memset(newptr, 0, bytes);

	return newptr;
}

/*
 * Return whether the pointer is in the heap.
 * May be useful for debugging.
 */
static int in_heap(const void *p)
{
	return p <= mem_heap_hi() && p >= mem_heap_lo();
}

/*
 * Return whether the pointer is aligned.
 * May be useful for debugging.
 */
static int aligned(const void *p) { return (size_t)ALIGN(p) == (size_t)p; }

/*
 * dump the heap if a catastrophic error occurs
 */
static void dump_heap(int lineno)
{
#ifdef DEBUG
	dbg_printf("mm_checkheap failed at line %d, dumping heap\n", lineno);
	dbg_printf("heap_hi: %p, heap_lo: %p\n", mem_heap_hi(), mem_heap_lo());
	dbg_printf("sentinel_block1: %p, sentinel_block2: %p\n", sentinel_block1, sentinel_block2);
	dbg_printf("\n\n>>> snapshot <<<\n");
	/* dump free blocks in each bin*/
	dbg_printf("Bin status:\n");
	for (size_t i = 0; i < NUM_CLASSES; i++)
	{
		size_t min_size = (i == 0) ? 0 : size_classes[i - 1];
		size_t max_size = size_classes[i];
		block_t *curr = bins[i].head;
		if (curr != NULL)
		{
			dbg_printf("Bin %zu (%lx-%lx): ", i, min_size, max_size);
			while (curr != NULL)
			{
				dbg_printf("%p (size 0x%lx)", curr, GET_SIZE(curr->header));
				if (curr->next != NULL)
				{
					dbg_printf(" <-> ");
				}
				curr = curr->next;
			}
			dbg_printf("\n");
		}
	}
	dbg_printf("\n\n");
#endif
}

/*
 * mm_checkheap
 */
void mm_checkheap(int lineno)
{
#ifdef DEBUG
	/* check sentinel block 2*/
	size_t sentinel_size = sizeof(block_t) + sizeof(packed_t);
	if ((char *)sentinel_block2 + sentinel_size - 1 != mem_heap_hi())
	{
		dbg_printf("sentinel_block2 is not at the end of the heap\n");
		dbg_printf("sentinel_block2: %p, heap_hi: %p\n", sentinel_block2, mem_heap_hi());
		dbg_printf("sentinel_size: %lu, heap_size: %lu\n", sentinel_size, mem_heap_hi() - mem_heap_lo());
		dump_heap(lineno);
		exit(1);
	}
	/* check size constraints and header/footer */
	errno = 0;
	for (size_t i = 0; i < NUM_CLASSES; i++)
	{
		block_t *curr = bins[i].head;
		while (curr != NULL)
		{
			size_t size = GET_SIZE(curr->header);
			ASSERT(bin_index(size) == i, "Wrong size");
			ASSERT(GET_ALLOC(curr->header) == false, "Header is allocated");
			ASSERT(GET_ALLOC(*FTPT(curr)) == false, "Footer is allocated");
			if (errno != 0)
			{
				fprintf(stderr, "@block %p\n", curr);
			}
			curr = curr->next;
		}
	}
	if (errno != 0)
	{
		dump_heap(lineno);
		exit(1);
	}

	/* check doubly linked list integrity */
	errno = 0;
	for (size_t i = 0; i < NUM_CLASSES; i++)
	{
		block_t *curr = bins[i].head;
		while (curr != NULL && curr->next != NULL)
		{
			ASSERT(curr->next->prev == curr, "Doubly linked list integrity violated");
			if (errno != 0)
			{
				fprintf(stderr, "@block %p\n", curr);
			}
			curr = curr->next;
		}
	}
	if (errno != 0)
	{
		dump_heap(lineno);
		exit(1);
	}
#endif
}

/* setup bins according to the size classes */
static int setup_bins()
{
	void *ptr = mem_sbrk(sizeof(bin_t) * NUM_CLASSES);
	if (ptr == (void *)(-1))
	{
		return -1; // unable to allocate memory
	}
	bins = (bin_t *)ptr;
	for (size_t i = 0; i < NUM_CLASSES; i++)
	{
		bins[i].head = NULL;
	}
	return 0;
}

/* return the index of the bin that the `size` belongs to */
size_t bin_index(size_t size)
{
	/* round the size up to ALIGNMENT*/
	size = ROUND(size);
	/* find the smallest class that can fit the size */
	for (size_t i = 0; i < NUM_CLASSES; i++)
	{
		if (size <= size_classes[i])
		{
			return i;
		}
	}
	/* should never reach here*/
	return NUM_CLASSES - 1;
}

/*
free the current block and coalesce adjacent free blocks if possible
place the combined big free block to its corresponding bin
*/
static block_t* coalesce(block_t *block_ptr)
{

	/* By prev and next, we mean physically adjacent blocks */
	block_t *next_blk = NEXT_HDPT(block_ptr);
    packed_t cur_header = *HDPT(block_ptr);
    packed_t next_header = *HDPT(next_blk);
	packed_t prev_footer = *PREV_FTPT(block_ptr);
	block_t *result_blk;
	if (GET_ALLOC(next_header) && GET_ALLOC(prev_footer))
	{
		/* Case 1: both blocks are allocated */
		/* cannot coalesce, insert only the current block */
        size_t cur_size = GET_SIZE(cur_header);

        *HDPT(block_ptr) = PACK(cur_size, false);
        *FTPT(block_ptr) = PACK(cur_size, false);
		insert_block(block_ptr, bin_index(cur_size));
		result_blk = block_ptr;
	}
	else if (GET_ALLOC(next_header) && !GET_ALLOC(prev_footer))
	{
		/* Case 2: next block is allocated, previous block is free */
		block_t *prev_blk = PREV_HDPT(block_ptr);
		size_t prev_size = GET_SIZE(prev_blk->header);
        size_t cur_size = GET_SIZE(block_ptr->header);
		size_t new_size = prev_size + cur_size + HSIZE + FSIZE;

		*HDPT(prev_blk) = PACK(new_size, false);
		*FTPT(prev_blk) = PACK(new_size, false);
		remove_block(prev_blk, bin_index(prev_size));
		insert_block(prev_blk, bin_index(new_size));
		result_blk = prev_blk;
	}
	else if (!GET_ALLOC(next_header) && GET_ALLOC(prev_footer))
	{
		/* Case 3: next block is free, previous block is allocated */
		block_t *next_blk = NEXT_HDPT(block_ptr);
		size_t next_size = GET_SIZE(next_blk->header);
        size_t cur_size = GET_SIZE(block_ptr->header);
		size_t new_size = cur_size + next_size + HSIZE + FSIZE;
        
		*HDPT(block_ptr) = PACK(new_size, false);
		*FTPT(block_ptr) = PACK(new_size, false);
		remove_block(next_blk, bin_index(next_size));
		insert_block(block_ptr, bin_index(new_size));
		result_blk = block_ptr;
	}
	else if (!GET_ALLOC(next_header) && !GET_ALLOC(prev_footer))
	{
		/* Case 4: both blocks are free */
		block_t *prev_blk = PREV_HDPT(block_ptr);
		block_t *next_blk = NEXT_HDPT(block_ptr);
		size_t prev_size = GET_SIZE(prev_blk->header);
		size_t next_size = GET_SIZE(next_blk->header);
        size_t cur_size = GET_SIZE(block_ptr->header);

		size_t new_size = prev_size + (HSIZE + FSIZE) * 2 +
						  next_size + cur_size;
		*HDPT(prev_blk) = PACK(new_size, false);
		*FTPT(prev_blk) = PACK(new_size, false);
		remove_block(prev_blk, bin_index(prev_size));
		remove_block(next_blk, bin_index(next_size));
		insert_block(prev_blk, bin_index(new_size));
		result_blk = prev_blk;
	}
	return result_blk;
}

/* insert a free block into the corresponding bin free list*/
static void insert_block(block_t *block, size_t bin_idx)
{
	// dbg_printf("Inserting into bin %zu\n", bin_idx);
	block->next = bins[bin_idx].head;
	block->prev = NULL;
	if (bins[bin_idx].head != NULL)
	{
		bins[bin_idx].head->prev = block;
	}
	bins[bin_idx].head = block;
}

/*
remove a block from the corresponding bin free list
have to make sure its actually **in** the list
*/
static void remove_block(block_t *block, size_t bin_idx)
{
	if (block->prev)
	{
		block->prev->next = block->next;
	}
	else
	{
		bins[bin_idx].head = block->next;
	}
	if (block->next)
	{
		block->next->prev = block->prev;
	}
	block->next = NULL;
	block->prev = NULL;
}
