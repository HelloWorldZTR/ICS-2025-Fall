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

#define ASSERT(cond, msg)                                                      \
  do {                                                                         \
    if (!(cond)) {                                                             \
      fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, msg);                 \
      errno = 1;                                                               \
    }                                                                          \
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

/* pack size and allocated*/
#define PACK(size, alloc) ((size) | (alloc))
#define GET_SIZE(packed) (size_t)(packed & ~0x7)
#define GET_ALLOC(packed) (bool)(packed & 0x1)
/* Offset from start of block_t to data field */
#define DATA_OFFSET offsetof(block_t, data)

/* p is a block_t pointer, get the header of the current block, which is
 * meaningless */
#define GET_HEADER_P(p) (&(p->header))
/* p is a block_t pointer, get the footer of the current block */
#define GET_FOOTER_P(p) ((packed_t *)((char *)p->data + GET_SIZE(p->header)))
/* assuming p is a block_t pointer, get the footer of the previous block */
#define GET_LFOOTER_P(p) ((packed_t *)((char *)p - sizeof(packed_t)))
/* assuming p is a block_t pointer, get the header of the previous block */
#define GET_LHEADER_P(p)                                                       \
  ((block_t *)((char *)p - DATA_OFFSET - GET_SIZE(*GET_LFOOTER_P(p)) -         \
               sizeof(packed_t)))
/* assuming p is a block_t pointer, get the header of the next block */
#define GET_RHEADER_P(p)                                                       \
  ((block_t *)((char *)p + DATA_OFFSET + GET_SIZE(p->header) +                 \
               sizeof(packed_t)))
/* get block header by data pointer*/
#define GET_HEADER_P_BY_DATA(p) ((block_t *)((char *)p - DATA_OFFSET))

/* struct for a free block in free chain */
typedef struct block_t {
  packed_t header;
  struct block_t *next;
  struct block_t *prev;
  void *data[0];
} block_t;

/* struct for a bin, which contains blocks that are of a particular size range
 */
typedef struct bin_t {
  size_t block_size_min; // Use for debugging, we can remove it
  size_t block_size_max;
  struct block_t *head;
} bin_t;

/* global bins array pointer, stored at the beginning of the heap */
static bin_t *bins;

/* bins are classified using the size rules*/
static const size_t size_classes[] = {
    8,         16,  24,  32,  40,  48,  56,  64,  80,  96,  112, 128,
    160,       192, 224, 256, 320, 384, 448, 512, 640, 768, 896, 1024,
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
static void coalesce(block_t *block_ptr);

/* debug structs and functions */
typedef struct dbg_blk_entry {
  block_t *blk_ptr;
  bool is_free;
  bool is_used;
} dbg_blk_entry;

enum dbg_op_type { ALLOC, FREE, REALLOC };

typedef struct dbg_trace_entry {
  int lineno;
  enum dbg_op_type op;
  size_t size;
  void *ptr;
  block_t *blk_ptr;
} dbg_trace_entry;

#ifdef DEBUG
#define DBG_BLK_ENTRIES_MAX 4096
#define DBG_TRACE_ENTRIES_MAX 4096
static dbg_blk_entry dbg_blk_entries[DBG_BLK_ENTRIES_MAX];
static size_t dbg_blk_entries_idx = 0;
static dbg_trace_entry dbg_trace_entries[DBG_TRACE_ENTRIES_MAX];
static size_t dbg_trace_entries_idx = 0;
#endif

static void dbg_register_block(int lineno, block_t *block, bool is_free);
static void dbg_unregister_block(block_t *block);
static void dbg_log_trace(int lineno, enum dbg_op_type op, size_t size,
                          void *ptr, block_t *blk_ptr);
static void dump_heap(int lineno);

/*
 * Initialize: return -1 on error, 0 on success.
 */
int mm_init(void) {
#ifdef DEBUG
	/* reset side note */
	dbg_blk_entries_idx = 0;
	dbg_trace_entries_idx = 0;
	memset(dbg_blk_entries, 0, sizeof(dbg_blk_entries));
	memset(dbg_trace_entries, 0, sizeof(dbg_trace_entries));
#endif

  /* reset heap size */
  mem_reset_brk();

  /* setup bins */
  if (setup_bins() != 0) {
    return -1; // unable to setup bins
  }

  /* install sentinel blocks */
  size_t sentinel_size = sizeof(block_t) + sizeof(packed_t);
  /* align sentinel block 1 */
  size_t current_heap_end = (size_t)mem_heap_hi() + 1;
  size_t aligned_addr = ALIGN(current_heap_end);
  size_t alignment_padding = aligned_addr - current_heap_end;
  void *mem_ptr = mem_sbrk(sentinel_size + alignment_padding);
  if (mem_ptr == (void *)(-1)) {
    return -1; // unable to allocate memory
  }
  sentinel_block1 = (block_t *)aligned_addr;
  *GET_HEADER_P(sentinel_block1) = PACK(0, true);
  *GET_FOOTER_P(sentinel_block1) = PACK(0, true);
	/* install sentinel block 2*/
  mem_ptr = mem_sbrk(sentinel_size);
  if (mem_ptr == (void *)(-1)) {
    return -1; // unable to allocate memory
  }
  sentinel_block2 = (block_t *)mem_ptr;
  *GET_HEADER_P(sentinel_block2) = PACK(0, true);
  *GET_FOOTER_P(sentinel_block2) = PACK(0, true);

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
static block_t *split_block(block_t *old_block, size_t size) {
  /* round the size up to ALIGNMENT */
  size = ROUND(size);

  /*
        when the block is too small, it is not worth splitting
        new_size = old_size - size - sizeof(packed_t) - sizeof(block_t)
        should be at least 8 bytes
        (old_size - size) should be at leat 8 + header + footer
        */
  size_t old_size = GET_SIZE(old_block->header);
  if (old_size - size <= MIN_BLOCK_SIZE) {
    /* remove the block from the bin and register it as allocated */
    *GET_HEADER_P(old_block) = PACK(old_size, true);
    *GET_FOOTER_P(old_block) = PACK(old_size, true);
    remove_block(old_block, bin_index(old_size));
    dbg_unregister_block(old_block);
    dbg_register_block(__LINE__, old_block, false);
    return old_block;
  }

  /* split the block into size + newsize blocks */
  /*
  |--*old_blk--|---------------------old_size----------------------|---old_footer--|
  |--*old_blk--|--size--|--old_footer--|--*new_block--|--new_size--|---new_footer--|
  */
  *GET_HEADER_P(old_block) = PACK(size, true);
  *GET_FOOTER_P(old_block) = PACK(size, true);
  /* create a new block for the remaining part */
  size_t new_size = old_size - size - sizeof(packed_t) - sizeof(block_t);
  block_t *new_block =
      (block_t *)((char *)old_block->data + size + sizeof(packed_t)); // footer
  *GET_HEADER_P(new_block) = PACK(new_size, false);
  *GET_FOOTER_P(new_block) = PACK(new_size, false);
  new_block->next = NULL;
  new_block->prev = NULL;
  insert_block(new_block, bin_index(new_size));
  remove_block(old_block, bin_index(old_size));
  dbg_unregister_block(old_block);
  dbg_register_block(__LINE__, old_block, false);
  dbg_register_block(__LINE__, new_block, true);
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
void *malloc(size_t size) {
#ifdef DEBUG
  mm_checkheap(__LINE__);
#endif

  size_t bin_idx = bin_index(size);

  /* search free list in bin for a fit */
  block_t *curr = bins[bin_idx].head;
  while (curr != NULL) {
		/* first fit*/
		if (GET_SIZE(curr->header) >= size) {
			/* split the block and return the desired block */
			curr = split_block(curr, size);
#ifdef DEBUG
			dbg_log_trace(__LINE__, ALLOC, size, curr->data, curr);
			mm_checkheap(__LINE__);
#endif
			return curr->data;
		}
		curr = curr->next;
	}

  /* no fit found, allocate a new block */
  size_t new_block_size = ROUND(size);
  size_t block_overhead =
      DATA_OFFSET + sizeof(packed_t); // header + footer
	size_t sentinel_size = DATA_OFFSET + sizeof(packed_t);
  size_t total_size = new_block_size + block_overhead;
	size_t required_size = total_size + sentinel_size;

  /* Allocate space for the new block and the sentinel block2 */
  void *ptr = mem_sbrk(required_size);
  if (ptr == (void *)(-1)) {
    return NULL;
  }
	/*
	|---many blocks---|---sentinel2---| heap hi
	|---many blocks---|---sentinelx---|--new_block----|----sentinel2---| heap hi
	*/
  block_t *new_block = (block_t *)ptr;

  /* Update sentinel_block2 to be after the new block */
  sentinel_block2 = (block_t *)((char*)new_block + total_size);
  *GET_HEADER_P(sentinel_block2) = PACK(0, true);
  *GET_FOOTER_P(sentinel_block2) = PACK(0, true);

#ifdef DEBUG
	/* check sentinel block2 */
	mm_checkheap(__LINE__);
#endif

  /* Set up the new block */
  *GET_HEADER_P(new_block) = PACK(new_block_size, true);
  *GET_FOOTER_P(new_block) = PACK(new_block_size, true);
  new_block->next = NULL;
  new_block->prev = NULL;

#ifdef DEBUG
  dbg_log_trace(__LINE__, ALLOC, size, new_block->data, new_block);
  mm_checkheap(__LINE__);
#endif

  return new_block->data;
}

/*
 * free
 * simply mark the block as not allocated, and coalesce if possible
 */
void free(void *ptr) {
  /* ignore free(NULL) */
  if (!ptr)
    return;

  /* find the block pointer by data pointer */
  block_t *block_ptr = GET_HEADER_P_BY_DATA(ptr);

#ifdef DEBUG
  dbg_log_trace(__LINE__, FREE, GET_SIZE(block_ptr->header), ptr, block_ptr);
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
void *realloc(void *oldptr, size_t size) {
#ifdef DEBUG
  mm_checkheap(__LINE__);
#endif

  size_t oldsize;
  void *newptr;

  /* If size == 0 then this is just free, and we return NULL. */
  if (size == 0) {
    free(oldptr);
    return 0;
  }

  /* If oldptr is NULL, then this is just malloc. */
  if (oldptr == NULL) {
    return malloc(size);
  }

  newptr = malloc(size);

  /* If realloc() fails the original block is left untouched  */
  if (!newptr) {
    return 0;
  }

  /* Copy the old data. */
  block_t *block_ptr = GET_HEADER_P_BY_DATA(oldptr);
  oldsize = GET_SIZE(block_ptr->header);

  if (size < oldsize)
    oldsize = size;
  memcpy(newptr, oldptr, oldsize);

  /* Free the old block. */
  free(oldptr);

#ifdef DEBUG
  dbg_log_trace(__LINE__, REALLOC, size, newptr, block_ptr);
  mm_checkheap(__LINE__);
#endif

  return newptr;
}

/*
 * calloc - you may want to look at mm-naive.c
 * initialize a nmemb * size block of memory to 0
 */
void *calloc(size_t nmemb, size_t size) {
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
static int in_heap(const void *p) {
  return p <= mem_heap_hi() && p >= mem_heap_lo();
}

/*
 * Return whether the pointer is aligned.
 * May be useful for debugging.
 */
static int aligned(const void *p) { return (size_t)ALIGN(p) == (size_t)p; }

/*
 * keep a side note of all the blocks in heap, for debugging
 */

/*
 * dump the heap if a catastrophic error occurs
 */
static void dump_heap(int lineno) {
#ifdef DEBUG
  dbg_printf("mm_checkheap failed at line %d, dumping heap\n", lineno);
	dbg_printf("heap_hi: %p, heap_lo: %p\n", mem_heap_hi(), mem_heap_lo());
	dbg_printf("sentinel_block1: %p, sentinel_block2: %p\n", sentinel_block1, sentinel_block2);
  dbg_printf("\n\n>>> snapshot <<<\n");
  /* dump free blocks in each bin*/
  dbg_printf("Bin status:\n");
  for (size_t i = 0; i < NUM_CLASSES; i++) {
    block_t *curr = bins[i].head;
    size_t min_size = bins[i].block_size_min;
    size_t max_size = bins[i].block_size_max;
    if (curr != NULL) {
      dbg_printf("Bin %zu (%lx-%lx): ", i, min_size, max_size);
      while (curr != NULL) {
        dbg_printf("%p (size 0x%lx)", curr, GET_SIZE(curr->header));
        if (curr->next != NULL) {
          dbg_printf(" <-> ");
        }
        curr = curr->next;
      }
      dbg_printf("\n");
    }
  }
  /* dump blocks registered in side note */
  dbg_printf("All blocks:\n");
  for (size_t i = 0; i < dbg_blk_entries_idx; i++) {
    if (!dbg_blk_entries[i].is_used) {
      continue;
    }
    block_t *blk_ptr = dbg_blk_entries[i].blk_ptr;
    dbg_printf("Block %p (size 0x%lx, %s)\n", blk_ptr,
               GET_SIZE(blk_ptr->header),
               dbg_blk_entries[i].is_free ? "free" : "allocated");
  }

  /* show call stack */
  dbg_printf("\n\n>>> calls <<<\n");
  for (size_t i = 0; i < dbg_trace_entries_idx; i++) {
    size_t idx = dbg_trace_entries_idx - i - 1;
    dbg_printf(" #%ld mm.c:%d %s %p (size 0x%lx)\n", i,
               dbg_trace_entries[idx].lineno,
               dbg_trace_entries[idx].op == ALLOC  ? "ALLOC"
               : dbg_trace_entries[idx].op == FREE ? "FREE"
                                                   : "REALLOC",
               dbg_trace_entries[idx].ptr, dbg_trace_entries[idx].size);
    dbg_printf("  block %p\n", dbg_trace_entries[idx].blk_ptr);
    if (i > 10) {
      dbg_printf("  ...\n");
      break;
    }
  }
  dbg_printf("\n\n");
#endif
}

/*
 * mm_checkheap
 */
void mm_checkheap(int lineno) {
#ifdef DEBUG
	/* check sentinel block 2*/
	size_t sentinel_size = sizeof(block_t) + sizeof(packed_t);
	if ((char*)sentinel_block2 + sentinel_size - 1 != mem_heap_hi()) {
		dbg_printf("sentinel_block2 is not at the end of the heap\n");
		dbg_printf("sentinel_block2: %p, heap_hi: %p\n", sentinel_block2, mem_heap_hi());
		dbg_printf("sentinel_size: %lu, heap_size: %lu\n", sentinel_size, mem_heap_hi() - mem_heap_lo());
		dump_heap(lineno);
		exit(1);
	}
  /* check size constraints and header/footer */
  errno = 0;
  for (size_t i = 0; i < NUM_CLASSES; i++) {
    block_t *curr = bins[i].head;
    size_t min_size = bins[i].block_size_min;
    size_t max_size = bins[i].block_size_max;

    while (curr != NULL) {
      size_t size = GET_SIZE(curr->header);
      ASSERT(size >= min_size && size <= max_size, "Block size out of range");
      ASSERT(GET_ALLOC(curr->header) == false, "Block is allocated");
      ASSERT(GET_ALLOC(*GET_FOOTER_P(curr)) == false, "Footer is allocated");
      if (errno != 0) {
        fprintf(stderr, "@block %p\n", curr);
      }
      curr = curr->next;
    }
  }
  if (errno != 0) {
    dump_heap(lineno);
    exit(1);
  }

  /* check doubly linked list integrity */
  errno = 0;
  for (size_t i = 0; i < NUM_CLASSES; i++) {
    block_t *curr = bins[i].head;
    while (curr != NULL && curr->next != NULL) {
      ASSERT(curr->next->prev == curr, "Doubly linked list integrity violated");
      if (errno != 0) {
        fprintf(stderr, "@block %p\n", curr);
      }
      curr = curr->next;
    }
  }
  if (errno != 0) {
    dump_heap(lineno);
    exit(1);
  }

  /* check header footer consistency */
  errno = 0;
  for (size_t i = 0; i < dbg_blk_entries_idx; i++) {
    if (!dbg_blk_entries[i].is_used) {
      continue;
    }
    block_t *blk_ptr = dbg_blk_entries[i].blk_ptr;
    ASSERT(GET_SIZE(blk_ptr->header) == GET_SIZE(*GET_FOOTER_P(blk_ptr)),
           "Header footer consistency violated");
    ASSERT(GET_ALLOC(blk_ptr->header) == !dbg_blk_entries[i].is_free,
           "Allocated bit consistency violated");
    ASSERT(GET_ALLOC(*GET_FOOTER_P(blk_ptr)) == !dbg_blk_entries[i].is_free,
           "Allocated bit consistency violated");
    if (errno != 0) {
      fprintf(stderr, "@block %p\n", blk_ptr);
      break;
    }
  }
  if (errno != 0) {
    dump_heap(lineno);
    exit(1);
  }
#endif
}

/* setup bins according to the size classes */
static int setup_bins() {
  void *ptr = mem_sbrk(sizeof(bin_t) * NUM_CLASSES);
  if (ptr == (void *)(-1)) {
    return -1; // unable to allocate memory
  }
  bins = (bin_t *)ptr;
  for (size_t i = 0; i < NUM_CLASSES; i++) {
    if (i == 0) {
      bins[i].block_size_min = 0;
    } else {
      bins[i].block_size_min = size_classes[i - 1];
    }
    bins[i].block_size_max = size_classes[i];
    bins[i].head = NULL;
  }
  return 0;
}

/* return the index of the bin that the `size` belongs to */
size_t bin_index(size_t size) {
  /* round the size up to ALIGNMENT*/
  size = ROUND(size);
  /* find the smallest class that can fit the size */
  for (size_t i = 0; i < NUM_CLASSES; i++) {
    if (size <= size_classes[i]) {
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
static void coalesce(block_t *block_ptr) {

  /* By prev and next, we mean physically adjacent blocks */
  block_t *next_blk = GET_RHEADER_P(block_ptr);
  packed_t next_header = *GET_HEADER_P(next_blk);
  packed_t prev_footer = *GET_LFOOTER_P(block_ptr);
  if (GET_ALLOC(next_header) && GET_ALLOC(prev_footer)) {
    /* Case 1: both blocks are allocated */
    /* cannot coalesce, insert only the current block */
    *GET_HEADER_P(block_ptr) = PACK(GET_SIZE(block_ptr->header), false);
    *GET_FOOTER_P(block_ptr) = PACK(GET_SIZE(block_ptr->header), false);
    insert_block(block_ptr, bin_index(GET_SIZE(block_ptr->header)));
    dbg_unregister_block(block_ptr);
    dbg_register_block(__LINE__,block_ptr, true);

  } else if (GET_ALLOC(next_header) && !GET_ALLOC(prev_footer)) {
    /* Case 2: next block is allocated, previous block is free */
    block_t *prev_blk = GET_LHEADER_P(block_ptr);
    size_t prev_size = GET_SIZE(prev_blk->header);
    /* the combined size = previous block size + current block size + header and
       footer
			|--*prev_blk--|--prev_size---|--footer--|--*block_ptr--|--block_size---|--footer--|
			|--*prev_blk--|--new_size----------------------------------------------|--footer--|
		*/
    size_t new_size = prev_size + GET_SIZE(block_ptr->header) +
                      sizeof(packed_t) + sizeof(block_t);
    *GET_HEADER_P(prev_blk) = PACK(new_size, false);
    *GET_FOOTER_P(prev_blk) = PACK(new_size, false);
    remove_block(prev_blk, bin_index(prev_size));
    insert_block(prev_blk, bin_index(new_size));
    dbg_unregister_block(prev_blk);
    dbg_unregister_block(block_ptr);
    dbg_register_block(__LINE__,prev_blk, true);

  } else if (!GET_ALLOC(next_header) && GET_ALLOC(prev_footer)) {
    /* Case 3: next block is free, previous block is allocated */
    block_t *next_blk = GET_RHEADER_P(block_ptr);
    size_t next_size = GET_SIZE(next_blk->header);
    /* the combined size = previous block size + current block size + header and
     * footer */
    size_t new_size = GET_SIZE(block_ptr->header) + sizeof(packed_t) +
                      sizeof(block_t) + next_size;
    *GET_HEADER_P(block_ptr) = PACK(new_size, false);
    *GET_FOOTER_P(block_ptr) = PACK(new_size, false);
    block_ptr->next = NULL;
    block_ptr->prev = NULL;
    remove_block(next_blk, bin_index(next_size));
    insert_block(block_ptr, bin_index(new_size));
    dbg_unregister_block(next_blk);
    dbg_unregister_block(block_ptr);
    dbg_register_block(__LINE__, block_ptr, true);

  } else if (!GET_ALLOC(next_header) && !GET_ALLOC(prev_footer)) {
    /* Case 4: both blocks are free */
    block_t *prev_blk = GET_LHEADER_P(block_ptr);
    block_t *next_blk = GET_RHEADER_P(block_ptr);
    size_t prev_size = GET_SIZE(prev_blk->header);
    size_t next_size = GET_SIZE(next_blk->header);

    /* the combined size = previous block size + header and footer +
            current block size +
      header and footer + next block size */
    size_t new_size = prev_size + (sizeof(packed_t) + sizeof(block_t)) * 2 +
                      next_size + GET_SIZE(block_ptr->header);
    *GET_HEADER_P(prev_blk) = PACK(new_size, false);
    *GET_FOOTER_P(prev_blk) = PACK(new_size, false);
    remove_block(prev_blk, bin_index(prev_size));
    remove_block(next_blk, bin_index(next_size));
    insert_block(prev_blk, bin_index(new_size));
    dbg_unregister_block(prev_blk);
    dbg_unregister_block(next_blk);
    dbg_unregister_block(block_ptr);
    dbg_register_block(__LINE__, prev_blk, true);

  } else {
    ASSERT(false, "Invalid block state");
    exit(1);
  }
  return;
}

/* insert a free block into the corresponding bin free list*/
static void insert_block(block_t *block, size_t bin_idx) {
  // dbg_printf("Inserting into bin %zu\n", bin_idx);
  block->next = bins[bin_idx].head;
  block->prev = NULL;
  if (bins[bin_idx].head != NULL) {
    bins[bin_idx].head->prev = block;
  }
  bins[bin_idx].head = block;
}

/*
remove a block from the corresponding bin free list
have to make sure its actually **in** the list
*/
static void remove_block(block_t *block, size_t bin_idx) {
  // dbg_printf("Removing from bin %zu\n", bin_idx);
  if (block->prev) {
    block->prev->next = block->next;
  } else {
    bins[bin_idx].head = block->next;
  }
  if (block->next) {
    block->next->prev = block->prev;
  }
  block->next = NULL;
  block->prev = NULL;
}

/* register a block to side note */
static void dbg_register_block(int lineno, block_t *block, bool is_free) {
#ifdef DEBUG
	/* disable protection */
	if (dbg_blk_entries_idx >= DBG_BLK_ENTRIES_MAX)
	  return;
	/* register the block */
  for (size_t i = 0; i < dbg_blk_entries_idx; i++) {
    if (!dbg_blk_entries[i].is_used) {
      dbg_blk_entries[i].blk_ptr = block;
      dbg_blk_entries[i].is_free = is_free;
      dbg_blk_entries[i].is_used = true;
      return;
    }
  }
  dbg_blk_entries[dbg_blk_entries_idx].blk_ptr = block;
  dbg_blk_entries[dbg_blk_entries_idx].is_free = is_free;
  dbg_blk_entries[dbg_blk_entries_idx].is_used = true;
  dbg_blk_entries_idx++;
#endif
}

/* delete registered block from side note*/
static void dbg_unregister_block(block_t *block) {
#ifdef DEBUG
	/* disable protection */
	if (dbg_blk_entries_idx >= DBG_BLK_ENTRIES_MAX)
	  return;
	/* unregister the block */
  for (size_t i = 0; i < dbg_blk_entries_idx; i++) {
    if (dbg_blk_entries[i].blk_ptr == block) {
      dbg_blk_entries[i].is_used = false;
      break;
    }
  }
#endif
}

/* log a trace entry */
static void dbg_log_trace(int lineno, enum dbg_op_type op, size_t size,
                          void *ptr, block_t *blk_ptr) {
#ifdef DEBUG
	/* disable protection */
	if (dbg_trace_entries_idx >= DBG_TRACE_ENTRIES_MAX)
	  return;
	/* log the trace entry */
  dbg_trace_entries[dbg_trace_entries_idx].lineno = lineno;
  dbg_trace_entries[dbg_trace_entries_idx].op = op;
  dbg_trace_entries[dbg_trace_entries_idx].size = size;
  dbg_trace_entries[dbg_trace_entries_idx].ptr = ptr;
  dbg_trace_entries[dbg_trace_entries_idx].blk_ptr = blk_ptr;
  dbg_trace_entries_idx++;
#endif
}