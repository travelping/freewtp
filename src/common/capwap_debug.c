#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef USE_DEBUG_BACKTRACE
#include <execinfo.h>
#endif

#include "capwap_logging.h"
#include "capwap_error.h"

#define BACKTRACE_BUFFER		256

/* Memory block */
struct capwap_memory_block {
	void* item;
	size_t size;
	const char* file;
	int line;
#ifdef USE_DEBUG_BACKTRACE
	void* backtrace[BACKTRACE_BUFFER];
	int backtrace_count;
#endif
	struct capwap_memory_block* next;
};

static struct capwap_memory_block* g_memoryblocks = NULL;

/* Alloc memory block */
void* capwap_alloc_debug(size_t size, const char* file, const int line) {
	struct capwap_memory_block* block;

	/* Request size > 0 */
	if (size <= 0) {
		capwap_logging_debug("%s(%d): Invalid memory size %d", file, line, size);
		exit(CAPWAP_ASSERT_CONDITION);
	}

	/* Alloc block with memory block */
	block = (struct capwap_memory_block*)malloc(sizeof(struct capwap_memory_block) + size);
	if (!block) {
		capwap_logging_debug("Out of memory %s(%d)", file, line);
		exit(CAPWAP_OUT_OF_MEMORY);
	}

	/* Info memory block */
	block->item = (void*)(((char*)block) + sizeof(struct capwap_memory_block));
	block->size = size;
	block->file = file;
	block->line = line;
#ifdef USE_DEBUG_BACKTRACE
	block->backtrace_count = backtrace(block->backtrace, BACKTRACE_BUFFER);
#endif
	block->next = g_memoryblocks;

	g_memoryblocks = block;

	return block->item;
}

/* Free memory block */
void capwap_free_debug(void* p, const char* file, const int line) {
	struct capwap_memory_block* block;
	struct capwap_memory_block* findblock;
	struct capwap_memory_block* prevblock;

	if (!p) {
		capwap_logging_debug("%s(%d): Free NULL pointer", file, line);
		exit(CAPWAP_ASSERT_CONDITION);
	}

	/* Memory block */
	if ((size_t)p <= sizeof(struct capwap_memory_block)) {
		capwap_logging_debug("%s(%d): Invalid pointer", file, line);
		exit(CAPWAP_ASSERT_CONDITION);
	}

	block = (struct capwap_memory_block*)((char*)p - sizeof(struct capwap_memory_block));
	if (block->item != p) {
		capwap_logging_debug("%s(%d): Invalid pointer", file, line);
		exit(CAPWAP_ASSERT_CONDITION);
	}

	/* Find memory block */
	prevblock = NULL;
	findblock = g_memoryblocks;
	while (findblock != NULL) {
		if (findblock == block) {
			if (!prevblock) {
				g_memoryblocks = block->next;
			} else {
				prevblock->next = block->next;
			}

			/* Invalidate block */
			memset(block, 0, sizeof(struct capwap_memory_block));
			free(block);
			return;
		}

		/* Next */
		prevblock = findblock;
		findblock = findblock->next;
	}
	
	capwap_logging_debug("%s(%d): Unable to find memory block", file, line);
}

/* Dump memory alloced */
void capwap_dump_memory(void) {
#ifdef USE_DEBUG_BACKTRACE
	char** backtrace_functions;
#endif
	struct capwap_memory_block* findblock;

	findblock = g_memoryblocks;
	while (findblock != NULL) {
		capwap_logging_debug("%s(%d): block at %p, %d bytes long", findblock->file, findblock->line, findblock->item, findblock->size);

#ifdef USE_DEBUG_BACKTRACE
		backtrace_functions = backtrace_symbols(findblock->backtrace, findblock->backtrace_count);
		if (backtrace_functions) {
			int j;

			/* Skipping capwap_alloc_debug function print out */
			for (j = 1; j < findblock->backtrace_count; j++) {
				capwap_logging_debug("\t%s", backtrace_functions[j]);
			}

			free(backtrace_functions);
		}
#endif

		/* Next */
		findblock = findblock->next;
	}
}

/* Check if all memory is free */
int capwap_check_memory_leak(int verbose) {
	if ((g_memoryblocks != NULL) && (verbose != 0)) {
		capwap_logging_debug("*** Detected memory leaks ! ***");
		capwap_dump_memory();
		capwap_logging_debug("*******************************");
	}

	return ((g_memoryblocks != NULL) ? 1 : 0);
}

/* Backtrace call stack */
#ifdef USE_DEBUG_BACKTRACE
void capwap_backtrace_callstack(void) {
	int i;
	int count;
	char** functions;
	void* buffer[BACKTRACE_BUFFER];

	/* */
	count = backtrace(buffer, BACKTRACE_BUFFER);
	if (count) {
		functions = backtrace_symbols(buffer, count);
		if (functions) {

			/* Skipping capwap_backtrace_callstack function print out */
			for (i = 1; i < count; i++) {
				capwap_logging_debug("\t%s", functions[i]);
			}

			free(functions);
		}
	}
}
#endif
