#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>

#ifndef ALOKATOR_HEAP_H
#define ALOKATOR_HEAP_H

#define CHUNK_SIZE sizeof(struct memory_chunk_t)
#define FENCE_SIZE 1
#define HEAP_SIZE 4096 * 1028

struct memory_manager_t
{
    void *memory_start;
    size_t memory_size;
    struct memory_chunk_t *first_memory_chunk;
};

struct memory_chunk_t
{
    size_t size;
    int free; // 1 - wolny, 0 - zajęty
    int control_sum;
    struct memory_chunk_t* prev;
    struct memory_chunk_t* next;
};

enum pointer_type_t
{
    pointer_null,
    pointer_heap_corrupted,
    pointer_control_block,
    pointer_inside_fences,
    pointer_inside_data_block,
    pointer_unallocated,
    pointer_valid
};

int heap_setup(void);
void heap_clean(void);
int heap_validate(void);

void* heap_malloc(size_t size);
void* heap_calloc(size_t number, size_t size);
void* heap_realloc(void* memblock, size_t count);
void  heap_free(void* memblock);

size_t   heap_get_largest_used_block_size(void);
enum pointer_type_t get_pointer_type(const void* const pointer);

#endif //ALOKATOR_HEAP_H