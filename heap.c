#include "heap.h"
#include "tested_declarations.h"
#include "rdebug.h"

struct memory_manager_t memory_manager;


int calculate_sum(struct memory_chunk_t* ptr){
    int s=0;
    if(ptr->next != NULL)
        s+=(intptr_t)ptr->next%5;
    if(ptr->prev != NULL)
        s+=(intptr_t)ptr->prev%5;
    s+=ptr->free;
    s+=ptr->size%5;
    return s;
}
void sum_update(){
    struct memory_chunk_t* tmp = memory_manager.first_memory_chunk;
    while(tmp){
        tmp->control_sum = calculate_sum(tmp);
        tmp=tmp->next;
    }
}



int heap_setup(void){
    memory_manager.memory_start = custom_sbrk(0);
    void* f = custom_sbrk(HEAP_SIZE);
    if(f == NULL)
        return -1;
    memory_manager.memory_size = HEAP_SIZE;
    memory_manager.first_memory_chunk = NULL;
    return 0;
}

void heap_clean(void){
    custom_sbrk(-memory_manager.memory_size);
    memory_manager.first_memory_chunk = NULL;
    memory_manager.memory_start = NULL;
    memory_manager.memory_size = 0;
}
int heap_validate(void){
    if(memory_manager.memory_start == NULL)
        return 2;
    struct memory_chunk_t* pcurrent = memory_manager.first_memory_chunk;
    int c_sum;

    while (pcurrent){
        c_sum= calculate_sum(pcurrent);
        if(c_sum != pcurrent->control_sum || pcurrent->size > 100000000)
            return 3;
        if(pcurrent->free == 1){
            pcurrent=pcurrent->next;
            continue;
        }


        void *ret = (char*)pcurrent+ CHUNK_SIZE;
        for(int i=0;i<FENCE_SIZE;i++){
            ret = (char*)pcurrent + CHUNK_SIZE + i;
            if(memchr(ret,0,1) == NULL)
                return 1;
        }

        for(int i=0;i<FENCE_SIZE;i++){
            ret = (char*)pcurrent + CHUNK_SIZE + FENCE_SIZE + pcurrent->size + i;
            if(memchr(ret,0,1) == NULL)
                return 1;
        }
        pcurrent=pcurrent->next;
    }
    return 0;
}

void* heap_malloc(size_t size){
    if(size == 0)
        return NULL;

    if(memory_manager.first_memory_chunk == NULL){
        size_t total_size = size + FENCE_SIZE*2 + CHUNK_SIZE;
        if(memory_manager.memory_size < total_size){
            void *f  = custom_sbrk(total_size - memory_manager.memory_size +4096);
            if(f == (void*)-1)
                return NULL;
            memory_manager.memory_size+=(total_size - memory_manager.memory_size);
        }
        memory_manager.first_memory_chunk = (struct memory_chunk_t*)(memory_manager.memory_start);
        memory_manager.first_memory_chunk->size = size;
        memory_manager.first_memory_chunk->prev = NULL;
        memory_manager.first_memory_chunk->next = NULL;
        memory_manager.first_memory_chunk->free = 0;

        void *ret = (char*)memory_manager.first_memory_chunk + CHUNK_SIZE;
        for(int i=0;i<FENCE_SIZE;i++){
            ret = (char*)memory_manager.first_memory_chunk + CHUNK_SIZE + i;
            memset(ret,0,1);
        }
        ret = (char*)memory_manager.first_memory_chunk + CHUNK_SIZE + FENCE_SIZE+size;
        for(int i=0;i<FENCE_SIZE;i++){
            ret = (char*)memory_manager.first_memory_chunk + CHUNK_SIZE + FENCE_SIZE+size+ i;
            memset(ret,0,1);
        }
        ret = (char*)memory_manager.first_memory_chunk + CHUNK_SIZE + FENCE_SIZE;
        sum_update();
        return ret;
    }
    int already_existed=0;
    struct memory_chunk_t* pcurrent = memory_manager.first_memory_chunk; // pcurrent -> za tym alokacja
    if(pcurrent->free == 1 && size + 2*FENCE_SIZE <= pcurrent->size)
        already_existed=2;
    else{
        while (pcurrent->next != NULL) {
            if(pcurrent->next != NULL){
                if (pcurrent->next->free == 1 && size + 2 * FENCE_SIZE <= pcurrent->next->size) {
                    already_existed = 1;
                    break;
                }
            }
            pcurrent = pcurrent->next;
        }
    }
    if(already_existed != 0){ // alokacja w bloku free==1
        if(already_existed == 1)
            pcurrent=pcurrent->next;

        pcurrent->free=0;
        pcurrent->size=size;
        pcurrent->control_sum = calculate_sum(pcurrent);

        void *ret = (char*)pcurrent+ CHUNK_SIZE;
        for(int i=0;i<FENCE_SIZE;i++){
            ret = (char*)pcurrent + CHUNK_SIZE + i;
            memset(ret,0,1);
        }
        ret = (char *) pcurrent + CHUNK_SIZE + FENCE_SIZE+size;
        for(int i=0;i<FENCE_SIZE;i++){
            ret = (char*)pcurrent + CHUNK_SIZE + FENCE_SIZE + size+ i;
            memset(ret,0,1);
        }
        ret = (char *) pcurrent + CHUNK_SIZE + FENCE_SIZE;
        sum_update();
        return ret;
    }
    uint64_t pom = (uint64_t) pcurrent - (uint64_t ) memory_manager.first_memory_chunk;
    int64_t x = memory_manager.memory_size - pom - pcurrent->size - CHUNK_SIZE - 4 * FENCE_SIZE;
    if(x < (int64_t) size){
        size_t total_size = size + FENCE_SIZE*2 + CHUNK_SIZE;
        if(custom_sbrk(total_size - memory_manager.memory_size) == (void*)-1)
            return NULL;
        memory_manager.memory_size+=(total_size - memory_manager.memory_size);
    }

    struct memory_chunk_t* new = (struct memory_chunk_t*)((char*)pcurrent + pcurrent->size + CHUNK_SIZE + 2 * FENCE_SIZE);
    new->prev = pcurrent;
    new->next = NULL;
    new->size = size;
    new->free = 0;
    pcurrent->next = new;
    pcurrent->control_sum = calculate_sum(pcurrent);
    new->control_sum = calculate_sum(new);

    void *ret = (char*)new + CHUNK_SIZE;

    for(int i=0;i<FENCE_SIZE;i++){
        ret = (char*)new + CHUNK_SIZE + i;
        memset(ret,0,1);
    }
    ret = (char*)new + CHUNK_SIZE + FENCE_SIZE+size;
    for(int i=0;i<FENCE_SIZE;i++){
        ret = (char*)new + CHUNK_SIZE+ FENCE_SIZE+size + i;
        memset(ret,0,1);
    }
    ret = (char*)new + CHUNK_SIZE + FENCE_SIZE;
    sum_update();
    return ret;
}
void* heap_calloc(size_t number, size_t size){
    if(size == 0 || number == 0)
        return NULL;
    void* ptr =  heap_malloc(number*size);
    if(ptr == NULL)
        return NULL;
    memset(ptr,0,number*size);
    sum_update();
    return ptr;
}
void* heap_realloc(void* memblock, size_t count){
    if(memory_manager.memory_start == NULL)
        return NULL;
    if(memblock == NULL)
        return heap_malloc(count);
    struct memory_chunk_t* pcurrent = memory_manager.first_memory_chunk;
    struct memory_chunk_t* pom = (struct memory_chunk_t*)((char*)pcurrent + CHUNK_SIZE + FENCE_SIZE);
    while (pom != memblock){
        if(pcurrent == NULL)
            return NULL;
        pcurrent=pcurrent->next;
        pom = (struct memory_chunk_t*)((char*)pcurrent + CHUNK_SIZE + FENCE_SIZE);
    }
    if(count == 0){
        pcurrent->free = 1;
        pcurrent->control_sum = calculate_sum(pcurrent);
        sum_update();
        return NULL;
    }
    if(count <= pcurrent->size){
        pcurrent->size = count;

        void *ptr;
        for(int i=0;i<FENCE_SIZE;i++){
            ptr = (char*)pcurrent + CHUNK_SIZE + FENCE_SIZE + pcurrent->size+i;
            memset(ptr,0,1);
        }
        sum_update();
        return memblock;
    }
    size_t diff = count - pcurrent->size;
    if(pcurrent->next == NULL){
        if((char*)pcurrent - (char*)memory_manager.memory_start + diff + CHUNK_SIZE + 2*FENCE_SIZE >= memory_manager.memory_size){
            void* f = custom_sbrk(diff);
            if(f == (void*)-1){
                sum_update();
                return NULL;
            }

            memory_manager.memory_size+=diff;
        }
        pcurrent->size+=diff;
        pcurrent->control_sum = calculate_sum(pcurrent);
        for(int i=0;i<FENCE_SIZE;i++){
            void *ptr = (char*)pcurrent + CHUNK_SIZE + FENCE_SIZE + pcurrent->size+i;
            memset(ptr,0,1);
        }

        sum_update();
        return memblock;

    }
    if(pcurrent->next->free == 1 && diff <= pcurrent->next->size + CHUNK_SIZE){
        pcurrent->size+=diff;
        pcurrent->next=pcurrent->next->next;
        if(pcurrent->next != NULL && pcurrent->next->prev != NULL && pcurrent->next->prev->prev != NULL && pcurrent->next->prev->prev == pcurrent)
            pcurrent->prev = NULL;
        else if(pcurrent->next != NULL && pcurrent->next->prev != NULL && pcurrent->next->prev->prev != NULL)
            pcurrent->prev=pcurrent->next->prev->prev;
        if(pcurrent->next != NULL)
            pcurrent->next->prev = pcurrent;
        if(pcurrent->prev != NULL)
            pcurrent->prev->next = pcurrent;
        for(int i=0;i<FENCE_SIZE;i++){
            void *ptr = (char*)pcurrent + CHUNK_SIZE + FENCE_SIZE + pcurrent->size+i;
            memset(ptr,0,1);
        }

        sum_update();
        return memblock;
    }
    else{
        void* r= heap_malloc(count);
        if(r == NULL)
            return NULL;
        memcpy(r,memblock,pcurrent->size);
        pcurrent->free=1;
        pcurrent->control_sum= calculate_sum(pcurrent);
        return r;
    }
    return NULL;
}



void  heap_free(void* memblock){
    if(memblock == NULL || heap_validate() != 0)
        return;
    struct memory_chunk_t* pcurrent = memory_manager.first_memory_chunk;

    struct memory_chunk_t* pom = (struct memory_chunk_t*)((uint8_t*)memory_manager.first_memory_chunk + CHUNK_SIZE + FENCE_SIZE);
    while(pom != memblock && pcurrent != NULL){
        pcurrent = pcurrent->next;
        pom = (struct memory_chunk_t*)((uint8_t*)pcurrent + CHUNK_SIZE + FENCE_SIZE);
    }
    if(pcurrent == NULL || pcurrent->free == 1)
        return;

    size_t free_size=0;
    struct memory_chunk_t* new_ptr;
    struct memory_chunk_t* temp1;
    struct memory_chunk_t* temp2;

    if(pcurrent->free == 1)
        return;
    if(pcurrent->next == NULL){
        if(pcurrent->prev == NULL){
            memory_manager.first_memory_chunk = NULL;
        }
        else{
            pcurrent->prev->next = NULL;
        }
        sum_update();
        return;
    }
    if(pcurrent->next != NULL && pcurrent->prev != NULL && pcurrent->next->free == 1 && pcurrent->prev->free == 1){ // posrodku wolnych
        if(pcurrent->next->next == NULL){
            if(pcurrent->prev->prev == NULL)
                memory_manager.first_memory_chunk = NULL;
            else
                pcurrent->prev->prev->next=NULL;
            sum_update();
            return;
        }
        if(pcurrent->prev->prev == NULL){
            pcurrent->next->next->prev = memory_manager.first_memory_chunk;
            free_size = (size_t)((char*)pcurrent->next->next - (char*)memory_manager.memory_start) - CHUNK_SIZE;

            memory_manager.first_memory_chunk = (struct memory_chunk_t *)((char*)memory_manager.memory_start);
            memory_manager.first_memory_chunk->next = pcurrent->next->next;
            memory_manager.first_memory_chunk->prev=NULL;
            memory_manager.first_memory_chunk->free=1;
            memory_manager.first_memory_chunk->size = free_size;
        }
        else{
            free_size = (size_t)((char*)pcurrent->next->next - (char*)pcurrent->prev->prev) - pcurrent->prev->prev->size - CHUNK_SIZE - 2*FENCE_SIZE;

            temp1 = pcurrent->prev->prev;
            temp2 = pcurrent->next->next;

            new_ptr = (struct memory_chunk_t *)((char*)pcurrent->prev->prev + pcurrent->prev->prev->size + CHUNK_SIZE + 2*FENCE_SIZE);
            //pcurrent->prev->prev->next = new_ptr;
            //pcurrent->next->next->prev = new_ptr;
            new_ptr->next = temp2;
            new_ptr->prev = temp1;
            new_ptr->size = free_size;
            new_ptr->free = 1;

            temp1->next = new_ptr;
            temp2->prev = new_ptr;

        }
    }
    else if(pcurrent->next != NULL && pcurrent->next->free == 1){ // next jest wolny
        if(pcurrent->next->next == NULL && pcurrent == memory_manager.first_memory_chunk){
            memory_manager.first_memory_chunk = NULL;
            sum_update();
            return;
        }
        if(pcurrent->prev == NULL){
            pcurrent->next->next->prev = memory_manager.first_memory_chunk;
            free_size = (size_t)((char*)pcurrent->next->next - (char*)memory_manager.memory_start)- CHUNK_SIZE;

            memory_manager.first_memory_chunk = (struct memory_chunk_t *)((char*)memory_manager.memory_start);
            memory_manager.first_memory_chunk->next = pcurrent->next->next;
            memory_manager.first_memory_chunk->prev=NULL;
            memory_manager.first_memory_chunk->free=1;
            memory_manager.first_memory_chunk->size = free_size;
        }
        else{
            free_size = (size_t)((char*)pcurrent->next->next - (char*)pcurrent->prev) - pcurrent->prev->size - CHUNK_SIZE - 2*FENCE_SIZE;

            temp1 = pcurrent->prev;
            temp2 = pcurrent->next->next;

            new_ptr = (struct memory_chunk_t *)((char*)pcurrent->prev + pcurrent->prev->size + CHUNK_SIZE + 2*FENCE_SIZE);
            //pcurrent->prev->next = new_ptr;
            //pcurrent->next->next->prev = new_ptr;
            new_ptr->next = temp2;
            new_ptr->prev = temp1;
            new_ptr->size = free_size;
            new_ptr->free = 1;
            temp1->next = new_ptr;
            temp2->prev = new_ptr;

        }
    }
    else if(pcurrent->prev != NULL && pcurrent->prev->free == 1){ // prev jest wolny
        if(pcurrent->next == NULL){
            if(pcurrent->prev == memory_manager.first_memory_chunk){
                memory_manager.first_memory_chunk = NULL;
            }
            else{
                pcurrent->prev->prev->next = NULL;
            }
            sum_update();
            return;
        }

        if(pcurrent->prev->prev == NULL){
            pcurrent->next->prev = memory_manager.first_memory_chunk;
            free_size = (size_t)((char*)pcurrent->next - (char*)memory_manager.memory_start)- CHUNK_SIZE;

            memory_manager.first_memory_chunk = (struct memory_chunk_t *)((char*)memory_manager.memory_start);
            memory_manager.first_memory_chunk->next = pcurrent->next;
            memory_manager.first_memory_chunk->prev=NULL;
            memory_manager.first_memory_chunk->free=1;
            memory_manager.first_memory_chunk->size = free_size;
        }
        else{
            free_size = (size_t)((char*)pcurrent->next - (char*)pcurrent->prev->prev) - pcurrent->prev->prev->size - 2*CHUNK_SIZE - 2*FENCE_SIZE;

            temp1 = pcurrent->prev->prev;
            temp2 = pcurrent->next;

            new_ptr = (struct memory_chunk_t *)((char*)pcurrent->prev->prev + pcurrent->prev->prev->size + CHUNK_SIZE + 2*FENCE_SIZE);
            //pcurrent->prev->prev->next = new_ptr;
            //pcurrent->next->prev = new_ptr;
            new_ptr->next = temp2;
            new_ptr->prev = temp1;
            new_ptr->size = free_size;
            new_ptr->free = 1;
            temp1->next = new_ptr;
            temp2->prev = new_ptr;
        }
    }
    else{
        if(pcurrent->next == NULL && pcurrent == memory_manager.first_memory_chunk){
            memory_manager.first_memory_chunk = NULL;
            sum_update();
            return;
        }

        if(pcurrent->prev == NULL){
            pcurrent->next->prev = memory_manager.first_memory_chunk;
            free_size = (size_t)((char*)pcurrent->next - (char*)memory_manager.memory_start) - CHUNK_SIZE;

            memory_manager.first_memory_chunk = (struct memory_chunk_t *)((char*)memory_manager.memory_start);
            memory_manager.first_memory_chunk->next = pcurrent->next;
            memory_manager.first_memory_chunk->prev=NULL;
            memory_manager.first_memory_chunk->free=1;
            memory_manager.first_memory_chunk->size = free_size;
        }
        else{
            free_size = (size_t)((char*)pcurrent->next - (char*)pcurrent->prev) - pcurrent->prev->size - 2*CHUNK_SIZE - 2*FENCE_SIZE;

            temp1 = pcurrent->prev;
            temp2 = pcurrent->next;

            new_ptr = (struct memory_chunk_t *)((char*)pcurrent->prev + pcurrent->prev->size + CHUNK_SIZE + 2*FENCE_SIZE);
            new_ptr->next = temp2;
            new_ptr->prev = temp1;
            new_ptr->size = free_size;
            new_ptr->free = 1;

            temp1->next = new_ptr;
            temp2->prev = new_ptr;
        }
    }

    sum_update();

}

size_t heap_get_largest_used_block_size(void){
    if(heap_validate() != 0 || memory_manager.first_memory_chunk == NULL)
        return 0;
    struct memory_chunk_t *pcurrent = memory_manager.first_memory_chunk;
    size_t max = 0;

    while (pcurrent){
        if(pcurrent->size > max && pcurrent->free == 0)
            max = pcurrent->size;
        pcurrent=pcurrent->next;
    }
    return max;
}
enum pointer_type_t get_pointer_type(const void* const pointer){
    if (pointer == NULL)
        return pointer_null;
    if(heap_validate() == 1)
        return pointer_heap_corrupted;
    struct memory_chunk_t* pcurrent = memory_manager.first_memory_chunk;
    while(pcurrent){
        if(pointer == (void*)((char*)pcurrent + CHUNK_SIZE + FENCE_SIZE)){
            if(pcurrent->free == 1)
                return pointer_unallocated;
            return pointer_valid;
        }

        if(pointer >= (void*)pcurrent && pointer < (void*)((char*)pcurrent + CHUNK_SIZE)){
            if(pcurrent->free == 1)
                return pointer_unallocated;
            return pointer_control_block;
        }

        if((pointer >= (void*)((char*)pcurrent + CHUNK_SIZE) && pointer < (void*)((char*)pcurrent + CHUNK_SIZE +  FENCE_SIZE)) || (pointer >= (void*)((char*)pcurrent + CHUNK_SIZE + FENCE_SIZE + pcurrent->size) && pointer < (void*)((char*)pcurrent + CHUNK_SIZE +  2*FENCE_SIZE + pcurrent->size))){
            if(pcurrent->free == 1)
                return pointer_unallocated;
            return pointer_inside_fences;
        }

        if((pointer > (void*)((char*)pcurrent + CHUNK_SIZE + FENCE_SIZE) && pointer < (void*)((char*)pcurrent + CHUNK_SIZE +  FENCE_SIZE + pcurrent->size))){
            if(pcurrent->free == 1)
                return pointer_unallocated;
            return pointer_inside_data_block;
        }

        pcurrent = pcurrent->next;
    }
    return pointer_unallocated;
}