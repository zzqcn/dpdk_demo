#include <rte_common.h>
#include <rte_malloc.h>
#include "hlib_stack.h"

int HLIB_Stack_Init(HLIB_Stack_t* s, uint32_t count)
{
    if(NULL == s || count < 1)
        return -1;

    s->data = (void*) malloc(sizeof(void*) * count);
    if(NULL == s->data)
        return -1;
    s->size = count;
    s->top = 0;

    return 0;
}

int HLIB_Stack_Init2(HLIB_Stack_t* s, uint32_t count, int socket_id)
{
    if(NULL == s || count < 1)
        return -1;

    s->data = (void*) rte_zmalloc_socket(NULL, sizeof(void*) * count,
            RTE_CACHE_LINE_SIZE, socket_id);
    if(NULL == s->data)
        return -1;
    s->size = count;
    s->top = 0;

    return 0;
}

int HLIB_Stack_Fini(HLIB_Stack_t* s)
{
    if(NULL == s || NULL == s->data)
        return -1;
    free(s->data);
    return 0;
}

void HLIB_Stack_Dump(FILE* f, const HLIB_Stack_t* s)
{
    if(NULL == f || NULL == s)
        return;

    fprintf(f, "size: %u\n", s->size);
    fprintf(f, "top: %u\n", s->top);
    fprintf(f, "data addr: %p\n", s->data);
}


