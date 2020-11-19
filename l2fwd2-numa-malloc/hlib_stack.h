#ifndef __HLIB_STACK_H__
#define __HLIB_STACK_H__

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief 通用栈.
 */
typedef struct 
{
    void** data;    /**< 存储空间 */
    uint32_t top;   /**< 栈顶 */
    uint32_t size;  /**< 栈大小 */
} HLIB_Stack_t;

int HLIB_Stack_Init(HLIB_Stack_t* s, uint32_t count);
int HLIB_Stack_Init2(HLIB_Stack_t* s, uint32_t count, int socket_id);
int HLIB_Stack_Fini(HLIB_Stack_t* s);
void HLIB_Stack_Dump(FILE* f, const HLIB_Stack_t* s);

static inline int
 HLIB_Stack_Push(HLIB_Stack_t* s, void* obj)
{
    if(s->top >= s->size)
        return -1;

    s->data[s->top] = obj;
    s->top++;
    return 0;
}

static inline void*
HLIB_Stack_Pop(HLIB_Stack_t* s)
{
    if(0 == s->top)
        return NULL;

    s->top--;
    return s->data[s->top];
}

    
#ifdef __cplusplus
}
#endif

#endif

