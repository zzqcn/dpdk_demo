#include <stdio.h>
#include <stdint.h>


const uint32_t SIZE = 16;
const uint32_t MASK = (16-1);

void calc(uint32_t prod, uint32_t cons)
{
    uint32_t used, free;

    printf("prod: %u, cons: %u\n", prod, cons);
    printf("prod_mod: %u, cons_mod: %u\n", prod & MASK, cons & MASK);

    used = (prod - cons) & MASK;
    free = (cons - prod - 1) & MASK;
    printf("used ((prod-cons) & MASK): %u\n", used);
    printf("free ((cons-prod-1) & MASK): %u\n", free);

    used = (prod - cons);
    free = MASK + cons - prod;
    printf("used (prod-cons): %u\n", used);
    printf("free (MASK+cons-prod): %u\n", free);
}

int main(int argc, char** argv)
{
    calc(14u, 3u);
    calc((15u+5u), 9u);

    return 0;
}

