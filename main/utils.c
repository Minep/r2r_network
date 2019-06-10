#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include "include/utils.h"


uint32_t fnv1a_hash(const unsigned char* cp)
{
    uint32_t hash = 0x811c9dc5;
    while (*cp) {
        hash ^= *cp++;
        hash *= 0x01000193;
    }
    return hash;
}

void print_formated_hex(uint8_t* data, size_t len, int max_col)
{
    for(int i=0;i<len;i++)
    {
        printf("0x%02x ",*(data+i));
        if((i+1)%max_col==0 && i>0)
        {
            printf("\r\n");
        }
    }
    printf("\r\n");
}
char *int2bin(uint8_t a, char *buffer, int buf_size) {
    buffer += (buf_size - 1);

    for (int i = sizeof(uint8_t)-1; i >= 0; i--) {
        *buffer-- = (a & 1) + '0';

        a >>= 1;
    }

    return buffer;
}