#include "lib_syscall.h"
#include <stdlib.h>

int main(int argc, char **argv);

extern uint8_t __bss_start__[], __bss_end__[];

/**
 * @brief 应用的初始化
 */
void cstart(int argc, char **argv)
{
    uint8_t *start = __bss_start__;
    while (start < __bss_end__)
    {
        *start++ = 0;
    }

    exit(main(argc, argv));
}