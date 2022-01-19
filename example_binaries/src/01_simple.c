#include <stdio.h>

int main()
{
    printf("Starting ...");
    int* target = (int*)0x1FE;
    int value = *target;

    if(value == 0x12345678) {
        printf("CRP1");
    } else if(value == 0x87654321) {
        printf("CRP2");
    } else {
        printf("CRP disabled");
    }
}
