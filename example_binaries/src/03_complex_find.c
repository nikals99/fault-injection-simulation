#include <stdio.h>

int main()
{
    printf("Starting ...");
    int* target = (int*)0x1FE;
    int value = *target;

    int result = 0x1234;
    int* resultPointer = (int*)0xCFE;

    if(value == 0x12345678) {
        result = 0x5678;
    }

    *resultPointer = result;
}
