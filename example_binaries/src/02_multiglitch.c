#include <stdio.h>

int main()
{
    printf("Starting ...");
    int* target = (int*)0x1FE;
    int value = *target;

    int* target2 = (int*)0x2FE;
    int value2 = *target2;

    if(value == 0x12345678) {
        printf("Reached step 1");
        if(value2 == 0x12345678) {
            printf("Reached Step 2");
        }
    }
}
