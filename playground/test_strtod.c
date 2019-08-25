#include <stdio.h> /* printf */
#include <stdlib.h> /* strtod */

int main(int argc, char const *argv[])
{
    if(3.1416 != strtod("3.1416", NULL)) {
        printf("NOT EQUAL!\n");
    } else {
        printf("EQUAL.\n");
    }
    return 0;
}
