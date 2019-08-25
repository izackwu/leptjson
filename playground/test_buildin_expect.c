#include <stdio.h> /* atoi, rand */
#include <time.h> /* time, clock */
#include <stdlib.h> /* rand, srand */
#include <math.h> /* sqrt, abs, pow */

#define LIKELY(x) __builtin_expect(!!(x), 1) /* x is very likely to be true */
#define UNLIKELY(x) __builtin_expect(!!(x), 0) /* x is very likely to be false */

#define DEFAULT_N  1000000

void without_buildin_expect(int n)
{
    clock_t before = clock();
    int i, bias, useless;
    for(i = 0, bias = 0; i != n; ++i){
        if(rand() + 123 < RAND_MAX / 100){
            ++bias;
            useless += sqrt(abs(bias));
            useless -= pow(abs(bias), 3);
        }else{
            --bias;
            useless -= sqrt(abs(bias));
            useless += pow(abs(bias), 3);
        }
    }
    printf("Without __buildin_expect: %d ms. (%d iterations and %d bias)\n",
        (clock() - before) * 1000 / CLOCKS_PER_SEC, n, bias); 
}

void with_buildin_expect(int n)
{
    clock_t before = clock();
    int i, bias, useless;
    for(i = 0, bias = 0; i != n; ++i){
        if(UNLIKELY(rand() + 123 < RAND_MAX / 100)){
            ++bias;
            useless += sqrt(abs(bias));
            useless -= pow(abs(bias), 3);
        }else{
            --bias;
            useless -= sqrt(abs(bias));
            useless += pow(abs(bias), 3);
        }
    }
    printf("With __buildin_expect: %d ms. (%d iterations and %d bias)\n",
        (clock() - before) * 1000 / CLOCKS_PER_SEC, n, bias); 
}

int main(int argc, char const *argv[])
{
    int n;
    if(argc == 1){
        n = DEFAULT_N;
    }else if(argc == 2){
        n = atoi(argv[1]);
        n = (n <= 0 ? DEFAULT_N : n);
    }else{
        printf("Too many arguments applied!\n");
        return 0;
    }
    srand(time(0));
    without_buildin_expect(n);
    with_buildin_expect(n);
    return 0;
}
