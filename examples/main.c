#include <stdio.h>

typedef int (*func1)(int);

int A(int x) { return x + 1; }
int B(int x) { return x + 2; }

int test8(int x)
{
    func1 f = A;

    int r1 = f(x); // calls A

    f = B;

    int r2 = f(x); // calls B

    return r1 + r2;
}