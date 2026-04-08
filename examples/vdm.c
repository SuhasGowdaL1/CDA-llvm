#include "types.h"

/* Target functions */
int F0(int x) { return x + 10; }
int F1(int x) { return x + 20; }
int F2(int x) { return x + 30; }

/* Array 'a' */
const AEntry a[3] = {
    {0, F0},
    {1, F1},
    {2, F2}};

/* Return struct with index */
BEntry getB(int x)
{
    BEntry b;

    if (x % 3 == 0)
        b.d = 0;
    else if (x % 3 == 1)
        b.d = 1;
    else
        b.d = 2;

    return b;
}