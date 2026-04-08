#include <stdio.h>
#include "types.h"

/* External array */
extern const AEntry a[3];

int test(int c, int x)
{
    return a[b(c).d]
        .e(x); // 🔥 EXACT PATTERN
}

int main()
{
    test(2, 5);
    return 0;
}