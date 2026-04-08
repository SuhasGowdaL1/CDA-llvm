#include <stdio.h>
#include "vdm.h"

int test(int port, int i, int x)
{
    return aVdm(port)[i].vdmHandler(x); // 🔥 TARGET PATTERN
}

int main()
{
    test(0, 1, 5);
    return 0;
}