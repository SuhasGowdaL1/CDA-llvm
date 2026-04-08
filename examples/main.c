#include <stdio.h>
#include "vdm.h"

int test(int port, int i, int x)
{

    return aVdm(port)[i].vdmHandler(x); // 🔥 TARGET PATTERN
}
int test2(int port, int i, int x)
{
    const VdmEntry *entry = &aVdm(port)[i];

    return entry->vdmHandler(x); // same pattern via pointer
}
int main()
{
    test(0, 1, 5);
    return 0;
}