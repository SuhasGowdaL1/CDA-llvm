#include "vdm.h"

/* Handlers */
int H0(int x) { return x + 10; }
int H1(int x) { return x + 20; }
int H2(int x) { return x + 30; }

/* Tables for different ports */
static const VdmEntry port0[] = {
    {0, H0},
    {1, H1},
    {2, H2}};

static const VdmEntry port1[] = {
    {0, H1},
    {1, H2},
    {2, H0}};

/* Return table based on port */
const VdmEntry *getVdmTable(int port)
{
    if (port == 0)
        return port0;
    else
        return port1;
}