#ifndef VDM_H
#define VDM_H

typedef int (*vdm_cb)(int);

/* Struct with function pointer */
typedef struct
{
    int id;
    vdm_cb vdmHandler;
} VdmEntry;

/* Function returning pointer to array (per port) */
const VdmEntry *getVdmTable(int port);

/* Macro */
#define aVdm(port) (getVdmTable(port))

#endif