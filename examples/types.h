#ifndef TYPES_H
#define TYPES_H

typedef int (*fp_t)(int);

/* Struct used in final array (a[]) */
typedef struct
{
    int id;
    fp_t e; // function pointer
} AEntry;

/* Struct returned by macro b(c) */
typedef struct
{
    int d; // index into a[]
} BEntry;

/* Macro (wraps function) */
#define b(x) (getB(x))

/* Function returning struct */
BEntry getB(int x);

#endif