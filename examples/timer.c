#include "timer.h"
#include <string.h>

#define NULL 0

/* Handlers */
void H1(int portID) {}
void H2(void) {}

/* Global */
tSWTimers gSWTimers[2] = {
    {portDepSwTimerListP1, NULL, PORT_NUM},
    {portDepSwTimerListP2, NULL, PORT_NUMD},
};

/* StartTimer uses memcpy INTO GLOBAL */
void StartTimer(int x, int y, tfp handlerFunction)
{
    tTimerElement *insert;

    insert = &gSWTimers[0].timerList[y];

    insert->timerVal = x;

    /* 🔥 memcpy into global union field */
    memcpy(&insert->fp, &handlerFunction, sizeof(tfp));

    insert->next = NULL;

    gSWTimers[0].head = insert;
}
void a()
{
    tfp fp;
    fp.handlerFunc1 = H1;
    StartTimer(2, 3, fp);
}
/* Handler reads from global */
void TimerHandler()
{
    tTimerElement *current;
    current = gSWTimers[0].head;

    if (current != NULL)
    {
        /* 🔥 read from global */
        current->fp.handlerFunc1(0);
    }
    else
    {
        tfp tmp;
        tmp.handlerFunc2 = H2;

        /* 🔥 memcpy into global head element */
        memcpy(&gSWTimers[0].timerList[0].fp, &tmp, sizeof(tfp));

        gSWTimers[0].timerList[0].fp.handlerFunc2();
    }
}