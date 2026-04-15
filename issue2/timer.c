#include "timer.h"
#define NULL 0

tSWTimers gSWTimers[2] = {
    {portDepSwTimerListP1, NULL, PORT_NUMS1},
    {portDepSwTimerListP2, NULL, PORT_NUMS2},
};

void StartTimer(int x, int y, func_ptr handlerFunction)
{
    tTimerElement *insert;
    insert = &gSWTimers[0].timerList[y];
    insert->timerVal = x;
    insert->fp.handlerFunc1 = handlerFunction;
    insert->next = NULL;
}
void TimerIntHandler()
{
    tTimerElement *current;
    current = gSWTimers[0].head;
    tfp fps[2];
    for (int i = 0; i < 10; i++)
    {
        fps[i] = current->fp;
        if (current != NULL)
        {
            gSWTimers[i].head = current->next;
            fps[i].handlerFunc1();
        }
        else
        {
            fps[i].handlerFunc1();
        }
    }
}

void handlerFunc1(void) {}
void handlerFunc2(void) {}
int main()
{
    StartTimer(10, 0, handlerFunc1);
    StartTimer(20, 1, handlerFunc2);
    TimerIntHandler();
    return 0;
}