#include "timer.h"
#define NULL 0

tSWTimers gSWTimers[2] = {
    {portDepSwTimerListP1, NULL, PORT_NUMS1},
    {portDepSwTimerListP2, NULL, PORT_NUMS2},
};

void StartTimer(int x, int y, tfp handlerFunction)
{
    tTimerElement *insert;
    insert = &gSWTimers[0].timerList[y];
    insert->timerVal = x;
    insert->fp = handlerFunction;
    insert->next = NULL;
}
void TimerIntHandler()
{
    tTimerElement *current;
    current = gSWTimers[0].head;
    tfp fps[2];
    fps[0] = current->fp;
    fps[1] = current->fp;
    if (current != NULL)
    {
        gSWTimers[0].head = current->next;
        fps[0].handlerFunc1(0);
    }
    else
    {
        fps[1].handlerFunc2();
    }
}

void handlerFunc1(int portId) {}
void handlerFunc2() {}

int main()
{
    tfp fps;
    fps.handlerFunc1 = handlerFunc1;
    fps.handlerFunc2 = handlerFunc2;
    StartTimer(10, 0, fps);
    StartTimer(20, 1, fps);
    TimerIntHandler();
    return 0;
}