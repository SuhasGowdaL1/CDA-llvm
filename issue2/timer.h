typedef void (*tfp_func1)(void);
typedef void (*func_ptr)(void);
typedef union
{
    tfp_func1 handlerFunc1;
    int someValue;
} tfp;

typedef struct TimerElement
{
    int timerVal;
    struct TimerElement *next;
    tfp fp;
} tTimerElement;

typedef struct
{
    tTimerElement *timerList;
    tTimerElement *head;
    int numTimers;
} tSWTimers;

typedef enum
{
    PORT_NUMS1 = 3,
    PORT_NUMS2
} tPortDepSwTimerID;

tTimerElement portDepSwTimerListP1[PORT_NUMS1];
tTimerElement portDepSwTimerListP2[PORT_NUMS2];

void StartTimer(int x, int y, func_ptr handlerFunction);
void TimerIntHandler(void);
