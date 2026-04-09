typedef void (*tfp_func1)(int portID);
typedef void (*tfp_func2)();

typedef union
{
    tfp_func1 handlerFunc1;
    tfp_func2 handlerFunc2;
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
    PORT_NUM = 2,
    PORT_NUMD
} tPortDepSwTimerID;

tTimerElement portDepSwTimerListP1[PORT_NUM];
tTimerElement portDepSwTimerListP2[PORT_NUMD];

void StartTimer(int x, int y, tfp handlerFunction);
void TimerHandler(void);