#include <stdio.h>

/* =========================================================
   ACTION FUNCTIONS (simulate hardware / policy actions)
   ========================================================= */

int act_idle(int x) { return x + 1; }
int act_run(int x) { return x + 2; }
int act_sleep(int x) { return x + 3; }

int act_init(int x) { return x + 4; }
int act_check(int x) { return x + 5; }
int act_error(int x) { return x + 6; }

int act_eventA(int x) { return x + 7; }
int act_eventB(int x) { return x + 8; }
int act_eventC(int x) { return x + 9; }

int act_safe(int x) { return x + 10; }
int act_warn(int x) { return x + 11; }
int act_shutdown(int x) { return x + 12; }

/* =========================================================
   POLICY ENGINE LOOP
   ========================================================= */

int policy_engine(int n)
{
    int i = 0;
    int sum = 0;

    while (i < n)
    {

        int mode = i % 3;
        int state = i % 4;
        int event = i % 3;
        int safe = i % 3;

        /* ================= SWITCH 1: MODE ================= */
        switch (mode)
        {
        case 0:
            if (i < 3)
            {
                sum += act_idle(i);
                i++;
                continue; // skip rest of pipeline
            }
            else
            {
                sum += act_run(i);
            }
            break;

        case 1:
            sum += act_sleep(i);
            break;

        case 2:
            sum += act_run(i);
            break;
        }

        /* ================= SWITCH 2: STATE ================= */
        switch (state)
        {
        case 0:
            sum += act_init(i);
            break;

        case 1:
            if (i > 5)
            {
                sum += act_error(i);
                i += 2;
                continue; // skip remaining switches
            }
            else
            {
                sum += act_check(i);
            }
            break;

        case 2:
            sum += act_check(i);
            break;

        case 3:
            sum += act_error(i);
            break;
        }

        /* ================= SWITCH 3: EVENT ================= */
        switch (event)
        {
        case 0:
            sum += act_eventA(i);
            break;

        case 1:
            if (i == 4)
            {
                sum += act_eventB(i);
                i++;
                continue; // skip safety stage
            }
            else
            {
                sum += act_eventC(i);
            }
            break;

        case 2:
            sum += act_eventB(i);
            break;
        }

        /* ================= SWITCH 4: SAFETY ================= */
        switch (safe)
        {
        case 0:
            sum += act_safe(i);
            break;

        case 1:
            if (i > 7)
            {
                sum += act_shutdown(i);
                return sum; // hard exit (critical fault)
            }
            else
            {
                sum += act_warn(i);
            }
            break;

        case 2:
            sum += act_safe(i);
            break;
        }

        /* loop increment */
        i++;
    }

    return sum;
}

/* =========================================================
   MAIN
   ========================================================= */

int main()
{
    int result = policy_engine(10);
    act_check(result);
    printf("Result: %d\n", result);
    return 0;
}