#include <stdio.h>

/* ===== Logging Macros ===== */
#define LOG_ENTRY(fn) printf("%s_entry\n", fn)
#define LOG_EXIT(fn) printf("%s_exit\n", fn)
#define LOG_FUNC(fn) printf("%s\n", fn)

/* ===== Shared (Ambiguous) Functions ===== */
void process_data(void)
{
    LOG_FUNC("process_data");
}

void update_state(void)
{
    LOG_FUNC("update_state");
}

void send_response(void)
{
    LOG_FUNC("send_response");
}

/* ===== Entry Point 2 ===== */
void Timer_ISR(void)
{
    LOG_ENTRY("Timer_ISR");

    process_data(); // <-- ambiguous
    update_state();

    LOG_EXIT("Timer_ISR");
}
void loglog(int x)
{
    if (x > 0)
        process_data();
}
/* ===== Entry Point 3 ===== */
void UART_ISR(void)
{
    LOG_ENTRY("UART_ISR");

    process_data(); // <-- ambiguous (same as above)
    send_response();

    LOG_EXIT("UART_ISR");
}

/* ===== Entry Point 1 ===== */
int main(void)
{
    LOG_ENTRY("main");

    for (int i = 0; i < 2; i++)
    {
        // LOG_FUNC("main_loop");
        loglog(i);
        process_data(); // <-- ambiguous (third place)

        if (i % 2 == 0)
        {
            Timer_ISR();
        }
        else
        {
            UART_ISR();
        }
    }

    LOG_EXIT("main");
    return 0;
}