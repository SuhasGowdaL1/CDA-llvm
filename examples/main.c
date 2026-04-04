#include <stdio.h>
#include <stdlib.h>

/* =========================================================
   FORWARD DECLARATIONS
   ========================================================= */

/* Indirect recursion chain */
int A(int n);
int B(int n);
int C(int n);
int D(int n);
int E(int n);
int F(int n);

/* Branch system (all call-based) */
int entry(int x);
int branch_even(int x);
int branch_odd(int x);

int even_gt10(int x);
int even_le10(int x);

int odd_lt5(int x);
int odd_ge5(int x);

/* Recursive vs non-recursive branches */
int recursive_path(int x);
int recursive_step(int x);

int non_recursive_path(int x);
int non_recursive_loop(int i, int limit);

/* Switch via dispatcher */
int switch_entry(int x);
int case0(int x);
int case1(int x);
int case2(int x);
int case_default(int x);

/* Loop system (call-driven) */
int loop_entry(int n);
int loop_check(int i, int n);
int loop_body(int i, int n);
int loop_continue(int i, int n);
int loop_break(int i, int n);

/* Mixed driver */
int mixed_entry(int x);

/* =========================================================
   🔁 INDIRECT RECURSION (3+ FUNCTIONS)
   A → B → C → A
   WITH ESCAPE PATH
   ========================================================= */

int A(int n)
{
    if (n <= 0)
        return 1;

    if (n % 2 == 0)
        return B(n - 1); // recursion path
    else
        return D(n - 1); // escape path
}

int B(int n)
{
    if (n <= 0)
        return 2;

    if (n % 3 == 0)
        return C(n - 2); // continue recursion
    else
        return E(n - 1); // escape recursion
}

int C(int n)
{
    if (n <= 0)
        return 3;

    return A(n - 1); // closes recursion loop
}

/* Escape chain (non-recursive path) */
int D(int n)
{
    if (n <= 0)
        return 4;
    return E(n - 1);
}

int E(int n)
{
    if (n <= 0)
        return 5;
    return F(n - 1);
}

int F(int n)
{
    return n * 10;
}

/* =========================================================
   🔀 CALL-ONLY BRANCHING SYSTEM
   ========================================================= */

int entry(int x)
{
    int a;
    for (int i = 0; i < 5; i++)
    {
        if (x % 2 == 0)
            a = branch_even(x);
        else
            a = branch_odd(x);
    }
    return a;
}

int branch_even(int x)
{
    if (x > 10)
        return even_gt10(x);
    else
        return even_le10(x);
}

int branch_odd(int x)
{
    if (x < 5)
        return odd_lt5(x);
    else
        return odd_ge5(x);
}

int even_gt10(int x)
{
    return recursive_path(x);
}

int even_le10(int x)
{
    return non_recursive_path(x);
}

int odd_lt5(int x)
{
    return recursive_path(x);
}

int odd_ge5(int x)
{
    return non_recursive_path(x);
}

/* =========================================================
   🔁 RECURSIVE PATH (CALL-ONLY)
   ========================================================= */

int recursive_path(int x)
{
    if (x <= 0)
        return 100;

    return recursive_step(x);
}

int recursive_step(int x)
{
    return recursive_path(x - 2);
}

/* =========================================================
   🔁 NON-RECURSIVE LOOP (CALL-DRIVEN)
   ========================================================= */

int non_recursive_path(int x)
{
    return non_recursive_loop(0, x);
}

int non_recursive_loop(int i, int limit)
{
    if (i >= limit)
        return 0;

    if (i == 3)
        return loop_break(i, limit);

    if (i % 2 == 0)
        return loop_continue(i, limit);

    return loop_body(i, limit);
}

int loop_body(int i, int limit)
{
    return i + non_recursive_loop(i + 1, limit);
}

int loop_continue(int i, int limit)
{
    return non_recursive_loop(i + 1, limit);
}

int loop_break(int i, int limit)
{
    return i;
}

/* =========================================================
   🔀 SWITCH VIA FUNCTION DISPATCH
   ========================================================= */

int switch_entry(int x)
{
    int key = x % 4;

    if (key == 0)
        return case0(x);
    else if (key == 1)
        return case1(x);
    else if (key == 2)
        return case2(x);
    else
        return case_default(x);
}

int case0(int x)
{
    return x + 10;
}

int case1(int x)
{
    return case2(x); // fallthrough simulation
}

int case2(int x)
{
    return x + 20;
}

int case_default(int x)
{
    return x - 1;
}

/* =========================================================
   🔁 LOOP STRUCTURE (FULLY CALL-DRIVEN)
   ========================================================= */

int loop_entry(int n)
{
    return loop_check(0, n);
}

int loop_check(int i, int n)
{
    if (i >= n)
        return 0;
    return loop_body(i, n);
}

/* =========================================================
   🔀 MIXED PATH DRIVER
   ========================================================= */

int mixed_entry(int x)
{
    if (x % 3 == 0)
        return A(x); // recursion possible
    else if (x % 3 == 1)
        return entry(x); // branch system
    else
        return switch_entry(x); // switch dispatch
}

/* =========================================================
   MAIN
   ========================================================= */

int main(int argc, char *argv[])
{
    int input = argc > 1 ? atoi(argv[1]) : 7;

    int r1 = A(input);     // indirect recursion / escape
    int r2 = entry(input); // call-only branching
    int r3 = switch_entry(input);
    int r4 = loop_entry(input);
    int r5 = mixed_entry(input);

    printf("Results:\n");
    printf("Indirect Recursion: %d\n", r1);
    printf("Branch System: %d\n", r2);
    printf("Switch System: %d\n", r3);
    printf("Loop System: %d\n", r4);
    printf("Mixed Path: %d\n", r5);

    return 0;
}