#include "repetition_cases.h"

int loop_helper(int x) {
    return x + 1;
}

int recursive_sum(int n) {
    if (n <= 0) {
        return 0;
    }
    return n + recursive_sum(n - 1);
}

int mutual_a(int n) {
    if (n <= 0) {
        return 0;
    }
    return 1 + mutual_b(n - 1);
}

int mutual_b(int n) {
    if (n <= 0) {
        return 0;
    }
    return 1 + mutual_a(n - 1);
}

int loop_calls(int n) {
    int total = 0;
    int i = 0;
    while (i < n) {
        total += loop_helper(i);
        i = i + 1;
    }
    return total;
}

int non_recursive_repeat(int x) {
    int total = 0;
    total += loop_helper(x);
    total += loop_helper(x + 1);
    if (x > 0) {
        total += loop_helper(x + 2);
    }
    return total;
}

int verify_repetition_cases(int seed) {
    int a = recursive_sum(seed);
    int b = mutual_a(seed);
    int c = loop_calls(seed);
    int d = non_recursive_repeat(seed);
    return a + b + c + d;
}
