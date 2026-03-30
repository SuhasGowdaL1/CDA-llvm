#include "math_utils.h"

int absolute_value(int x) {
    if (x < 0) {
        return -x;
    }
    return x;
}

int square(int x) {
    int abs_x = absolute_value(x);
    return abs_x * abs_x;
}

int cube(int x) {
    int sq = square(x);
    return sq * x;
}

int min_value(int a, int b) {
    if (a < b) {
        return a;
    }
    return b;
}

int max_value(int a, int b) {
    if (a > b) {
        return a;
    }
    return b;
}
