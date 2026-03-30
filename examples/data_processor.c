#include "data_processor.h"
#include "math_utils.h"

int validate_range(int val, int min, int max) {
    int min_val = min_value(min, max);
    int max_val = max_value(min, max);
    if (val >= min_val && val <= max_val) {
        return 1;
    }
    return 0;
}

int normalize_value(int val, int min, int max) {
    if (!validate_range(val, min, max)) {
        return 0;
    }
    int abs_val = absolute_value(val);
    return abs_val;
}

int scale_value(int val, int factor) {
    int abs_val = absolute_value(val);
    return abs_val * factor;
}

int transform_data(int input, int operation) {
    if (operation == 0) {
        return scale_value(input, 2);
    } else if (operation == 1) {
        return normalize_value(input, -100, 100);
    } else if (operation == 2) {
        int sq = square(input);
        return min_value(sq, 1000);
    }
    return 0;
}
