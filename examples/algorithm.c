#include "algorithm.h"
#include "data_processor.h"
#include "math_utils.h"

int filter_data(int value, int threshold) {
    int abs_val = absolute_value(value);
    if (abs_val > threshold) {
        return 1;
    }
    return 0;
}

int process_sequence(int *data, int count, int operation) {
    int result = 0;
    int i = 0;
    while (i < count) {
        int transformed = transform_data(data[i], operation);
        result += transformed;
        i = i + 1;
    }
    return result;
}

int compute_result(int input1, int input2, int mode) {
    int val1 = scale_value(input1, 2);
    int val2 = scale_value(input2, 3);
    if (mode == 0) {
        return max_value(val1, val2);
    } else {
        return min_value(val1, val2);
    }
}

int apply_algorithm(int base_value) {
    int filtered = filter_data(base_value, 50);
    int processed = 0;
    if (filtered) {
        int transformed = transform_data(base_value, 1);
        processed = compute_result(transformed, base_value, 0);
    }
    return processed;
}
