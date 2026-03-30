#include "algorithm.h"
#include "data_processor.h"
#include "math_utils.h"
#include "repetition_cases.h"

int process_batch() {
    int data[] = {10, 20, -30, 40, 50};
    int total = process_sequence(data, 5, 0);
    return total;
}

int validate_input(int value) {
    if (validate_range(value, -1000, 1000)) {
        return apply_algorithm(value);
    }
    return 0;
}

int main() {
    int input_value = 42;
    int validated = validate_input(input_value);
    
    int batch_result = process_batch();

    int repetition_result = verify_repetition_cases(3);
    
    int final_result = compute_result(validated, batch_result, 1);

    final_result += repetition_result;
    
    return final_result;
}
