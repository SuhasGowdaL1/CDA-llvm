#ifndef DATA_PROCESSOR_H
#define DATA_PROCESSOR_H

int normalize_value(int val, int min, int max);
int scale_value(int val, int factor);
int transform_data(int input, int operation);
int validate_range(int val, int min, int max);

#endif
