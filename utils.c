#include "utils.h"
#include <stdio.h>

const char * bytes_unit[] = { "B", "KB", "MB", "GB", "TB" };
char result[50];
char * bytes_format(unsigned long bytes) {
    int i;
    double converted_bytes = bytes;
    for (i = 0; i < 5 && bytes >= 1024; i++, bytes /= 1024) {
        converted_bytes = bytes / 1024.0;
    }

    sprintf(result, "%.2f %s", converted_bytes, bytes_unit[i]);
    return result;
}
