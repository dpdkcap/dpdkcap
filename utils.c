#include "utils.h"
#include <stdio.h>
#include <string.h>

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

char * str_replace(const char * src, const char * find, const char * replace) {
  int find_len, replace_len, src_left_length;
  char * pos = strstr(src,find);
  if (pos) {
    find_len = strlen(find);
    replace_len = strlen(replace);
    src_left_length = strlen(pos+find_len)+1;

    memmove(pos+replace_len, pos+find_len, src_left_length);
    memmove(pos           , replace, replace_len);
  }
  return pos;
}
