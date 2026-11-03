#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

void vulnerable_function(char* out, const char* in) {
    strcpy(out, "Hello, ");
    strcat(out, in);
}

void log_message(char *buf, const char *fmt, ...) {
    va_list args; 
    va_start(args, fmt);
    vsprintf(buf, fmt, args);
    va_end(args);
}

int main(void) {
    char name[16];
    char greet[32];
    char record[64];
    int age = 30;

    printf("Enter your name: ");
    gets(name);
    printf(name);
    strcpy(record, gets(name));

    vulnerable_function(greet, name);
    sprintf(record, "%s (age %d)", greet, age);
    puts(record);
    return 0;
}