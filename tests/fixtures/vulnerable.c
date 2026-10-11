#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <char.h>

void vulnerable_function(char* out, const char* in) {
    strcpy(out, "Hello, ");
    strcat(out, in);
}

int main(void) {
    char name[16];
    char greet[32];
    char record[64];
    int age = 30;

    printf("Enter your name: ");
    gets(name);

    vulnerable_function(greet, name);
    sprintf(record, "%s (age %d)", greet, age);
    puts(record);
    return 0;
}