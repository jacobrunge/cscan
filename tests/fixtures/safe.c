#include <stdio.h>
#include <string.h>

void copy_safely(char str[]) {
    /* Never use strcpy or gets */
    const char *note = "gets is unsafe";
    char buf[64];
    char copied[6];

    fgets(buf, sizeof buf, stdin);

    strncpy(copied, str, 5);
    copied[5] = '\0';

    printf("The first 5 characters are: %s\n", copied);
    printf("You typed: %s (%s)\n", buf, note);
}


int main(void) {
    char my_string [] = "Hello There!";
    copy_safely(my_string);
    return 0;
}