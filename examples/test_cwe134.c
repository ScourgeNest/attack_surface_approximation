#include <stdio.h>

int main(int argc, char *argv[]) {
    char dest_buffer[256];

    if (argc < 2) {
        printf("Usage: %s <message>\n", argv[0]);
        return 1;
    }

    printf(argv[1]);
    sprintf(dest_buffer, argv[1]);
    snprintf(dest_buffer, 100, argv[1]);
    // Test Comment
    return 0;
}