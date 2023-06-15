#include <stdio.h>
#include <unistd.h>

#define MAX_LENGTH 10

int main() {
    char content[MAX_LENGTH + 1]; // +1 for null terminator
    ssize_t length = read(STDIN_FILENO, content, MAX_LENGTH);
    if (length == -1) {
        perror("read");
        return 1;
    }
    content[length] = '\0'; // manually add null terminator
    printf("%s", content);
    return 0;
}

