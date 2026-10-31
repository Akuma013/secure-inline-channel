/* Plaintext test apps for PC1/PC2 (no crypto: the gateways do it).
 *   gcc -o pc_apps pc_apps.c
 *   pc_apps server            (on PC2, binds 10.0.3.2:5000)
 *   pc_apps client [message]  (on PC1, connects to 10.0.3.2:5000)
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define PORT 5000
#define IP   "10.0.3.2"

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s server|client [msg]\n", argv[0]); return 1; }
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_port = htons(PORT);
    inet_pton(AF_INET, IP, &a.sin_addr);

    if (!strcmp(argv[1], "server")) {
        int one = 1; setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        if (bind(fd, (struct sockaddr *)&a, sizeof a) < 0 || listen(fd, 1) < 0) { perror("bind/listen"); return 1; }
        printf("PC2 listening on %s:%d\n", IP, PORT);
        int c = accept(fd, NULL, NULL);
        char buf[4096]; ssize_t n;
        while ((n = recv(c, buf, sizeof buf - 1, 0)) > 0) { buf[n] = 0; printf("PC2 got %zd bytes: %s\n", n, buf); }
        close(c);
    } else {
        if (connect(fd, (struct sockaddr *)&a, sizeof a) < 0) { perror("connect"); return 1; }
        const char *msg = argc > 2 ? argv[2] : "Hello from PC1!";
        for (int i = 0; i < 3; i++) { send(fd, msg, strlen(msg), 0); sleep(1); }
        char buf[256]; ssize_t n = recv(fd, buf, sizeof buf - 1, MSG_DONTWAIT); (void)n;
    }
    close(fd);
    return 0;
}
