#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#define SERV_PORT 11112

int main()
{
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0 ) {
    perror("socket()");
    return 1;
  }

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family      = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  addr.sin_port        = htons(SERV_PORT);

  if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
    perror("bind()");
    close(fd);
    return 1;
  }

  while (true) {
    char buffer[4096];
    const ssize_t recv = recvfrom(fd, buffer, sizeof(buffer), 0, NULL, NULL);
    if (recv < 0) {
      perror("recvfrom()");
      close(fd);
      return 1;
    }

    printf("Received %zd bytes.\n", recv);
    fflush(stdout);
  }
}
