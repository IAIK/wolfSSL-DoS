#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

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

  char* buffer = malloc(16 * 1024);
  if (!buffer) {
    perror("malloc()");
    close(fd);
    return 1;
  }

  int ret = 0;
  while (true) {
    const ssize_t recv = recvfrom(fd, buffer, 16 * 1024, 0, NULL, NULL);
    if (recv < 0) {
      perror("recvfrom()");
      ret = 1;
      break;
    }

    printf("Received %zd bytes.\n", recv);
    fflush(stdout);
  }

  free(buffer);
  close(fd);
  return ret;
}
