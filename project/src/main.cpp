
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h> 
#include <sys/select.h>
#include <sys/time.h>
#include <errno.h>
#include <stdarg.h>
#include <string>
#include <chrono>

#define BUFSIZE 1500  
#define CLIENT 0
#define SERVER 1
#define PORT 5555

int debug;
char *progname;

using namespace std;


void print_ip(unsigned int ip)
{
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;   
    printf("%d.%d.%d.%d\n", bytes[3], bytes[2], bytes[1], bytes[0]);        
}


int tun_alloc(char *dev, int flags) {

  struct ifreq ifr;
  int fd, err;
  char *clonedev = "/dev/net/tun";

  if( (fd = open(clonedev , O_RDWR)) < 0 ) {
    perror("Opening /dev/net/tun");
    return fd;
  }

  memset(&ifr, 0, sizeof(ifr));

  ifr.ifr_flags = flags;

  if (*dev) {
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
  }

  if( (err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 ) {
    perror("creating TUN Device");
    close(fd);
    return err;
  }

  if(ioctl(fd, TUNSETPERSIST, 1) < 0){
    perror("enabling TUNSETPERSIST");
    exit(1);
  }

  strcpy(dev, ifr.ifr_name);

  return fd;
}


int cread(int fd, char *buf, int n){
  
  int nread;

  if((nread=read(fd, buf, n)) < 0){
    perror("Reading data");
    exit(1);
  }
  return nread;
}


int cwrite(int fd, char *buf, int n){
  
  int nwrite;

  if((nwrite=write(fd, buf, n)) < 0){
    perror("Writing data");
    exit(1);
  }
  return nwrite;
}

/**************************************************************************
 * do_debug: prints debugging stuff (doh!)                                *
 **************************************************************************/
void do_debug(char *msg, ...){
  
  va_list argp;
  
  if(debug) {
	va_start(argp, msg);
	vfprintf(stderr, msg, argp);
	va_end(argp);
  }
}

/**************************************************************************
 * my_err: prints custom error messages on stderr.                        *
 **************************************************************************/
void my_err(char *msg, ...) {

  va_list argp;
  
  va_start(argp, msg);
  vfprintf(stderr, msg, argp);
  va_end(argp);
}

void hexdump(void *ptr, int buflen) {
  unsigned char *buf = (unsigned char*)ptr;
  int i, j;
  for (i=0; i<buflen; i+=16) {
    printf("%06x: ", i);
    for (j=0; j<16; j++) 
      if (i+j < buflen)
        printf("%02x ", buf[i+j]);
      else
        printf("   ");
    printf(" ");
    for (j=0; j<16; j++) 
      if (i+j < buflen)
        printf("%c", isprint(buf[i+j]) ? buf[i+j] : '.');
    printf("\n");
  }
}

int main(int argc, char *argv[]) {
  
  int tap_fd, option;

  char if_name[IFNAMSIZ] = "tun0";
  int maxfd;
  uint16_t nread, nwrite, plength;
  char buffer[BUFSIZE];
  struct sockaddr_in local, remote;
  char remote_ip[16] = "";       
  unsigned short int port = PORT;
  int net_fd, optval = 1;
  socklen_t remotelen;
  unsigned long int tap2net = 0, net2tap = 0;

  progname = argv[0];
  
  /* Check command line options */
  while((option = getopt(argc, argv, "i:p:d")) > 0) {
    switch(option) {
      case 'd':
        debug = 1;
        break;
      case 'i':
        strncpy(if_name,optarg, IFNAMSIZ-1);
        break;
      case 'p':
        port = atoi(optarg);
        break;
      default:
        my_err("Unknown option %c\n", option);
    }
  }

  argv += optind;
  argc -= optind;

  if(argc > 0) {
    my_err("Too many options!\n");
  }


  /* initialize tun/tap interface */
  if ( (tap_fd = tun_alloc(if_name, IFF_TUN | IFF_NO_PI)) < 0 ) {
    my_err("Error connecting to tun/tap interface %s!\n", if_name);
    exit(1);
  } 

  do_debug("Successfully connected to interface %s\n", if_name);

  if ( (net_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
    perror("socket()");
    exit(1);
  }

  int status = system(("ip link set " + string(if_name) + " up").c_str());

  status = system(("ip addr add 10.0.0.1/24 dev " + string(if_name)).c_str()); // Set IP address on tun alloc instead

  /* Activate NAT */
  status = system(("iptables --table nat --append POSTROUTING --out-interface " + string("enp2s0") + " -j MASQUERADE").c_str()); // make interface changeable
  status = system(("iptables --append FORWARD --in-interface " + string(if_name) + " -j ACCEPT && echo 1 > /proc/sys/net/ipv4/ip_forward").c_str());
  
  memset(&local, 0, sizeof(local));
  local.sin_family = AF_INET;
  local.sin_addr.s_addr = htonl(INADDR_ANY);
  local.sin_port = htons(port);
  if (bind(net_fd, (struct sockaddr*) &local, sizeof(local)) < 0) {
    perror("bind()");
    exit(1);
  }
  
  remotelen = sizeof(remote);
  memset(&remote, 0, remotelen);

  
  /* use select() to handle two descriptors at once */
  maxfd = (tap_fd > net_fd)?tap_fd:net_fd;
  int len = sizeof(sockaddr_in);
  int port_cl = 0;

  while(1) {
    int ret;
    fd_set rd_set;
    
    FD_ZERO(&rd_set);
    FD_SET(tap_fd, &rd_set); 

    FD_SET(net_fd, &rd_set);

    ret = select(maxfd + 1, &rd_set, NULL, NULL, NULL);

    if (ret < 0 && errno == EINTR){
      continue;
    }

    if (ret < 0) {
      perror("select()");
      exit(1);
    }

    /* data from the network: read it, and write it to the tun interface. */
    if(FD_ISSET(net_fd, &rd_set)) {
      nread = recvfrom(net_fd, buffer, BUFSIZE, MSG_WAITALL, (struct sockaddr *)&remote, (socklen_t *)&len);
      port_cl = ntohs(remote.sin_port);
      
      net2tap++;
      do_debug("NET2TUN %lu: Read %d bytes from the network\n", net2tap, nread);
      /* GZIP... why did we even try that...
      if(gzip::is_compressed(buffer, nread)) {
        string original = gzip::decompress(buffer, nread);
        nwrite = cwrite(tap_fd, original.data(), original.length());
        cout << "Saved bytes received: " << original.length() - nread << endl;
      } else {
        nwrite = cwrite(tap_fd, buffer, nread);
      }*/
      nwrite = cwrite(tap_fd, buffer, nread);

      /* now buffer[] contains a full packet or frame, write it into the tun interface */ 
      if(debug) {
        print_ip(ntohl(remote.sin_addr.s_addr));
        cout << ntohs(remote.sin_port) << endl;
      }
      do_debug("NET2TUN %lu: Written %d bytes to the tap interface\n", net2tap, nwrite);
    }

    /* data from tun: just read it and write it to the network */
    if(FD_ISSET(tap_fd, &rd_set) && port_cl != 0) {
      nread = cread(tap_fd, buffer, BUFSIZE);
      tap2net++;
      do_debug("TAP2NET %lu: Read %d bytes from the tap interface\n", tap2net, nread);

      /*
      std::chrono::steady_clock::time_point begin = std::chrono::steady_clock::now();
      string compressed = gzip::compress(buffer, nread);
      std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
      */

      /* write length + packet .... JETZT OHNE LENGTH*/
      /*
      if(compressed.length() + 2000 < nread) { // + 2000 to make it allways false
        plength = htons(compressed.length());
        nwrite = cwrite(net_fd, compressed.data(), compressed.length());
        sendto(net_fd, compressed.data(), compressed.length(), 0, (const sockaddr*) &remote, sizeof(remote));
        cout << "Saved bytes send: " << nread - compressed.length() << endl;
        std::cout << "Time difference = " << std::chrono::duration_cast<std::chrono::nanoseconds> (end - begin).count() << "[ns]" << std::endl;
      } else {
        //remote.sin_port = htons(65526);
        print_ip(ntohl(remote.sin_addr.s_addr));
        cout << ntohs(remote.sin_port) << endl;
        sendto(net_fd, buffer, nread, 0, (const sockaddr*) &remote, sizeof(remote));
        /*plength = htons(nread);
        nwrite = cwrite(net_fd, (char *)&plength, sizeof(plength));
        nwrite = cwrite(net_fd, buffer, nread);
      }*/
        sendto(net_fd, buffer, nread, 0, (const sockaddr*) &remote, sizeof(remote));

      do_debug("TAP2NET %lu: Written %d bytes to the network\n", tap2net, nwrite);
    }
  }
  
  return(0);
}
