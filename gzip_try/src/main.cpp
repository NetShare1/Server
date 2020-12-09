/**************************************************************************
 * simpletun.c                                                            *
 *                                                                        *
 * A simplistic, simple-minded, naive tunnelling program using tun/tap    *
 * interfaces and TCP. DO NOT USE THIS PROGRAM FOR SERIOUS PURPOSES.      *
 *                                                                        *
 * You have been warned.                                                  *
 *                                                                        *
 * (C) 2010 Davide Brini.                                                 *
 *                                                                        *
 * DISCLAIMER AND WARNING: this is all work in progress. The code is      *
 * ugly, the algorithms are naive, error checking and input validation    *
 * are very basic, and of course there can be bugs. If that's not enough, *
 * the program has not been thoroughly tested, so it might even fail at   *
 * the few simple things it should be supposed to do right.               *
 * Needless to say, I take no responsibility whatsoever for what the      *
 * program might do. The program has been written mostly for learning     *
 * purposes, and can be used in the hope that is useful, but everything   *
 * is to be taken "as is" and without any kind of warranty, implicit or   *
 * explicit. See the file LICENSE for further details.                    *
 *************************************************************************/ 
// Edited by Alexander Doubrava for testing purposes

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
#include <gzip/compress.hpp>
#include <gzip/config.hpp>
#include <gzip/decompress.hpp>
#include <gzip/utils.hpp>
#include <gzip/version.hpp>
#include <chrono>

/* buffer for reading from tun/tap interface, must be >= 1500 */
#define BUFSIZE 2000   
#define CLIENT 0
#define SERVER 1
#define PORT 55555

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

/**************************************************************************
 * tun_alloc: allocates or reconnects to a tun/tap device. The caller     *
 *            must reserve enough space in *dev.                          *
 **************************************************************************/
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

/**************************************************************************
 * cread: read routine that checks for errors and exits if an error is    *
 *        returned.                                                       *
 **************************************************************************/
int cread(int fd, char *buf, int n){
  
  int nread;

  if((nread=read(fd, buf, n)) < 0){
    perror("Reading data");
    exit(1);
  }
  return nread;
}

/**************************************************************************
 * cwrite: write routine that checks for errors and exits if an error is  *
 *         returned.                                                      *
 **************************************************************************/
int cwrite(int fd, char *buf, int n){
  
  int nwrite;

  if((nwrite=write(fd, buf, n)) < 0){
    perror("Writing data");
    exit(1);
  }
  return nwrite;
}

/**************************************************************************
 * read_n: ensures we read exactly n bytes, and puts them into "buf".     *
 *         (unless EOF, of course)                                        *
 **************************************************************************/
int read_n(int fd, char *buf, int n) {

  int nread, left = n;

  while(left > 0) {
    if ((nread = cread(fd, buf, left)) == 0){
      return 0 ;      
    }else {
      left -= nread;
      buf += nread;
    }
  }
  return n;  
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

/**************************************************************************
 * usage: prints usage and exits.                                         *
 **************************************************************************/
void usage(void) {
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "%s -i <ifacename> [-s|-c <serverIP>] [-p <port>] [-u|-a] [-d]\n", progname);
  fprintf(stderr, "%s -h\n", progname);
  fprintf(stderr, "\n");
  fprintf(stderr, "-i <ifacename>: Name of interface to use (mandatory)\n");
  fprintf(stderr, "-s|-c <serverIP>: run in server mode (-s), or specify server address (-c <serverIP>) (mandatory)\n");
  fprintf(stderr, "-p <port>: port to listen on (if run in server mode) or to connect to (in client mode), default 55555\n");
  fprintf(stderr, "-u|-a: use TUN (-u, default) or TAP (-a)\n");
  fprintf(stderr, "-d: outputs debug information while running\n");
  fprintf(stderr, "-h: prints this help text\n");
  exit(1);
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
  int flags = IFF_TUN;
  char if_name[IFNAMSIZ] = "";
  int maxfd;
  uint16_t nread, nwrite, plength;
  char buffer[BUFSIZE];
  struct sockaddr_in local, remote;
  char remote_ip[16] = "";            /* dotted quad IP string */
  unsigned short int port = PORT;
  int sock_fd, net_fd, optval = 1;
  socklen_t remotelen;
  int cliserv = -1;    /* must be specified on cmd line */
  unsigned long int tap2net = 0, net2tap = 0;

  progname = argv[0];
  
  /* Check command line options */
  while((option = getopt(argc, argv, "i:sc:p:uahd")) > 0) {
    switch(option) {
      case 'd':
        debug = 1;
        break;
      case 'h':
        usage();
        break;
      case 'i':
        strncpy(if_name,optarg, IFNAMSIZ-1);
        break;
      case 's':
        cliserv = SERVER;
        break;
      case 'c':
        cliserv = CLIENT;
        strncpy(remote_ip,optarg,15);
        break;
      case 'p':
        port = atoi(optarg);
        break;
      case 'u':
        flags = IFF_TUN;
        break;
      case 'a':
        flags = IFF_TAP;
        break;
      default:
        my_err("Unknown option %c\n", option);
        usage();
    }
  }

  argv += optind;
  argc -= optind;

  if(argc > 0) {
    my_err("Too many options!\n");
    usage();
  }

  if(*if_name == '\0') {
    my_err("Must specify interface name!\n");
    usage();
  } else if(cliserv < 0) {
    my_err("Must specify client or server mode!\n");
    usage();
  } else if((cliserv == CLIENT)&&(*remote_ip == '\0')) {
    my_err("Must specify server address!\n");
    usage();
  }

  /* initialize tun/tap interface */
  if ( (tap_fd = tun_alloc(if_name, flags | IFF_NO_PI)) < 0 ) {
    my_err("Error connecting to tun/tap interface %s!\n", if_name);
    exit(1);
  } 



  do_debug("Successfully connected to interface %s\n", if_name);

  if ( (sock_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
    perror("socket()");
    exit(1);
  }

  int status = system(("ip link set " + string(if_name) + " up").c_str());

  if(cliserv == CLIENT) {
    /* Only for my VM Client */
    char* interface = "usb0";
    setsockopt(sock_fd, SOL_SOCKET, SO_BINDTODEVICE, interface, 4 ); 
    /* Client, try to connect to server */
    /* Test with fixed IP */
    status = system(("ip addr add 10.0.0.2/24 dev " + string(if_name)).c_str());
    /* assign the destination address */
    memset(&remote, 0, sizeof(remote));
    remote.sin_family = AF_INET;
    remote.sin_addr.s_addr = inet_addr(remote_ip);
    remote.sin_port = htons(port);

    /* connection request */
    status = system(("route add " + string(remote_ip) + " gw 192.168.0.1 " + string(interface)).c_str());
    if (connect(sock_fd, (struct sockaddr*) &remote, sizeof(remote)) < 0) {
      perror("connect()");
      exit(1);
    }
    status = system("ip route del default");
    status = system(("route add default gw 10.0.0.1 " + string(if_name)).c_str());
    


    net_fd = sock_fd;
    do_debug("CLIENT: Connected to server %s\n", inet_ntoa(remote.sin_addr));
    
  } else {
    /* Server, wait for connections */
    /* Test with fixed IP */
    status = system(("ip addr add 10.0.0.1/24 dev " + string(if_name)).c_str());
    status = system(("iptables --table nat --append POSTROUTING --out-interface " + string("enp2s0") + " -j MASQUERADE").c_str());
    status = system(("iptables --append FORWARD --in-interface " + string(if_name) + " -j ACCEPT && echo 1 > /proc/sys/net/ipv4/ip_forward").c_str());

    /* avoid EADDRINUSE error on bind() */
    if(setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(optval)) < 0) {
      perror("setsockopt()");
      exit(1);
    }
    
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    local.sin_port = htons(port);
    if (bind(sock_fd, (struct sockaddr*) &local, sizeof(local)) < 0) {
      perror("bind()");
      exit(1);
    }
    
    remotelen = sizeof(remote);
    memset(&remote, 0, remotelen);
    net_fd = sock_fd; // That should fix it
    /*
    if (listen(sock_fd, 5) < 0) {
      perror("listen()");
      exit(1);
    }
    
    if ((net_fd = accept(sock_fd, (struct sockaddr*)&remote, &remotelen)) < 0) {
      perror("accept()");
      exit(1);
    }

    do_debug("SERVER: Client connected from %s\n", inet_ntoa(remote.sin_addr));
    */
  }
  
  /* use select() to handle two descriptors at once */
  maxfd = (tap_fd > net_fd)?tap_fd:net_fd;
  int len = sizeof(sockaddr_in);
  int port_cl = 0;

  if(cliserv == CLIENT) {
    port_cl = PORT;
  }

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

    if(FD_ISSET(net_fd, &rd_set)) {

      /* data from the network: read it, and write it to the tun/tap interface. 
       * We need to read the length first, and then the packet */
      
      if(port_cl == 0) {
        nread = recvfrom(net_fd, buffer, BUFSIZE, 0, (struct sockaddr *)&remote, (socklen_t *)&len);
        port_cl = ntohs(remote.sin_port);
        cout << "Client Port: " << port_cl << endl;
      } else {
        nread = recvfrom(net_fd, buffer, BUFSIZE, MSG_WAITALL, (struct sockaddr *)&remote, (socklen_t *)&len);
      }
      port_cl = ntohs(remote.sin_port);
      
      net2tap++;
      do_debug("NET2TAP %lu: Read %d bytes from the network\n", net2tap, nread);
      /*
      if(gzip::is_compressed(buffer, nread)) {
        string original = gzip::decompress(buffer, nread);
        nwrite = cwrite(tap_fd, original.data(), original.length());
        cout << "Saved bytes received: " << original.length() - nread << endl;
      } else {
        nwrite = cwrite(tap_fd, buffer, nread);
      }*/
      nwrite = cwrite(tap_fd, buffer, nread);

      /* now buffer[] contains a full packet or frame, write it into the tun/tap interface */ 
      if(debug) {
        print_ip(ntohl(remote.sin_addr.s_addr));
        cout << ntohs(remote.sin_port) << endl;
      }
      do_debug("NET2TAP %lu: Written %d bytes to the tap interface\n", net2tap, nwrite);
    }


    if(FD_ISSET(tap_fd, &rd_set) && port_cl != 0) {
      /* data from tun/tap: just read it and write it to the network */
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
