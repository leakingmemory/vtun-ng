#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>

#include <sys/sockio.h>
#include <stropts.h>
#include "if_tun.h"

/* Allocate TUN device */
int gettun(int d)
{
    int ip_fd, tun_fd, if_fd, ppa;
	
    if( (ip_fd = open("/dev/ip", O_RDWR, 0)) < 0){
       printf("Couldn't open IP device\n");
       return -1;
    }

    if( (tun_fd = open("/dev/tun", O_RDWR, 0)) < 0){
       printf("Can't open /dev/tun\n");
       return -1;
    }
	
    /* Assign a new PPA and get its unit number. */
    if( (ppa = ioctl(tun_fd, TUNNEWPPA, d)) < 0){
       printf("Can't assign new interface\n");
       return -1;
    }
    printf("New iface %d\n", ppa);

    if( (if_fd = open("/dev/tun", O_RDWR, 0)) < 0){
       printf("Can't open /dev/tun (2)\n");
       return -1;
    }

    if(ioctl(if_fd, I_PUSH, "ip") < 0){
       printf("Can't push IP module\n");
       return -1;
    }

    /* Assign ppa according to the unit number returned by tun device */
    if(ioctl(if_fd, IF_UNITSEL, (char *)&ppa) < 0){
       printf("Can't set PPA %d\n", ppa);
       return -1;
    }

    if(ioctl(ip_fd, I_LINK, if_fd) < 0){
       printf("Can't link TUN device to IP");
       return -1;
    }

    return tun_fd;
}

#define max(a,b) ((a)>(b) ? (a):(b))

int main(int argc, char *argv[])
{
   char buf[1600];
   int f1,f2,l,fm;
   fd_set fds;
 
   if(argc < 2) {
      printf("Usage: bridge tap|tun\n");
      exit(1);
   }

   f1 = gettun(0);
   f2 = gettun(1);
   fm = max(f1, f2) + 1;

   while(1){
	FD_ZERO(&fds);
        FD_SET(f1, &fds);
        FD_SET(f2, &fds);

	select(fm, &fds, NULL, NULL, NULL);

	if( FD_ISSET(f1, &fds) ) {
	   l = read(f1,buf,sizeof(buf));
           write(f2,buf,l);
	}
	if( FD_ISSET(f2, &fds) ) {
	   l = read(f2,buf,sizeof(buf));
           write(f1,buf,l);
	}
   }
}
