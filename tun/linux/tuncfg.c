










#include <argp.h>
     
const char *argp_program_version = "tuncfg 0.1";
const char *argp_program_bug_address = "<vtun@office.satix.net>";
     
static struct argp_option options[] = {
	{"tun", 	't', 0, 0, "TUN (Point-to-Point) device" },
	{"tap", 	'e', 0, 0, "TAP (Ethernet) device" },
	{"persist",	'p', 0, 0, "Make device persistent" },
	{"nopersist",	'n', 0, 0,  "Make device non-persistent" },
	{"owner", 	'o', 0, 0, "Set owner of the persistent device" },
	{ 0 }
};

static char *dev;
static long flags;
     
static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	switch (key) {
		case 'p': 
			flags |= 1;
			break;

		case 'o':
			dev = arg;
			break;
     
		case ARGP_KEY_ARG:
			dev = arg;
			break;

   		case ARGP_KEY_END:
			if( !dev )
				argp_usage(state);
			break;
 
		default:
			return ARGP_ERR_UNKNOWN;
	}
	return 0;
}
     
struct argp parser = { 
	options, 
	parse_opt, 
	"<device name>",
	"tuncfg - TUN/TAP device configuration utility"
};

int main (int argc, char **argv)
{
	argp_parse (&parser, argc, argv, 0, NULL, NULL);

	printf("Device %s flags %x\n", dev, flags);
}






#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/socket.h>

#include <linux/if.h>
#include <linux/if_tun.h>

int main(void)
{
	char buf[2000];
	struct ifreq ifr;
	int fd, len;

	if( (fd = open("/dev/net/tun", O_RDWR)) < 0 ){
		perror("Failed to open /dev/net/tun");
		exit(1);
	}

	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, "tun10");
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI | IFF_ONE_QUEUE;
	if( ioctl(fd, TUNSETIFF, (long)&ifr) < 0 ){ 
		perror("Failed to set interface");
		exit(1);
	}

	if( ioctl(fd, TUNSETPERSIST, 1) < 0 ){ 
		perror("Failed to set persist");
		exit(1);
	}

	if( ioctl(fd, TUNSETOWNER, 500) < 0 ){ 
		perror("Failed to set owner");
		exit(1);
	}

	while( 1 ){
		if( (len = read(fd, buf, sizeof(buf))) < 0 ){
			perror("Read failed");
			exit(1);
		}
		printf("Read %d bytes\n", len);
	}
}
