#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>

#include <linux/if.h>
#include <linux/if_tun.h>

#include <pwd.h>
#include <argp.h>
    
const char *argp_program_version = "tuncfg 0.1";
const char *argp_program_bug_address = "<vtun@office.satix.net>";
     
static struct argp_option options[] = {
	{"tun", 	't', 0, 0, "TUN (Point-to-Point) device" },
	{"tap", 	'e', 0, 0, "TAP (Ethernet) device" },
	{"persist",	'p', 0, 0, "Make device persistent" },
	{"remove",	'r', 0, 0, "Remove persistent device" },
	{"pinfo",	'i', 0, 0, "Enable protocol information" },
	{"owner", 	'o', "user", 0, "Set owner of the persistent device" },
	{ 0 }
};

#define TUN_NODE	"/dev/net/tun"

static char *dev    = NULL;
static int  persist = -1;
static int  pinfo   = 0;
uid_t       owner   = -2;
static int  tun     = 1;
 
static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	struct passwd *pw;

	switch (key) {
		case 't':
			tun = 1;
			break;

		case 'e':
			tun = 0;
			break;

		case 'p': 
			persist = 1;
			break;

		case 'r': 
			persist = 0;
			break;

		case 'o':
			if( isdigit(*arg) )
				pw = getpwuid((uid_t)atol(arg));
			else
				pw = getpwnam(arg);

			if( pw )
				owner = pw->pw_uid;
			else
				owner = -1;
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

int main(int argc, char **argv)
{
	char buf[2000];
	struct ifreq ifr;
	int fd, len;

	argp_parse(&parser, argc, argv, 0, NULL, NULL);

	if( (fd = open(TUN_NODE, O_RDWR)) < 0 ){
		perror("Failed to open control device");
		exit(1);
	}

	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, dev);

	if( tun )
		ifr.ifr_flags |= IFF_TUN;
	else
		ifr.ifr_flags |= IFF_TAP;
	
	if( !pinfo )
		ifr.ifr_flags |= IFF_NO_PI;
	
	if( ioctl(fd, TUNSETIFF, (long)&ifr) < 0 ){ 
		perror("Failed to set interface");
		exit(1);
	}

	if( persist != -1 ) 
		if( ioctl(fd, TUNSETPERSIST, persist) < 0 )
			perror("Failed to set persist mode");

	if( owner != -2 ) 
		if( ioctl(fd, TUNSETOWNER, owner) < 0 ) 
			perror("Failed to set owner");

	close(fd);
}
