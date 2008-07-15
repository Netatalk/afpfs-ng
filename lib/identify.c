#include <string.h>
#include "afp.h"


/* 
 * afp_server_identify()
 *
 * Identifies a server
 *
 * Right now, this only does identification using the machine_type
 * given in getsrvrinfo, but this could later use mDNS to get 
 * more details.
 */
void afp_server_identify(struct afp_server * s)
{
	if (strcmp(s->basic.machine_type,"Netatalk")==0)
		s->basic.server_type=AFPFS_SERVER_TYPE_NETATALK;
	else if (strcmp(s->basic.machine_type,"AirPort")==0)
		s->basic.server_type=AFPFS_SERVER_TYPE_AIRPORT;
	else if (strcmp(s->basic.machine_type,"Macintosh")==0)
		s->basic.server_type=AFPFS_SERVER_TYPE_MACINTOSH;
	else
		s->basic.server_type=AFPFS_SERVER_TYPE_UNKNOWN;
}
