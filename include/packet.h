/*
 * packet.h
 *
 * $Id: packet.h,v 1.1.1.1 2006/12/19 12:56:33 zipbreake Exp $
 */
#ifndef INCLUDED_packet_h
#define INCLUDED_packet_h
#ifndef INCLUDED_sys_types_h
#include <sys/types.h>
#define INCLUDED_sys_types_h
#endif

struct Client;

/*
 * Prototypes
 */

extern int server_dopacket(struct Client* cptr, char* buffer, int length);
extern int connect_dopacket(struct Client* cptr, const char* buffer, int length);
extern int client_dopacket(struct Client* cptr, unsigned int length);

#endif /* INCLUDED_packet_h */
