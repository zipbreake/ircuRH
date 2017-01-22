/*
 * support.h
 *
 * $Id: support.h,v 1.1.1.1 2006/12/19 12:56:38 zipbreake Exp $
 */
#ifndef INCLUDED_support_h
#define INCLUDED_support_h

/*
 * Given a number of bits, make a netmask out of it.
 */
#define NETMASK(bits) htonl((0xffffffff>>(32-(bits)))<<(32-(bits)))


/*
 * Prototypes
 */
  
extern int check_if_ipmask(const char *mask);
extern void write_log(const char *filename, const char *pattern, ...);

#endif /* INCLUDED_support_h */
