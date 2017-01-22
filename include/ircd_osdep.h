/*
 * ircd_osdep.h
 *
 * $Id: ircd_osdep.h,v 1.1.1.1 2006/12/19 12:56:33 zipbreake Exp $
 */
#ifndef INCLUDED_ircd_osdep_h
#define INCLUDED_ircd_osdep_h

struct Client;
struct sockaddr_in;
struct MsgQ;

typedef enum IOResult {
  IO_FAILURE = -1,
  IO_BLOCKED = 0,
  IO_SUCCESS = 1
} IOResult;

/*
 * NOTE: osdep.c files should never need to know the actual size of a
 * Client struct. When passed as a parameter, the pointer just needs
 * to be forwarded to the enumeration function.
 */
typedef void (*EnumFn)(struct Client*, const char* msg);

extern int os_disable_options(int fd);
extern int os_get_rusage(struct Client* cptr, int uptime, EnumFn enumerator);
extern int os_get_sockerr(int fd);
extern int os_get_sockname(int fd, struct sockaddr_in* sin_out);
extern int os_get_peername(int fd, struct sockaddr_in* sin_out);
extern IOResult os_recv_nonb(int fd, char* buf, unsigned int length,
                        unsigned int* length_out);
extern IOResult os_send_nonb(int fd, const char* buf, unsigned int length,
                        unsigned int* length_out);
extern IOResult os_sendv_nonb(struct Client *acptr, struct MsgQ* buf,
			      unsigned int* len_in, unsigned int* len_out);
extern IOResult os_recvfrom_nonb(int fd, char* buf, unsigned int len,
                                 unsigned int* length_out,
                                 struct sockaddr_in* from_out);
extern IOResult os_connect_nonb(int fd, const struct sockaddr_in* sin);
extern int os_set_fdlimit(unsigned int max_descriptors);
extern int os_set_listen(int fd, int backlog);
extern int os_set_nonblocking(int fd);
extern int os_set_reuseaddr(int fd);
extern int os_set_sockbufs(int fd, unsigned int size);
extern int os_set_tos(int fd,int tos);

#endif /* INCLUDED_ircd_osdep_h */

