#ifndef _SOCKUTIL_H
#define _SOCKUTIL_H

#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <machine/endian.h>
#include <netdb.h>
#include <arpa/nameser.h>
#include <resolv.h>

/* Do an ident lookup on the connection and return 0 on success or -1 with
 * errno on failure, -2 on garbled server response. */
int ident(int fd, char *buf, size_t buf_size);

/* Convert the numerical "type" field to the standard abbreviation.
 * Returns NULL if it's not known. */
const char *dns_ttos(int type);

/* string-to-type */
int dns_stot(const char *string);

struct ns_response {
	char *name;
	int class;
	int type;
	unsigned int ttl;
	union {
		struct in_addr a;
		struct { char *addr; } ns;
		struct { char *addr; } cname;
		struct { char *addr; int pref; } mx;
		struct { char *addr; } ptr;
		struct {
			char *addr;
			char *maintainer;
			int serial, refresh, retry, expire, def_ttl;
		} soa;
		struct { char *cpu; char *os; } hinfo;
		struct { char *text; } txt;
	} info;
};

/* Do a DNS lookup.
 *  - "name" is the host to look up
 *  - "class" should be C_IN
 *  - "type" should be T_A, T_CNAME, etc
 *  - "response" is a pointer to an array of ns_response structs to store the
 *      requested information in
 *  - "max_answers" is the number of elements allocated for "response"
 *  - "buf" is some pre-allocated memory to store the strings for "response" in
 *  - "buf_size" is the size of buf.  Don't make this too small.
 * This returns the number of elements filled into "response".  On error, -1 is
 * returned and h_errno is set.  If the result is too large, it will return -1
 * and set h_errno to NO_RECOVERY. */
int lookup(const char *name, int class, int type, struct ns_response *response, int max_answers, char *buf, size_t buf_size);

#endif
