#include "sockutil.h"
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>


#define DEBUG


int ident(int fd, char *buf, size_t buf_size) {
	struct sockaddr_in their_addr, my_addr;
	int sockfd, tmpint, my_port, their_port;
	FILE *sockfp;
	char *ptr1, *ptr2;

	bzero(&my_addr, sizeof(my_addr));
	tmpint = sizeof(my_addr);
	if(getsockname(fd, (struct sockaddr *)&my_addr, &tmpint)) return -1;
	my_port = ntohs(my_addr.sin_port);
	my_addr.sin_port = 0;

	bzero(&their_addr, sizeof(their_addr));
	tmpint = sizeof(their_addr);
	if(getpeername(fd, (struct sockaddr *)&their_addr, &tmpint)) return -1;
	their_port = ntohs(their_addr.sin_port);
	their_addr.sin_port = htons(113);

	if(my_addr.sin_family != AF_INET) { errno = EPFNOSUPPORT; return -1; }
	if(their_addr.sin_family != AF_INET) { errno = EPFNOSUPPORT; return -1; }

	/* Open socket */
	if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) return -1;
	if(bind(sockfd, (struct sockaddr *)&my_addr, sizeof(my_addr))) { close(sockfd); return -1; }
	if(connect(sockfd, (struct sockaddr *)&their_addr, sizeof(struct sockaddr))) { close(sockfd); return -1; }
	if(!(sockfp = fdopen(sockfd, "r+"))) { close(sockfd); return -1; }
	setlinebuf(sockfp);

	fprintf(sockfp, "%i,%i\n", their_port, my_port);
	*buf = 0;
	fgets(buf, buf_size, sockfp);

	fclose(sockfp);

	/* Parse response */
	ptr1 = buf;
	ptr2 = strsep(&ptr1, ":");      /* ptr2 == " their_port , my_port " */
	if(!ptr2) return -1;
	ptr2 = strsep(&ptr1, ":");      /* ptr2 == " USERID " */
	if(!ptr2 || !ptr1) return -2;
	while(*ptr2 == ' ') ptr2++;
	if(strncmp("USERID", ptr2, 6)) return -2;
	ptr2 = strsep(&ptr1, ":");      /* ptr2 == " OPERATING-SYSTEM " */

	while(*ptr1 == ' ') ptr1++;     /* ptr1 == " username\r\n" */

	/* chomp end of string */
	tmpint = strlen(ptr1);          /* ptr1[tmpint] == '\0' */
	while(tmpint && strchr(" \r\n", ptr1[--tmpint])) ptr1[tmpint] = 0;

	strcpy(buf, ptr1);
	return 0;
}


/* type-to-string converter */
const char *dns_ttos(int type) {
	switch(type) {
		case T_A:	return("A");		/* internet address */
		case T_NS:	return("NS");		/* authoritative server */
		case T_MD:	return("MD");		/* mail destination */
		case T_MF:	return("MF");		/* mail forwarder */
		case T_CNAME:	return("CNAME");	/* canonical name */
		case T_SOA:	return("SOA");		/* start of auth zone */
		case T_MB:	return("MB");		/* mailbox domain name */
		case T_MG:	return("MG");		/* mail group member */
		case T_MR:	return("MR");		/* mail rename name */
		case T_NULL:	return("NULL");		/* null resource record */
		case T_WKS:	return("WKS");		/* well known service */
		case T_PTR:	return("PTR");		/* domain name pointer */
		case T_HINFO:	return("HINFO");	/* host information */
		case T_MINFO:	return("MINFO");	/* mailbox information */
		case T_MX:	return("MX");		/* mail routing info */
		case T_TXT:	return("TXT");		/* descriptive text */
		case T_RP:	return("RP");		/* responsible person */
		case T_AFSDB:	return("AFSDB");	/* afs database location */
		case T_X25:	return("X25");		/* x25 address */
		case T_ISDN:	return("ISDN");		/* isdn address */
		case T_RT:	return("RT");		/* route through host */
		case T_NSAP:	return("NSAP");		/* nsap address */
#ifdef T_NSAP_PTR
		case T_NSAP_PTR: return("NSAP_PTR");	/* reverse NSAP lookup (deprecated) */
#endif
		case T_SIG:	return("SIG");		/* security signature */
		case T_KEY:	return("KEY");		/* security key */
		case T_PX:	return("PX");		/* rfc822 - x400 mapping */
#ifdef T_GPOS
		case T_GPOS:	return("GPOS");		/* geographical position (withdrawn) */
#endif
		case T_AAAA:	return("AAAA");		/* ip v6 address */
		case T_LOC:	return("LOC");		/* geographical location */
		case T_NXT:	return("NXT");		/* next valid name */
		case T_EID:	return("EID");		/* endpoint identifier */
		case T_NIMLOC:	return("NIMLOC");	/* nimrod locator */
		case T_SRV:	return("SRV");		/* service info */
		case T_ATMA:	return("ATMA");		/* atm address */
		case T_NAPTR:	return("NAPTR");	/* naming authority urn */
		case T_UINFO:	return("UINFO");	/* user information */
		case T_UID:	return("UID");		/* user ident */
		case T_GID:	return("GID");		/* group ident */
		case T_UNSPEC:	return("UNSPEC");	/* unspecified binary data */
		case T_IXFR:	return("IXFR");		/* incremental zone transfer */
		case T_AXFR:	return("AXFR");		/* zone transfer */
		case T_MAILB:	return("MAILB");	/* matches MB/MR/MG/MINFO */
		case T_MAILA:	return("MAILA");	/* matches MD/MF */
		case T_ANY:	return("ANY");		/* matches any type */
		default:	return 0;		/* unknown */
	}
}


/* type-to-string converter */
int dns_stot(const char *type) {
	if(!strcasecmp(type, "A")) {
		return T_A;		/* internet address */
	} else if(!strcasecmp(type, "NS")) {
		return T_NS;		/* authoritative server */
	} else if(!strcasecmp(type, "MD")) {
		return T_MD;		/* mail destination */
	} else if(!strcasecmp(type, "MF")) {
		return T_MF;		/* mail forwarder */
	} else if(!strcasecmp(type, "CNAME")) {
		return T_CNAME;		/* canonical name */
	} else if(!strcasecmp(type, "SOA")) {
		return T_SOA;		/* start of auth zone */
	} else if(!strcasecmp(type, "MB")) {
		return T_MB;		/* mailbox domain name */
	} else if(!strcasecmp(type, "MG")) {
		return T_MG;		/* mail group member */
	} else if(!strcasecmp(type, "MR")) {
		return T_MR;		/* mail rename name */
	} else if(!strcasecmp(type, "NULL")) {
		return T_NULL;		/* null resource record */
	} else if(!strcasecmp(type, "WKS")) {
		return T_WKS;		/* well known service */
	} else if(!strcasecmp(type, "PTR")) {
		return T_PTR;		/* domain name pointer */
	} else if(!strcasecmp(type, "HINFO")) {
		return T_HINFO;		/* host information */
	} else if(!strcasecmp(type, "MINFO")) {
		return T_MINFO;		/* mailbox information */
	} else if(!strcasecmp(type, "MX")) {
		return T_MX;		/* mail routing info */
	} else if(!strcasecmp(type, "TXT")) {
		return T_TXT;		/* descriptive text */
	} else if(!strcasecmp(type, "RP")) {
		return T_RP;		/* responsible person */
	} else if(!strcasecmp(type, "AFSDB")) {
		return T_AFSDB;		/* afs database location */
	} else if(!strcasecmp(type, "X25")) {
		return T_X25;		/* x25 address */
	} else if(!strcasecmp(type, "ISDN")) {
		return T_ISDN;		/* isdn address */
	} else if(!strcasecmp(type, "RT")) {
		return T_RT;		/* route through host */
	} else if(!strcasecmp(type, "NSAP")) {
		return T_NSAP;		/* nsap address */
#ifdef NSAP_PTR
	} else if(!strcasecmp(type, "NSAP_PTR")) {
		return T_NSAP_PTR;	/* reverse NSAP lookup (deprecated) */
#endif
	} else if(!strcasecmp(type, "SIG")) {
		return T_SIG;		/* security signature */
	} else if(!strcasecmp(type, "KEY")) {
		return T_KEY;		/* security key */
	} else if(!strcasecmp(type, "PX")) {
		return T_PX;		/* rfc822 - x400 mapping */
#ifdef T_GPOS
	} else if(!strcasecmp(type, "GPOS")) {
		return T_GPOS;		/* geographical position (withdrawn) */
#endif
	} else if(!strcasecmp(type, "AAAA")) {
		return T_AAAA;		/* ip v6 address */
	} else if(!strcasecmp(type, "LOC")) {
		return T_LOC;		/* geographical location */
	} else if(!strcasecmp(type, "NXT")) {
		return T_NXT;		/* next valid name */
	} else if(!strcasecmp(type, "EID")) {
		return T_EID;		/* endpoint identifier */
	} else if(!strcasecmp(type, "NIMLOC")) {
		return T_NIMLOC;	/* nimrod locator */
	} else if(!strcasecmp(type, "SRV")) {
		return T_SRV;		/* service info */
	} else if(!strcasecmp(type, "ATMA")) {
		return T_ATMA;		/* atm address */
	} else if(!strcasecmp(type, "NAPTR")) {
		return T_NAPTR;		/* naming authority urn */
	} else if(!strcasecmp(type, "UINFO")) {
		return T_UINFO;		/* user information */
	} else if(!strcasecmp(type, "UID")) {
		return T_UID;		/* user ident */
	} else if(!strcasecmp(type, "GID")) {
		return T_GID;		/* group ident */
	} else if(!strcasecmp(type, "UNSPEC")) {
		return T_UNSPEC;	/* unspecified binary data */
	} else if(!strcasecmp(type, "IXFR")) {
		return T_IXFR;		/* incremental zone transfer */
	} else if(!strcasecmp(type, "AXFR")) {
		return T_AXFR;		/* zone transfer */
	} else if(!strcasecmp(type, "MAILB")) {
		return T_MAILB;		/* matches MB/MR/MG/MINFO */
	} else if(!strcasecmp(type, "MAILA")) {
		return T_MAILA;		/* matches MD/MF */
	} else if(!strcasecmp(type, "ANY")) {
		return T_ANY;		/* matches any type */
	} else {
		return -1;		/* unknown */
	}
}

#ifdef DEBUG
#	define PANIC { \
		h_errno = NO_RECOVERY;										\
		fprintf(stderr, "Error: res_pos = %i; type = %s (%i); line = %i\n", res_pos, dns_ttos(response[res_pos].type), response[res_pos].type, __LINE__);  \
		tmpint = -1;											\
		while(++tmpint < res_pos)									\
			fprintf(stderr, "%s %s\n", response[tmpint].name, dns_ttos(response[tmpint].type));	\
		return -1;											\
	}
#else
#	define PANIC {h_errno = NO_RECOVERY; return -1;}
#endif


/* Do a DNS lookup */
int lookup(const char *name, int class, int type, struct ns_response *response, int max_answers, char *buf, size_t buf_size) {
	unsigned char ans_buf[buf_size], *ptr, *data, *ans_end;
	HEADER *header;
	int loop, res_pos = 0, tmpint;

	/*
The format of a res_query response is something like this:
<header><qd records - qualified-domain><an records - requested data>
<ns records><ar records - additional resources>

 - All data is network-endian.  Remember to convert everything as you go.
 - All records are in the format <name (compressed string)><type (16 bits)>
<class (16 bits)><ttl (32 bits)><data_len (16 bits)><data_len bytes of actual data>
 - The header contains information on the sizes of the other records.
 - The qd records are bizarre.  They leave out the ttl and data_len and have no
actual data, so they're a special case.  They seem to be extraneous, so I just
skip them.  Maybe dn_expand() uses them?
 - The last three parts are all the same format.
 - Depend on data_len for getting to the next record, not the format of the
record itself because you probably won't always know the format for the type of
data in the record.  Remember, data_len does not include the length of the
name, type, class, ttl, or data_len.

The format of the actual data in each record is irritatingly variable, but it
seems to follow the order they are entered in the named zone files.  In
general:
 - domain names need to be dn_expand()ed
 - text fields are preceeded by a byte indicating their length and should not
be dn_expand()ed
 - numerical fields are raw 16 or 32 bit ints.

The MX record format is:  <priority (16 bits)><host name (compressed string)>
Use dn_expand() on the host name.

The HINFO record format is:
<string-length (byte)><CPU type (raw text string)><string-length (byte)><OS
type (raw text string)>

The A record format is simply:
<IP address (32 bits)>
	*/


	if((tmpint = res_query(name, class, type, ans_buf, sizeof(ans_buf))) == -1) return -1;
	if(tmpint > sizeof(ans_buf)) fprintf(stderr, "BUFFER OVERFLOW! res_query() returned a response with size %i into buffer with size %i in %s on line %i\n", tmpint, sizeof(ans_buf), __FILE__, __LINE__), fflush(stderr), kill(getpid(), SIGSEGV);
	ans_end = ans_buf + tmpint;  /* Bizarre parameter for calls to dn_expand() */
	data = ans_buf + sizeof(HEADER); /* Location of the data we're processing, for calls to dn_expand() */
	header = (HEADER *)ans_buf;

	/* Skip past this - it's just the name we looked up. */
	loop = ntohs(header->qdcount);
	while(loop--) {
		/* Get the length of the data so we can skip past it */
		if((tmpint = dn_expand(ans_buf, ans_end, data, buf, buf_size)) < 0) PANIC
		data += tmpint + sizeof(int16_t)*2; /* Skip past entry, type, and class */
	}

	/* This is the requested information. */
	loop = ntohs(header->ancount) + ntohs(header->nscount) + ntohs(header->arcount);
	while(loop-- && res_pos < max_answers) {
		/* Find out what host this record pertains to and the length of the data */
		if((tmpint = dn_expand(ans_buf, ans_end, data, buf, buf_size)) < 0) PANIC
		data += tmpint; /* Length of compressed name */
		response[res_pos].name = buf;
		tmpint = strlen(buf) + 1; /* Length of uncompressed name */
		buf += tmpint;
		buf_size -= tmpint;

		response[res_pos].type = ntohs(*(u_int16_t *)data);
		data += sizeof(u_int16_t);

		response[res_pos].class = ntohs(*(u_int16_t *)data);
		data += sizeof(u_int16_t);

		response[res_pos].ttl = ntohl(*(u_int32_t *)data);
		data += sizeof(u_int32_t);

		/* This gives us the position of the next record. */
		tmpint = ntohs(*(u_int16_t *)data);
		data += sizeof(u_int16_t);
		ptr = data;
		data += tmpint;
		/* ptr now points to the type-specific information.  Data now
		 * points to the next record.  Next we figure out how to
		 * interpret this record. */

		memset(&response[res_pos].info, 0, sizeof(response[res_pos].info));
		switch(response[res_pos].type) {
		case T_A:
			response[res_pos].info.a.s_addr = *(u_int32_t *)ptr;
		break;
		case T_MX:
			response[res_pos].info.mx.pref = ntohs(*(u_int16_t *)ptr);
			ptr += sizeof(u_int16_t);
		case T_CNAME:
		case T_NS:
		case T_PTR:
			if((tmpint = dn_expand(ans_buf, ans_end, ptr, buf, buf_size)) < 0) PANIC
			ptr += tmpint;
			response[res_pos].info.ptr.addr = buf;
			tmpint = strlen(buf) + 1;
			buf += tmpint;
			buf_size -= tmpint;
		break;
		case T_SOA:
			if((tmpint = dn_expand(ans_buf, ans_end, ptr, buf, buf_size)) < 0) PANIC
			ptr += tmpint;
			response[res_pos].info.soa.addr = buf;
			tmpint = strlen(buf) + 1;
			buf += tmpint;
			buf_size -= tmpint;

			if((tmpint = dn_expand(ans_buf, ans_end, ptr, buf, buf_size)) < 0) PANIC
			ptr += tmpint;
			response[res_pos].info.soa.maintainer = buf;
			tmpint = strlen(buf) + 1;
			buf += tmpint;
			buf_size -= tmpint;

			response[res_pos].info.soa.serial = ntohl(*(u_int32_t *)ptr);
			ptr += sizeof(u_int32_t);
			response[res_pos].info.soa.refresh = ntohl(*(u_int32_t *)ptr);
			ptr += sizeof(u_int32_t);
			response[res_pos].info.soa.retry = ntohl(*(u_int32_t *)ptr);
			ptr += sizeof(u_int32_t);
			response[res_pos].info.soa.expire = ntohl(*(u_int32_t *)ptr);
			ptr += sizeof(u_int32_t);
			response[res_pos].info.soa.def_ttl = ntohl(*(u_int32_t *)ptr);
			ptr += sizeof(u_int32_t);
		break;
		case T_NULL:
		break;
		case T_HINFO:
			response[res_pos].info.hinfo.cpu = 0;
			response[res_pos].info.hinfo.os = 0;

			tmpint = (unsigned char)*ptr++;  /* Length of this field */
			if(tmpint + 1 > buf_size) { h_errno = NO_RECOVERY; return -1; }
			memcpy(buf, ptr, tmpint);
			ptr += tmpint;
			response[res_pos].info.hinfo.cpu = buf;
			buf += tmpint;
			*buf++ = 0;
			buf_size -= tmpint+1;

			if(ptr >= data) break; /* Shouldn't happen, really. */

			tmpint = (unsigned char)*ptr++;  /* Length of this field */
			if(tmpint + 1 > buf_size) { h_errno = NO_RECOVERY; return -1; }
			memcpy(buf, ptr, tmpint);
			ptr += tmpint;
			response[res_pos].info.hinfo.os = buf;
			buf += tmpint;
			*buf++ = 0;
			buf_size -= tmpint+1;
		break;
		case T_TXT:
			response[res_pos].info.txt.text = 0;
			if(data - ptr > buf_size) { h_errno = NO_RECOVERY; return -1; }
			response[res_pos].info.txt.text = buf;
			tmpint = -1;
			while(ptr < data) {
				tmpint = (unsigned char)*ptr++;  /* Length of this field */
				if(tmpint > buf_size) { h_errno = NO_RECOVERY; return -1; }
				memcpy(buf, ptr, tmpint);
				ptr += tmpint;
				buf += tmpint;
				*buf++ = ' ';
				buf_size -= tmpint+1;
			}
			if(tmpint != -1) buf++;
			buf[-1] = 0;
		break;

// Add more types in here, and add them to the union in the header file.
		}

		res_pos++;
	}

	return res_pos;
}
