#include "sockutil.h"
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>


//#define DEBUG

int server_tcp(u_int32_t address, u_int16_t port) {
	int listenfd, sockfd, tmpint;
	struct sockaddr_in listen_sock, remote_sock;

	memset(&listen_sock, 0, sizeof(listen_sock));
#ifndef __linux__
	listen_sock.sin_len = sizeof(listen_sock);
#endif
	listen_sock.sin_family = AF_INET;
	listen_sock.sin_port = htons(port);
	listen_sock.sin_addr.s_addr = htonl(address);

	if((listenfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) return -1;
	if(bind(listenfd, (struct sockaddr *)&listen_sock, sizeof(listen_sock)) == -1) return -1;
	if(listen(listenfd, 128) == -1) return -1;
	while(1) {
		tmpint = sizeof(remote_sock);
		if((sockfd = accept(listenfd, (struct sockaddr *)&remote_sock, &tmpint)) == -1) return -1;
		tmpint = fork();
/*		if(tmpint == -1) Just close() and keep listening. */
		if(tmpint == 0) break; /* Child breaks */
		close(sockfd);
	}
	/* Child server */
	close(listenfd);
	return sockfd;
}

int ident(int fd, char *buf, size_t buf_size) {
	struct sockaddr_in their_addr, my_addr;
	int sockfd, tmpint, my_port, their_port;
	FILE *sockfp;
	char *ptr1, *ptr2;

	memset(&my_addr, 0, sizeof(my_addr));
	tmpint = sizeof(my_addr);
	if(getsockname(fd, (struct sockaddr *)&my_addr, &tmpint)) return -1;
	my_port = ntohs(my_addr.sin_port);
	my_addr.sin_port = 0;

	memset(&their_addr, 0, sizeof(their_addr));
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
	char *names[256] = {
		0,		/*   0 */
		"A",		/*   1 */	/* internet address */
		"NS",		/*   2 */	/* authoritative server */
		"MD",		/*   3 */	/* mail destination */
		"MF",		/*   4 */	/* mail forwarder */
		"CNAME",	/*   5 */	/* canonical name */
		"SOA",		/*   6 */	/* start of auth zone */
		"MB",		/*   7 */	/* mailbox domain name */
		"MG",		/*   8 */	/* mail group member */
		"MR",		/*   9 */	/* mail rename name */
		"NULL",		/*  10 */	/* null resource record */
		"WKS",		/*  11 */	/* well known service */
		"PTR",		/*  12 */	/* domain name pointer */
		"HINFO",	/*  13 */	/* host information */
		"MINFO",	/*  14 */	/* mailbox information */
		"MX",		/*  15 */	/* mail routing info */
		"TXT",		/*  16 */	/* descriptive text */
		"RP",		/*  17 */	/* responsible person */
		"AFSDB",	/*  18 */	/* afs database location */
		"X25",		/*  19 */	/* x25 address */
		"ISDN",		/*  20 */	/* isdn address */
		"RT",		/*  21 */	/* route through host */
		"NSAP",		/*  22 */	/* nsap address */
		"NSAP_PTR",	/*  23 */	/* reverse NSAP lookup (deprecated) */
		"SIG",		/*  24 */	/* security signature */
		"KEY",		/*  25 */	/* security key */
		"PX",		/*  26 */	/* rfc822 - x400 mapping */
		"GPOS",		/*  27 */	/* geographical position (withdrawn) */
		"AAAA",		/*  28 */	/* ip v6 address */
		"LOC",		/*  29 */	/* geographical location */
		"NXT",		/*  30 */	/* next valid name */
		"EID",		/*  31 */	/* endpoint identifier */
		"NIMLOC",	/*  32 */	/* nimrod locator */
		"SRV",		/*  33 */	/* service info */
		"ATMA",		/*  34 */	/* atm address */
		"NAPTR",	/*  35 */	/* naming authority urn */
		0,		/*  36 */
		0,		/*  37 */
		0,		/*  38 */
		0,		/*  39 */
		0,		/*  40 */
		0,		/*  41 */
		0,		/*  42 */
		0,		/*  43 */
		0,		/*  44 */
		0,		/*  45 */
		0,		/*  46 */
		0,		/*  47 */
		0,		/*  48 */
		0,		/*  49 */
		0,		/*  50 */
		0,		/*  51 */
		0,		/*  52 */
		0,		/*  53 */
		0,		/*  54 */
		0,		/*  55 */
		0,		/*  56 */
		0,		/*  57 */
		0,		/*  58 */
		0,		/*  59 */
		0,		/*  60 */
		0,		/*  61 */
		0,		/*  62 */
		0,		/*  63 */
		0,		/*  64 */
		0,		/*  65 */
		0,		/*  66 */
		0,		/*  67 */
		0,		/*  68 */
		0,		/*  69 */
		0,		/*  70 */
		0,		/*  71 */
		0,		/*  72 */
		0,		/*  73 */
		0,		/*  74 */
		0,		/*  75 */
		0,		/*  76 */
		0,		/*  77 */
		0,		/*  78 */
		0,		/*  79 */
		0,		/*  80 */
		0,		/*  81 */
		0,		/*  82 */
		0,		/*  83 */
		0,		/*  84 */
		0,		/*  85 */
		0,		/*  86 */
		0,		/*  87 */
		0,		/*  88 */
		0,		/*  89 */
		0,		/*  90 */
		0,		/*  91 */
		0,		/*  92 */
		0,		/*  93 */
		0,		/*  94 */
		0,		/*  95 */
		0,		/*  96 */
		0,		/*  97 */
		0,		/*  98 */
		0,		/*  99 */
		"UINFO",	/* 100 */	/* user information (non-standard) */
		"UID",		/* 101 */	/* user ident (non-standard) */
		"GID",		/* 102 */	/* group ident (non-standard) */
		"UNSPEC",	/* 103 */	/* unspecified binary data (non-standard) */
		0,		/* 104 */
		0,		/* 105 */
		0,		/* 106 */
		0,		/* 107 */
		0,		/* 108 */
		0,		/* 109 */
		0,		/* 110 */
		0,		/* 111 */
		0,		/* 112 */
		0,		/* 113 */
		0,		/* 114 */
		0,		/* 115 */
		0,		/* 116 */
		0,		/* 117 */
		0,		/* 118 */
		0,		/* 119 */
		0,		/* 120 */
		0,		/* 121 */
		0,		/* 122 */
		0,		/* 123 */
		0,		/* 124 */
		0,		/* 125 */
		0,		/* 126 */
		0,		/* 127 */
		0,		/* 128 */
		0,		/* 129 */
		0,		/* 130 */
		0,		/* 131 */
		0,		/* 132 */
		0,		/* 133 */
		0,		/* 134 */
		0,		/* 135 */
		0,		/* 136 */
		0,		/* 137 */
		0,		/* 138 */
		0,		/* 139 */
		0,		/* 140 */
		0,		/* 141 */
		0,		/* 142 */
		0,		/* 143 */
		0,		/* 144 */
		0,		/* 145 */
		0,		/* 146 */
		0,		/* 147 */
		0,		/* 148 */
		0,		/* 149 */
		0,		/* 150 */
		0,		/* 151 */
		0,		/* 152 */
		0,		/* 153 */
		0,		/* 154 */
		0,		/* 155 */
		0,		/* 156 */
		0,		/* 157 */
		0,		/* 158 */
		0,		/* 159 */
		0,		/* 160 */
		0,		/* 161 */
		0,		/* 162 */
		0,		/* 163 */
		0,		/* 164 */
		0,		/* 165 */
		0,		/* 166 */
		0,		/* 167 */
		0,		/* 168 */
		0,		/* 169 */
		0,		/* 170 */
		0,		/* 171 */
		0,		/* 172 */
		0,		/* 173 */
		0,		/* 174 */
		0,		/* 175 */
		0,		/* 176 */
		0,		/* 177 */
		0,		/* 178 */
		0,		/* 179 */
		0,		/* 180 */
		0,		/* 181 */
		0,		/* 182 */
		0,		/* 183 */
		0,		/* 184 */
		0,		/* 185 */
		0,		/* 186 */
		0,		/* 187 */
		0,		/* 188 */
		0,		/* 189 */
		0,		/* 190 */
		0,		/* 191 */
		0,		/* 192 */
		0,		/* 193 */
		0,		/* 194 */
		0,		/* 195 */
		0,		/* 196 */
		0,		/* 197 */
		0,		/* 198 */
		0,		/* 199 */
		0,		/* 200 */
		0,		/* 201 */
		0,		/* 202 */
		0,		/* 203 */
		0,		/* 204 */
		0,		/* 205 */
		0,		/* 206 */
		0,		/* 207 */
		0,		/* 208 */
		0,		/* 209 */
		0,		/* 210 */
		0,		/* 211 */
		0,		/* 212 */
		0,		/* 213 */
		0,		/* 214 */
		0,		/* 215 */
		0,		/* 216 */
		0,		/* 217 */
		0,		/* 218 */
		0,		/* 219 */
		0,		/* 220 */
		0,		/* 221 */
		0,		/* 222 */
		0,		/* 223 */
		0,		/* 224 */
		0,		/* 225 */
		0,		/* 226 */
		0,		/* 227 */
		0,		/* 228 */
		0,		/* 229 */
		0,		/* 230 */
		0,		/* 231 */
		0,		/* 232 */
		0,		/* 233 */
		0,		/* 234 */
		0,		/* 235 */
		0,		/* 236 */
		0,		/* 237 */
		0,		/* 238 */
		0,		/* 239 */
		0,		/* 240 */
		0,		/* 241 */
		0,		/* 242 */
		0,		/* 243 */
		0,		/* 244 */
		0,		/* 245 */
		0,		/* 246 */
		0,		/* 247 */
		0,		/* 248 */
		0,		/* 249 */
		0,		/* 250 */
		"IXFR",		/* 251 */	/* incremental zone transfer */
		"AXFR",		/* 252 */	/* transfer zone of authority */
		"MAILB",	/* 253 */	/* matches MB/MR/MG/MINFO */
		"MAILA",	/* 254 */	/* matches MD/MF */
		"ANY"		/* 255 */	/* matches any type */
	};

	if(type >= 0 && type <= 255)
		return names[type];
	return 0;	/* NULL == Unknown */
}


/* type-to-string converter */
int dns_stot(const char *type) {
	if(!strcasecmp(type, "A"))
		return 1;	/* T_A */	/* internet address */
	else if(!strcasecmp(type, "NS"))
		return 2;	/* T_NS */	/* authoritative server */
	else if(!strcasecmp(type, "MD"))
		return 3;	/* T_MD */	/* mail destination */
	else if(!strcasecmp(type, "MF"))
		return 4;	/* T_MF */	/* mail forwarder */
	else if(!strcasecmp(type, "CNAME"))
		return 5;	/* T_CNAME */	/* canonical name */
	else if(!strcasecmp(type, "SOA"))
		return 6;	/* T_SOA */	/* start of auth zone */
	else if(!strcasecmp(type, "MB"))
		return 7;	/* T_MB */	/* mailbox domain name */
	else if(!strcasecmp(type, "MG"))
		return 8;	/* T_MG */	/* mail group member */
	else if(!strcasecmp(type, "MR"))
		return 9;	/* T_MR */	/* mail rename name */
	else if(!strcasecmp(type, "NULL"))
		return 10;	/* T_NULL */	/* null resource record */
	else if(!strcasecmp(type, "WKS"))
		return 11;	/* T_WKS */	/* well known service */
	else if(!strcasecmp(type, "PTR"))
		return 12;	/* T_PTR */	/* domain name pointer */
	else if(!strcasecmp(type, "HINFO"))
		return 13;	/* T_HINFO */	/* host information */
	else if(!strcasecmp(type, "MINFO"))
		return 14;	/* T_MINFO */	/* mailbox information */
	else if(!strcasecmp(type, "MX"))
		return 15;	/* T_MX */	/* mail routing info */
	else if(!strcasecmp(type, "TXT"))
		return 16;	/* T_TXT */	/* descriptive text */
	else if(!strcasecmp(type, "RP"))
		return 17;	/* T_RP */	/* responsible person */
	else if(!strcasecmp(type, "AFSDB"))
		return 18;	/* T_AFSDB */	/* afs database location */
	else if(!strcasecmp(type, "X25"))
		return 19;	/* T_X25 */	/* x25 address */
	else if(!strcasecmp(type, "ISDN"))
		return 20;	/* T_ISDN */	/* isdn address */
	else if(!strcasecmp(type, "RT"))
		return 21;	/* T_RT */	/* route through host */
	else if(!strcasecmp(type, "NSAP"))
		return 22;	/* T_NSAP */	/* nsap address */
	else if(!strcasecmp(type, "NSAP_PTR"))
		return 23;	/* T_NSAP_PTR*/	/* reverse NSAP lookup (deprecated) */
	else if(!strcasecmp(type, "SIG"))
		return 24;	/* T_SIG */	/* security signature */
	else if(!strcasecmp(type, "KEY"))
		return 25;	/* T_KEY */	/* security key */
	else if(!strcasecmp(type, "PX"))
		return 26;	/* T_PX */	/* rfc822 - x400 mapping */
	else if(!strcasecmp(type, "GPOS"))
		return 27;	/* T_GPOS */	/* geographical position (withdrawn) */
	else if(!strcasecmp(type, "AAAA"))
		return 28;	/* T_AAAA */	/* ip v6 address */
	else if(!strcasecmp(type, "LOC"))
		return 29;	/* T_LOC */	/* geographical location */
	else if(!strcasecmp(type, "NXT"))
		return 30;	/* T_NXT */	/* next valid name */
	else if(!strcasecmp(type, "EID"))
		return 31;	/* T_EID */	/* endpoint identifier */
	else if(!strcasecmp(type, "NIMLOC"))
		return 32;	/* T_NIMLOC */	/* nimrod locator */
	else if(!strcasecmp(type, "SRV"))
		return 33;	/* T_SRV */	/* service info */
	else if(!strcasecmp(type, "ATMA"))
		return 34;	/* T_ATMA */	/* atm address */
	else if(!strcasecmp(type, "NAPTR"))
		return 35;	/* T_NAPTR */	/* naming authority urn */
	else if(!strcasecmp(type, "UINFO"))
		return 100;	/* T_UINFO */	/* user information */
	else if(!strcasecmp(type, "UID"))
		return 101;	/* T_UID */	/* user ident */
	else if(!strcasecmp(type, "GID"))
		return 102;	/* T_GID */	/* group ident */
	else if(!strcasecmp(type, "UNSPEC"))
		return 103;	/* T_UNSPEC */	/* unspecified binary data */
	else if(!strcasecmp(type, "IXFR"))
		return 251;	/* T_IXFR */	/* incremental zone transfer */
	else if(!strcasecmp(type, "AXFR"))
		return 252;	/* T_AXFR */	/* zone transfer */
	else if(!strcasecmp(type, "MAILB"))
		return 253;	/* T_MAILB */	/* matches MB/MR/MG/MINFO */
	else if(!strcasecmp(type, "MAILA"))
		return 254;	/* T_MAILA */	/* matches MD/MF */
	else if(!strcasecmp(type, "ANY"))
		return 255;	/* T_ANY */	/* matches any type */
	else
		return -1;			/* unknown */
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
			response[res_pos].info.a.addr = ntohl(*(u_int32_t *)ptr);
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
#undef PANIC
