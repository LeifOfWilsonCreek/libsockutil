#include "sockutil.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char **argv) {
	int ret, loop, type;
	struct ns_response response[32];
	char buf[8192];

	if(argc != 3) {
		printf("usage: %s hostname type\n", argv[0]);
		return 1;
	}

	if((type = dns_stot(argv[2])) == -1) {
		printf("Unknown type.\n");
		return 1;
	}

	printf("Looking up %s for %s...\n", dns_ttos(type), argv[1]);
	ret = lookup(argv[1], C_IN, type, response, 32, buf, sizeof(buf));
	if(ret == -2) {
		fprintf(stderr, "Garbled data was returned.\n");
		return 1;
	}
	if(ret == -1) {
		fprintf(stderr, "Error: %s\n", hstrerror(h_errno));
		return 1;
	}
	if(ret < 0) {
		fprintf(stderr, "Shouldn't happen.\n");
		return 1;
	}
	printf("Found %i entries:\n", ret);
	printf("%-25s %-7s %-7s %s\n", "NAME", "TYPE", "TTL", "DATA");
	for(loop = 0; loop < ret; loop++) {
		printf("%-25.25s %-7.7s %7i ", response[loop].name, dns_ttos(response[loop].type), response[loop].ttl);
		switch(response[loop].type) {
		case T_A:
			printf("%s\n", inet_ntoa(response[loop].info.a));
		break;
		case T_MX:
			printf("%3i %s\n", response[loop].info.mx.pref, response[loop].info.mx.addr);
		break;
		case T_CNAME:
			printf("%s\n", response[loop].info.cname.addr);
		break;
		case T_NS:
			printf("%s\n", response[loop].info.ns.addr);
		break;
		case T_PTR:
			printf("%s\n", response[loop].info.ptr.addr);
		break;
		case T_SOA:
			printf("a = %s; m = %s; s = %i; ref = %i; ret = %i; e = %i; t = %i\n", response[loop].info.soa.addr, response[loop].info.soa.maintainer, response[loop].info.soa.serial, response[loop].info.soa.refresh, response[loop].info.soa.retry, response[loop].info.soa.expire, response[loop].info.soa.def_ttl);
		break;
		case T_NULL:
			printf("\n");
		break;
		case T_HINFO:
			printf("cpu = %s; os = %s\n", response[loop].info.hinfo.cpu, response[loop].info.hinfo.os);
		break;
		case T_TXT:
			printf("%s\n", response[loop].info.txt.text);
		break;
		case 0:
			printf("%s\n", response[loop].info.ptr.addr);
		break;
		default:
			printf("Unsupported entry.\n");
		}
	}

	return 0;
}
