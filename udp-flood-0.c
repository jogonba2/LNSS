#include <stdio.h>
#include <stdlib.h>
// Arguments standarized and checked //
// Respects executable [[--source-addr saddr] [--[remote|broadcast]-addr raddr] [--source-port sport] [--remote-port rport] [--n N]] //

int main(int argc,char* argv[]){
	if(argc!=9){ fprintf(stdout,"Usage: udp-flood-0 --source-addr saddr --remote-addr raddr --source-port sport --n N\n");exit(0);}
	char* source_address = argv[2];
	char* remote_address = argv[4];
	char* source_port    = argv[6];
	unsigned int iter    = atoi(argv[8]);
	char* cli = (char*)malloc(1000);
	sprintf(cli,"./udp-flood --source-addr %s --remote-addr %s --source-port %s --remote-port 0 --n %d",source_address, \
			remote_address,source_port,iter);
	system(cli);
	free(cli);
	return 0;
}
