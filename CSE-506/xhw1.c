#include <asm/unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef __NR_cryptocopy
#error cryptocopy system call not defined
#endif

struct user_args {
	char *infile;
	char *outfile;
	void *keybuf;
	unsigned int keylen;
	unsigned char flag;
};

int main(int argc, const char *argv[])
{
	int rc;
	// void *dummy = (void *) argv[1];

	struct user_args* uargs = (struct user_args*) malloc(sizeof(struct user_args));

	if(uargs == NULL){
		exit(1);
	}

	uargs->flag = (unsigned char)0x01;

	free(uargs);

  	rc = syscall(__NR_cryptocopy, uargs);
	
	if (rc == 0){
		printf("In UserLand\n");
		printf("syscall returned %d\n", rc);
	}
	else
		printf("syscall returned %d (errno=%d)\n", rc, errno);

	exit(rc);
}