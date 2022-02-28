#include <asm/unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>

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
	int ret;
	// void *dummy = (void *) argv[1];
	struct user_args* uargs = (struct user_args*) malloc(sizeof(struct user_args));

	if(!uargs){
		printf("[Error] Unable to allocate memeory for keynuf\n");
		ret = -ENOMEM;
		goto out;
	}

	const char src[9] = "password";
	uargs->infile = "infile";
	uargs->outfile = "outfile";
	uargs->keylen = 9;
	uargs->flag = (unsigned char)0x01;

	uargs->keybuf = malloc(uargs->keylen);
	
	if(!uargs->keybuf){
		printf("[Error] Unable to allocate memeory for keynuf\n");
		ret = -ENOMEM;
		goto out_uargs;
	}
	
	memcpy(uargs->keybuf, src, uargs->keylen);

  	ret = syscall(__NR_cryptocopy, uargs);

	goto out_uargs_keybuf;

	out_uargs_keybuf:
		free(uargs->keybuf);
	out_uargs:
		free(uargs);
	out:
		return ret;
	// if (ret == 0){
	// 	printf("In UserLand\n");
	// 	printf("syscall returned %d\n", ret);
	// }
	// else
	// 	printf("syscall returned %d (errno=%d)\n", ret, errno);

	// exit(ret);
}