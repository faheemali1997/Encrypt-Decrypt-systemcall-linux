#include <asm/unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <openssl/md5.h>
#include <string.h>

#ifndef __NR_cryptocopy
#error cryptocopy system call not defined
#endif

#define MD5_KEY_LENGTH 16

struct user_args {
	char *infile;
	char *outfile;
	void *keybuf;
	unsigned int keylen;
	unsigned char flag;
};

void generate_key(char *password, unsigned char *key)
{
	MD5_CTX ctx;

	MD5_Init(&ctx);
	MD5_Update(&ctx, password, strlen(password));
	MD5_Final(key, &ctx);
}

int main(int argc, const char *argv[])
{
	int ret;
	
	struct user_args *uargs = (struct user_args*)malloc(sizeof(struct user_args));
	
	if(uargs == NULL){
		printf("Cannot allocate memory for args");
		exit(1);
	}
	unsigned char key[MD5_KEY_LENGTH];
	char *passkey = "password";

	generate_key(passkey, key);

	uargs->infile = "file2";
	uargs->outfile = "file3";
	uargs->keybuf = malloc(MD5_KEY_LENGTH);
	uargs->flag = 0x02;
	uargs->keylen = MD5_KEY_LENGTH;

	memcpy(uargs->keybuf, (void *)key, MD5_KEY_LENGTH);

	printf("%s", (char *)uargs->keybuf);

  	ret = syscall(__NR_cryptocopy, uargs);

	if (ret == 0)
		printf("syscall returned %d\n", ret);
	else
		printf("syscall returned %d (errno=%d)\n", ret, errno);

	exit(ret);
}