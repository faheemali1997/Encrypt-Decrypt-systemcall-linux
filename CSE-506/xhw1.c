#include <asm/unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <openssl/md5.h>
#include <string.h>
#include <getopt.h>

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

int validate_password(char *optarg){
	if(!optarg)
	{
		printf("No password provided with -p flag\n");
		return -EINVAL;
	}
	int index = 0;
	for (int i = 0; i < strlen(optarg); i++) {
		if (optarg[i] != '\n')
			optarg[index++] = optarg[i];
	}
	optarg[index] = '\0';
	if (strlen(optarg) < 6) {
		printf("Password should be atleast 6 characters.\n");
		return -EINVAL;
	}
	return 0;
}

int validate_flags(struct user_args *uargs){
	
	//Get the flags from kernelland args.
	unsigned char flag = uargs->flag;
	//Get the length of the key.
	unsigned int key_len = uargs->keylen;

	if(!flag){
		printf("No flag provided in input. Please provide flags\n");
		return -EINVAL;
	}

	if(!(flag & 0x1) && !(flag & 0x2) && !(flag & 0x4)){
		printf("Not a valid flag. Poosible flags include -e, -d, -c\n");
		return -EINVAL;
	}

	if(flag & 0x1 || flag & 0x2){
		if(!key_len){
			printf("Possword not provided. Password must be provided to encrypt/decrypt\n");
			return -EINVAL;
		}else if(key_len < 6){
			printf("Incorrect Password. Password should be atleast 6 characters\n");
			return -EINVAL;
		}
	}

	if(flag & 0x4 && key_len){
		printf("Too many arguments.\n");
		return -EINVAL;
	}
	return 0;
}

int main(int argc, char* const argv[])
{
	int ret = 0, opt;
	struct user_args *uargs = (struct user_args*)malloc(sizeof(struct user_args));
	if(uargs == NULL){
		printf("Cannot allocate memory for args");
		goto out;
	}

	while((opt = getopt(argc, argv, "edcp:")) != -1){
		switch(opt){
			case 'c':
				uargs->flag |= 4;
				break;
			case 'e':
				uargs->flag |= 1;
				break;
			case 'd':
				uargs->flag |= 2;
				break;
			case 'p':
				ret = validate_password(optarg);
				if(ret < 0){
					goto out_uargs;
				}

				unsigned char key[MD5_KEY_LENGTH];
				generate_key(optarg, key);
				
				uargs->keybuf = malloc(MD5_KEY_LENGTH);
				if(!(uargs->keybuf)){
					printf("[Error] Unable to allocate memeory for keynuf\n");
					ret = -ENOMEM;
					goto out_uargs;
				}
				uargs->keylen = MD5_KEY_LENGTH;
				memcpy(uargs->keybuf, (void *)key, MD5_KEY_LENGTH);
		}
	}

	ret = validate_flags(uargs);
	if(ret < 0){
		goto out_uargs_keybuff;
	}

	// (*uargs).infile = argv[optind++];
	// (*uargs).outfile = argv[optind];

	if(optind < argc){
		if(argv[optind][0] == '\0'){
			printf("Input filename not provided\n");
			ret = -EINVAL;
			goto out_uargs_keybuff;
		}else{
			(*uargs).infile = argv[optind++];
		}
	}

	if(optind < argc){
		if(argv[optind][0] == '\0'){
			printf("Output filename not provided\n");
			ret = -EINVAL;
			goto out_uargs_keybuff;
		}else{
			(*uargs).outfile = argv[optind];
		}
	}

	printf("Flag %u\n", uargs->flag);
	printf("Infile : %s \n", (char *)uargs->infile);
	printf("Outfile : %s \n", (char *)uargs->outfile);

	ret = syscall(__NR_cryptocopy, uargs);
	if(ret < 0)
		goto out_uargs_keybuff;

	out_uargs_keybuff:
		free(uargs->keybuf);
	out_uargs:
		free(uargs);
	out:
		if (ret == 0)
			printf("syscall returned %d\n", ret);
		else
			printf("syscall returned %d (errno=%d)\n", ret, errno);
		exit(ret);
}