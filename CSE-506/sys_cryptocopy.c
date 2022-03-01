#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/fs.h>
#include <linux/uaccess.h>	/* for mm_segment_t??*/
#include <linux/slab.h>	 
#include <linux/crypto.h>
#include <crypto/hash.h>

asmlinkage extern long (*sysptr)(void *arg);

#define SHA256_LENGTH 32 

struct user_args {
	char *infile;
	char *outfile;
	void *keybuf;
	unsigned int keylen;
	unsigned char flag;
};

int check_valid_address(void* arg, int len){
	
	//Check if user arguments are NULL
	if(!arg){
		printk("User argument is empty\n");
		return -EINVAL;
	}

	//Check if the user has proper access for the buffer
	if(!access_ok(arg, len)){
		printk("Access to user is not valid\n");
		return -EFAULT;
	}

	return 0;
}

int copy_key_buff(struct user_args *kargs, struct user_args *arg, unsigned int key_len){
		int ret = 0;
		ret = check_valid_address(arg->keybuf, key_len);
		if(ret < 0){
			printk("[Error] Cannot validate user provided address for keybuf\n");
			goto out;
		}

		kargs->keybuf = kmalloc(key_len, GFP_KERNEL);

		if(!(kargs->keybuf)){
			printk("[Error] Unable to allocate memory to keybuf in kernel space\n");
			ret = -ENOMEM;
			goto out;
		}

		if(copy_from_user(kargs->keybuf, arg->keybuf, key_len)){
			printk("[Error] Failed copying keybuf from the user land to kernal land\n");
			ret = -EFAULT;
			goto out_kargs_keybuf;
		}

		printk("[TEST] PRINT KEYBUFF: %s\n", (char *)kargs->keybuf);

		out_kargs_keybuf:
			kfree(kargs->keybuf);
		out:
			return ret;
}

/*
	Validates the flags provided from the Userland. 
	If "flags & 0x1" is non-zero, then you should encrypt the infile onto the outfile.
	If "flags & 0x2" is non-zero, then you should decrypt the infile onto the outfile.
 	If "flags & 0x4" is non-zero, then you should just copy the infile to the outfile.
*/
int validate_flags(struct user_args *kargs){
	
	//Get the flags from kernelland args.
	unsigned char flag = kargs->flag;
	//Get the length of the key.
	unsigned int key_len = kargs->keylen;

	if(!flag){
		printk("No flag provided in input. Please provide flags\n");
		return -EINVAL;
	}

	if(!(flag & 0x1) && !(flag & 0x2) && !(flag & 0x4)){
		printk("Not a valid flag. Poosible flags include -e, -d, -c\n");
		return -EINVAL;
	}

	if(flag & 0x1 || flag & 0x2){
		if(!key_len){
			printk("Possword not provided. Password must be provided to encrypt/decrypt\n");
			return -EINVAL;
		}else if(key_len < 6){
			printk("Incorrect Password. Password should be atleast 6 characters\n");
			return -EINVAL;
		}
	}

	if(flag & 0x4 && key_len){
		printk("Too many arguments.\n");
		return -EINVAL;
	}
	printk("FLAG : %u\n", flag);
	return 0;
}

int read_file(struct file *in_filp, struct file *out_filp){

	ssize_t data_bytes_read = 0, data_bytes_write = 0;
	int ret = 0;
	
	//Allocate buffer of size PAGE_SiZE. When we read file we get PAGE_SIZE worth of bytes into the buffer and then use it.
	void* buf = kmalloc(PAGE_SIZE, GFP_KERNEL);

	if(!buf){
		ret = -ENOMEM;
		goto out; // Since the allocation fails we should just return the ret value
	}

	// bytes_read = kernel_read(in_filp, buf, PAGE_SIZE, &in_filp->f_pos);

	// printk("No. of bytes read: %ld", data_bytes);

	while((data_bytes_read = kernel_read(in_filp, buf, PAGE_SIZE, &in_filp->f_pos))>0){
		data_bytes_write = kernel_write(out_filp, buf, data_bytes_read, &out_filp->f_pos);
		if(data_bytes_write < 0){
			printk("[Error] Unable to write data to output file\n");
			ret = data_bytes_write;
			goto out_buf;
		}
	}

	if(data_bytes_read < 0){
		printk("[Error] Unable to read data from input file\n");
		ret = data_bytes_read;
		goto out_buf;
	}

	out_buf:
		kfree(buf);
	out:
		return ret;
}

int generate_hash(void *in_data, unsigned int in_len, void *hash_key_buff)
{
	struct shash_desc *desc;
	struct crypto_shash *tfm;
	int desc_size;
	int ret = 0;

	memset(hash_key_buff, 0, SHA256_LENGTH);

	tfm = crypto_alloc_shash("sha256", 0, CRYPTO_ALG_ASYNC);

	if (IS_ERR(tfm)) {
		pr_err("Could not allocate memory to tfm for sha256\n");
		ret = PTR_ERR(tfm);
		goto out_hash_key;
	}

	desc_size = crypto_shash_descsize(tfm) + sizeof(*desc);

	desc = kmalloc(desc_size, GFP_KERNEL);
	if (!desc) {
		ret = -ENOMEM;
		goto out_free_shash;
	}
	desc->tfm =  tfm;

	ret = crypto_shash_digest(desc, (u8 *)in_data, in_len, (u8 *)hash_key_buff);
	if (ret < 0) {
		pr_err("Error in hashing the key\n");
		goto out_free_desc;
	}
	
out_free_desc:
	desc->tfm = NULL;
	kfree(desc);
out_free_shash:
	crypto_free_shash(tfm);
out_hash_key:
	return ret;
}


asmlinkage long cryptocopy(void *arg)
{
	void* kargs = NULL;
	struct file* in_filp = NULL, *out_filp = NULL;
	struct filename* kinfile_name = NULL, *koutfile_name = NULL;
	unsigned char flag;
	unsigned int key_len;
	int ret = 0;
	void* hash_key_buff = NULL;

	ret = check_valid_address(arg, sizeof(struct user_args));

	if(ret < 0){
		printk("[Error] Cannot validate user provided address for arg\n");
		goto out;
	}

	//Allocate memory to copy the Userland args to Kernelland.
	kargs = kmalloc(sizeof(struct user_args), GFP_KERNEL);

	//If the memory allocation fails. Return ENOMEM Error.
	if(!kargs){
		ret = -ENOMEM;
		goto out; // Since the allocation fails we should just return the ret value
	}

	//Copy the arguments from the Userland to the KernelLand.
	if(copy_from_user(kargs, arg, sizeof(struct user_args))){
		printk("[Error] Failed copying arguments from the user land to kernal land\n");
		ret = -EFAULT;
		goto out_karg;
	}
	//Get the flags from kernelland args.
	flag = ((struct user_args*)kargs)->flag;
	//Get the length of the key.
	key_len = ((struct user_args*)kargs)->keylen;
	
	ret = validate_flags(kargs);

	if(ret < 0){
		goto out_karg;
	}

	if(flag & 0x1 || flag & 0x2){
		ret = copy_key_buff(kargs, arg, key_len);
		if(ret < 0){
			goto out_karg;
		}

		hash_key_buff = kmalloc(SHA256_LENGTH, GFP_KERNEL);
		if (!hash_key_buff) {
			ret = -ENOMEM;
			goto out_karg;
		}

		ret = generate_hash(((struct user_args *)kargs)->keybuf, key_len,
			       hash_key_buff);
		if (ret < 0)
			goto out_hash_key_buff;	
	}

	//Get the input filename from the user args
	kinfile_name = getname(((struct user_args *)arg) -> infile);
	
	if(IS_ERR(kinfile_name)){
		ret = PTR_ERR(kinfile_name);
		goto out_karg;
	}

	//Open the inpute file 
	in_filp = filp_open(kinfile_name->name, O_RDONLY, 0);
	
	if(IS_ERR(in_filp)){
		ret = PTR_ERR(in_filp);
		goto out_kinfile_name;
	}

	//Get the output filename from the user args.
	koutfile_name = getname(((struct user_args *)arg) -> outfile);
	
	if(IS_ERR(koutfile_name)){
		ret = PTR_ERR(koutfile_name);
		goto out_in_filp;
	}

	//Open the output file.
	out_filp = filp_open(koutfile_name->name, O_WRONLY, 0);
	
	if(IS_ERR(out_filp)){
		ret = PTR_ERR(out_filp);
		goto out_koutfile_name;
	}

	ret = read_file(in_filp, out_filp);

	if(ret < 0){
		printk("Error in reading the file");
		goto out_out_filp;
	}

	out_out_filp:
		filp_close(out_filp, NULL);
	out_koutfile_name:
		putname(koutfile_name);
	out_in_filp:
		filp_close(in_filp, NULL);
	out_kinfile_name:
		putname(kinfile_name);
	out_hash_key_buff:
		kfree(hash_key_buff);
	out_karg:
		kfree(kargs);
	out:
		return ret;
}

static int __init init_sys_cryptocopy(void)
{
	printk("installed new sys_cryptocopy module\n");
	if (sysptr == NULL)
		sysptr = cryptocopy;
	return 0;
}
static void  __exit exit_sys_cryptocopy(void)
{
	if (sysptr != NULL)
		sysptr = NULL;
	printk("removed sys_cryptocopy module\n");
}
module_init(init_sys_cryptocopy);
module_exit(exit_sys_cryptocopy);
MODULE_LICENSE("GPL");