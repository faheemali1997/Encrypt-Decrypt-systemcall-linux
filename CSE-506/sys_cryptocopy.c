#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/fs.h>
#include <linux/uaccess.h>	/* for mm_segment_t??*/
#include <linux/slab.h>	 
#include <linux/crypto.h>
#include <crypto/hash.h>
#include <crypto/skcipher.h>
#include <linux/scatterlist.h>

asmlinkage extern long (*sysptr)(void *arg);

#define SHA256_LENGTH 32 

struct user_args {
	char *infile;
	char *outfile;
	void *keybuf;
	unsigned int keylen;
	unsigned char flag;
};

struct skcipher_def {
	struct scatterlist sg;
	struct crypto_skcipher *tfm;
	struct skcipher_request *req;
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

static int encrypt_decrypt(struct skcipher_request *req, void *buf, int buf_len, char *ivdata, unsigned char flag)
{
	struct scatterlist *sg;
	struct crypto_wait *wait;
	int ret = 0;

	wait = kmalloc(sizeof(*wait), GFP_KERNEL);
	if (!wait) {
		ret = -ENOMEM;
		goto out1;
	}

	skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG, crypto_req_done, wait);

	sg = kmalloc(sizeof(*sg), GFP_KERNEL);
	if (!sg) {
		ret =  -ENOMEM;
		goto out_kfree_wait;
	}

	sg_init_one(sg, buf, buf_len);
	skcipher_request_set_crypt(req, sg, sg, buf_len, ivdata);
	crypto_init_wait(wait);

	if (flag & 0x1)
		ret = crypto_wait_req(crypto_skcipher_encrypt(req), wait);
	else
		ret = crypto_wait_req(crypto_skcipher_decrypt(req), wait);

	kfree(sg);
out_kfree_wait:
	kfree(wait);
out1:
	return ret;
}


int read_write(struct file *infile_ptr, struct file *outfile_ptr, void **ivdata,
	       void *key, unsigned int keylen, char *cipher_name,
	       unsigned char flag)
{
	ssize_t bytes_read = 0, bytes_wrote = 0, ret = 0;
	struct crypto_skcipher *skcipher = NULL;
	struct skcipher_request *req = NULL;
	void *buf;
	loff_t infile_size;
	if (flag & 0x1 || flag & 0x2) {
		skcipher = crypto_alloc_skcipher(cipher_name, 0, 0);
		if (IS_ERR(skcipher)) {
			ret = PTR_ERR(skcipher);
			goto out_read_write;
		}
		req = skcipher_request_alloc(skcipher, GFP_KERNEL);
		if (!req) {
			ret = -ENOMEM;
			goto out_clean_cipher_handles;
		}
		if (crypto_skcipher_setkey(skcipher, key, keylen)) {
			pr_err("Error in setting key in skcipher\n");
			ret = -EAGAIN;
			goto out_clean_cipher_handles;
		}
	}

	buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!buf) {
		ret = -ENOMEM;
		goto out_clean_cipher_handles;
	}

	infile_size = infile_ptr->f_inode->i_size;
	while ((bytes_read = kernel_read(infile_ptr, buf, PAGE_SIZE,
					 &infile_ptr->f_pos)) > 0) {
		/* if flag is 0x4 then directly jump to writing in file */
		if (flag & 0x4)
			goto out_write_in_file;	
		ret = encrypt_decrypt(req, buf, bytes_read, (char *)(*ivdata),
				      flag);
		if (ret < 0)
			goto out_kfree_buf;

	out_write_in_file:
		bytes_wrote = kernel_write(outfile_ptr, buf, bytes_read,
					   &outfile_ptr->f_pos);
		if (bytes_wrote < 0) {
			pr_err("Error in writing data to output file\n");
			ret = bytes_wrote;
			goto out_clean_cipher_handles;
		}
	}
	/*
	 * if bytes read is  0 but it fails on reading
	 * then set ret to -EINVAL
	 */
	if (bytes_read < 0 || infile_size < infile_ptr->f_pos) {
		ret = bytes_read ? bytes_read : -EINVAL;
		goto out_kfree_buf;
	}

out_kfree_buf:
	kfree(buf);
out_clean_cipher_handles:
	if (flag & 0x1 || flag & 0x2) {
		kfree(req);
		if (skcipher)
			crypto_free_skcipher(skcipher);
	}
out_read_write:
	return ret;
}

int copy_file(struct file *in_filp, struct file *out_filp){

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


/**
 * Reference: https://gist.github.com/vkobel/3100cea3625ca765e4153782314bd03d
 */
int generate_hash(void *in_data, unsigned int in_len, void *hash_key_buff)
{
	struct shash_desc *desc;
	struct crypto_shash *tfm;
	int desc_size;
	int ret = 0;

	memset(hash_key_buff, 0, SHA256_LENGTH);

	tfm = crypto_alloc_shash("sha256", 0, CRYPTO_ALG_ASYNC);

	if (IS_ERR(tfm)) {
		pr_err("Could not allocate memory to tfm for sha512\n");
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

int get_stat(const char *name, struct kstat **file_stat)
{
	mm_segment_t old_fs;
	int ret;
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	ret = vfs_stat(name, *(file_stat));
	set_fs(old_fs);
	return ret;
}

int validate_open_input_file(struct user_args *arg, struct file** in_filp, struct kstat *infile_stat){
	// struct kstat *infile_stat;
	struct filename *kinfile_name;
	int ret = 0;

	//Get the input filename from the user args
	kinfile_name = getname(arg->infile);
	if(IS_ERR(kinfile_name)){
		ret = PTR_ERR(kinfile_name);
		goto out;
	}

	infile_stat = kmalloc(sizeof(*infile_stat), GFP_KERNEL);
	if (!infile_stat) {
		ret = -ENOMEM;
		goto out_kinfile_name;
	}

	ret = get_stat(kinfile_name->name, &infile_stat);
	if (ret < 0) {
		printk("Input file does not exist\n");
		goto out_kinfile_name;
	}

	if (!S_ISREG(infile_stat->mode)) {
		printk("Input file is not a regular file\n");
		ret = -EINVAL;
		goto out_kinfile_name;
	} 
	
	if(S_ISDIR(infile_stat->mode)){
		printk("Input file is a directory\n");
		ret = -EINVAL;
		goto out_kinfile_name;
	}

	//Open the inpute file 
	(*in_filp) = filp_open(kinfile_name->name, O_RDONLY, 0);
	if(IS_ERR(in_filp)){
		ret = PTR_ERR(in_filp);
		goto out_kinfile_name;
	}

	// out_infile_stat:
	// 	kfree(infile_stat);
	out_kinfile_name:
		putname(kinfile_name);
	out:
		return ret;
}

int validate_open_output_file(struct user_args *arg, struct file** out_filp, struct kstat *outfile_stat, struct file** in_filp, struct kstat *infile_stat){
	
	struct filename *koutfile_name;
	int ret = 0;
	
	//Get the output filename from the user args.
	koutfile_name = getname(arg->outfile);
	if(IS_ERR(koutfile_name)){
		ret = PTR_ERR(koutfile_name);
		goto out;
	}

	outfile_stat = kmalloc(sizeof(*outfile_stat), GFP_KERNEL);
	if (!outfile_stat) {
		ret = -ENOMEM;
		goto out_koutfile_name;
	}

	// ret = get_stat(koutfile_name->name, &outfile_stat);
	// if (!ret) {
	// 	printk("Input and Output file point to same file\n");
	// 	goto out_koutfile_name;
	// }

	/***OPEN OUTPUT FILE WITH INPUT FILE PERMISSION***/
	//Opening output file with input file permissions
	(*out_filp) = filp_open(koutfile_name->name, O_WRONLY, (*in_filp)->f_mode);
	if(!(*out_filp) || IS_ERR(*out_filp)){
		//Creating output file with input file permissions
		(*out_filp) = filp_open(koutfile_name->name, O_WRONLY|O_CREAT , (*in_filp)->f_mode);
		if(!(*out_filp) || IS_ERR(*out_filp)){
			printk("[Error] Output file could not be created!");
			ret = PTR_ERR(*out_filp);
			goto out_koutfile_name;
		}
	}

	out_koutfile_name:
		putname(koutfile_name);
	out:
		return ret;
}

int write_preamble(struct file* out_filp, void* hash_key_buff, unsigned int key_len){
	ssize_t data_bytes_write = 0;

	data_bytes_write = kernel_write(out_filp, hash_key_buff, key_len,
				   &out_filp->f_pos);
	

	if (data_bytes_write < 0)
		return data_bytes_write;
	else
		return 0;
}

int read_preamble(struct file* in_filp, void* hash_key_buff, unsigned int key_len){
	int ret = 0;
	void* file_hash = NULL;
	ssize_t data_bytes_read = 0;

	file_hash = kmalloc(key_len, GFP_KERNEL);
	if(!file_hash){
		ret = -ENOMEM;
		goto out;
	}

	data_bytes_read = kernel_read(in_filp, file_hash, key_len, &in_filp->f_pos);
	
	printk("IN READ PREAMBLE - Bytes Read %ld\n", data_bytes_read);

	if(data_bytes_read<0){
		printk("[ERROR]: Reading hash from the file/n");
		ret = data_bytes_read;
		goto out_file_hash;
	}

	if(memcmp(file_hash, hash_key_buff, key_len)){
		ret = -EACCES;
		goto out_file_hash;
	}

	out_file_hash:
		kfree(file_hash);
	out:
		return ret;
}

int set_aes_cipher(char **cipher_full_name, char **cipher_name,
		   unsigned int *keylen)
{
	*cipher_full_name = kmalloc(14, GFP_KERNEL);
	if (!*cipher_full_name)
		return -ENOMEM;
	memcpy(*cipher_full_name, "ctr-aes-aesni", 14);
	*cipher_name = kmalloc(4, GFP_KERNEL);
	memcpy(*cipher_name, "aes", 4);
	*keylen = 32;
	return 0;
}

asmlinkage long cryptocopy(void *arg)
{
	void* kargs = NULL;
	struct file *in_filp = NULL, *out_filp = NULL;
	unsigned char flag;
	unsigned int key_len;
	int ret = 0;
	void* hash_key_buff = NULL;

	void *ivdata = NULL;
	char *cipher_name = NULL;
	char *cipher_full_name = NULL;

	struct kstat *infile_stat = NULL;
	struct kstat *outfile_stat = NULL;

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
		
		// ret = copy_key_buff(kargs, arg, key_len);
		// if(ret < 0){
		// 	goto out_karg;
		// }

		((struct user_args *)kargs)->keybuf = kmalloc(key_len, GFP_KERNEL);
		if (!(((struct user_args *)kargs)->keybuf)) {
			ret = -ENOMEM;
			goto out_karg;
		}

		/* copy arguments from user space to kernel space */
		if (copy_from_user(((struct user_args *)kargs)->keybuf,
				   ((struct user_args *)arg)->keybuf,
				   key_len)) {
			pr_err("Error in copy password from user to kernel memory\n");
			ret = -EFAULT;
			goto out_kargs_keybuf;
		}

		hash_key_buff = kmalloc(SHA256_LENGTH, GFP_KERNEL);
		if (!hash_key_buff) {
			ret = -ENOMEM;
			goto out_karg;
		}

		ret = generate_hash(((struct user_args *)kargs)->keybuf, key_len, hash_key_buff);
		if (ret < 0)
			goto out_hash_key_buff;	

		ivdata = kmalloc(16, GFP_KERNEL);
		if (!ivdata) {
			ret =  -ENOMEM;
			goto out_hash_key_buff;
		}
		memset(ivdata, 123456, 16);

		ret = set_aes_cipher(&cipher_full_name, &cipher_name, &key_len);
		if (ret < 0)
			goto out_ivdata;
	}

	ret = validate_open_input_file(arg, &in_filp, infile_stat);
	if(ret < 0){
		printk("[Error] Failed to open the input file.\n");
		goto out_in_filp;
	}

	ret = validate_open_output_file(arg, &out_filp, outfile_stat,  &in_filp, infile_stat);
	if(ret<0){
		printk("[Error]: Failed to open the output file.\n");
		goto out_out_filp;
	}

	/***INPUT AND OUTPUT FILE POINT TO THE SAME FILE***/
	if (out_filp->f_inode->i_ino  == in_filp->f_inode->i_ino) {
		printk("Input and Output file point to same file\n");
		ret = -EINVAL;
		goto out_out_filp;
	}

	if(flag & 0x1){
		printk("WRITE TO PREAMBLE\n");
		ret = write_preamble(out_filp, hash_key_buff, SHA256_LENGTH);
		if(ret < 0){
			printk("[Error] Unable to write hash to preamble\n");
			goto out_out_filp;
		}
	}else if(flag & 0x2){
		printk("READ FROM TO PREAMBLE\n");
		ret = read_preamble(in_filp, hash_key_buff, SHA256_LENGTH);
		if(ret < 0){
			printk("[Error] Unable to validate hash from preamble of inputfile and password provided.\n");
			goto out_out_filp;
		}
	}

	ret = read_write(in_filp, out_filp, &ivdata, hash_key_buff, key_len,
			 cipher_full_name, flag);

	if(ret < 0){
		printk("Error in reading the file");
		goto out_out_filp;
	}

	out_out_filp:
		if(!outfile_stat){
			kfree(outfile_stat);
		}
		if(!out_filp)
			filp_close(out_filp, NULL);
	// out_koutfile_name:
	// 	putname(koutfile_name);
	out_in_filp:
		if(!infile_stat){
			kfree(infile_stat);
		}
		if(!in_filp)
			filp_close(in_filp, NULL);
	// out_kinfile_name:
	// 	putname(kinfile_name);
	out_ivdata:
		kfree(ivdata);
		kfree(cipher_full_name);
		kfree(cipher_name);
	out_hash_key_buff:
		kfree(hash_key_buff);
	out_kargs_keybuf:
		kfree(((struct user_args *)kargs)->keybuf);
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