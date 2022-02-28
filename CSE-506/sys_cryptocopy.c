#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/fs.h>
#include <linux/uaccess.h>	/* for mm_segment_t??*/
#include <linux/slab.h>	 

asmlinkage extern long (*sysptr)(void *arg);

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

int read_file(struct file *in_filp){

	ssize_t bytes_read = 0;
	int ret = 0;
	
	//Allocate buffer of size PAGE_SiZE. When we read file we get PAGE_SIZE worth of bytes into the buffer and then use it.
	void* buf = kmalloc(PAGE_SIZE, GFP_KERNEL);

	if(!buf){
		ret = -ENOMEM;
		goto out; // Since the allocation fails we should just return the ret value
	}

	bytes_read = kernel_read(in_filp, buf, PAGE_SIZE, &in_filp->f_pos);

	printk("No. of bytes read: %ld", bytes_read);

	//while((bytes_read = kernel_read(in_filp, buf, PAGE_SIZE, &in_filp->f_pos))>0){

	//}

	out_buf:
		kfree(buf);
	out:
		return ret;
}

asmlinkage long cryptocopy(void *arg)
{
	void* kargs = NULL;
	struct file* in_filp = NULL, *out_filp = NULL;
	struct filename* kinfile_name = NULL, *koutfile_name = NULL;
	unsigned char flag;
	int ret = 0;

	ret = check_valid_address(arg, sizeof(struct user_args));

	if(ret < 0){
		printk("Error in user provided address\n");
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
		printk("Error in copying arguments from the user land to kernal land\n");
		ret = -EFAULT;
		goto out_karg;
	}
	//Get the flags from kernelland args.
	flag = ((struct user_args*)kargs)->flag;
	printk("FLAG : %u\n", ((struct user_args*)kargs)->flag);
	
	//Get the input filename from the user args
	kinfile_name = getname(((struct user_args *)kargs) -> infile);
	
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
	koutfile_name = getname(((struct user_args *)kargs) -> outfile);
	
	if(IS_ERR(koutfile_name)){
		ret = PTR_ERR(koutfile_name);
		goto out_in_filp;
	}

	//Open the output file.
	out_filp = filp_open(koutfile_name->name, O_RDONLY, 0);
	
	if(IS_ERR(out_filp)){
		ret = PTR_ERR(out_filp);
		goto out_koutfile_name;
	}

	ret = read_file(in_filp);

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