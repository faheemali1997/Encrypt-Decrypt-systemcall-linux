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

int check_valid_address(void *user_buf, int len){
	
	if(!user_buf){
		printk("User argument is empty\n");
		return -EINVAL;
	}

	if(!access_ok(user_buf, len)){
		printk("Access to user is not valid\n");
	}

	return 0;
}

asmlinkage long cryptocopy(void *arg)
{
	void *kargs;
	struct file *infile_ptr = NULL, *outfile_ptr = NULL;
	struct filename *kinfile = NULL, *koutfile = NULL;
	int ret = 0;

	mm_segment_t old_fs;

	ret = check_valid_address(arg, sizeof(struct user_args));

	if(ret < 0){
		printk("Error in user provided address\n");
		//goto out;
	}

	kargs = kmalloc(sizeof(struct user_args), GFP_KERNEL);

	if(!kargs){
		ret = -ENOMEM;
		//goto out;
	}

	if(copy_from_user(kargs, arg, sizeof(struct user_args))){
		printk("Error in copying arguments from the user land to kernal land\n");
		ret = -EFAULT;
		//goto out;
	}

	printk("FLAG : %u\n", ((struct user_args*)kargs)->flag);
	kfree(kargs);

	/* dummy syscall: returns 0 for non null, -EINVAL for NULL */
	printk("cryptocopy received arg %p\n", arg);
	if (arg == NULL)
		return -EINVAL;
	else
		return 0;
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