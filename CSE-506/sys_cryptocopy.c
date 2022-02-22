#include <linux/linkage.h>
#include <linux/moduleloader.h>

asmlinkage extern long (*sysptr)(void *arg);

asmlinkage long cryptocopy(void *arg)
{
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