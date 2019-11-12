#include <linux/kernel.h>
#include <linux/module.h>

#include <linux/fs.h>

int test_init(void)
{
	/*struct fib_result res;
	struct flowi4 f4;
	struct fib_table * ft;
	int ret = fib_lookup(&init_net, &f4, &res, 0);
	
	printk("RET: %d\n", ret);

	ft = fib_get_table(&init_net, RT_TABLE_MAIN);

	if (!ft)
	{	
		printk("ft is null\n");
		return -1;
	}

	printk("ft is not null\n");*/

	struct file * file = open_exec("/proc/net/route");
	if (!file)
		printk("file is null\n");
	else
	{
		/*char buf[512];
		int ret;
		loff_t off = 0;

		ret = kernel_read(file, buf, 512, &off);
		printk("%d, %s\n", ret, buf);*/

		printk("%s\n", ((file->f_path).dentry)->d_iname);
	}


	return -1;
}

void test_exit(void)
{

}

module_init(test_init);
module_exit(test_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("test_kernel");
MODULE_DESCRIPTION("test kernel module");
