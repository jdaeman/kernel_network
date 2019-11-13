#include <linux/kernel.h>
#include <linux/module.h>

#include <linux/fs.h>
#include <net/ip_fib.h>

#include <linux/net.h>
#include <linux/inet.h>

#include <linux/kthread.h>
#include <linux/delay.h>

static int test1(void)
{
	/*struct flowi4 f4;
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
	return 0;
}

static int test2(void)
{
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

static int test3(void)
{
	struct socket * socket = NULL;
	int err = sock_create(PF_INET, SOCK_DGRAM, 0, &socket);
	extern struct proto ping_prot;

	struct sockaddr_in sin;
	struct msghdr msg;
	struct iovec iov;
	char buf[] = "Hello";
	int len = 5;

	if (err < 0)
		printk("err code: %d\n", err);
	else
		printk("socket is create\n");

	if (!socket)
		return -1;

	memset(&msg, 0, sizeof(msg));
	sin.sin_addr.s_addr = in_aton("192.168.0.1");
	msg.msg_name = &sin;
	iov.iov_base = buf;
	iov.iov_len = len;
	
	iov_iter_init(&msg.msg_iter, WRITE, &iov, 1, len);

	printk("ret: %d\n", ping_prot.sendmsg(socket->sk, &msg, len));


	if (socket->ops)
		printk("ops is exist\n");
	else
		printk("ops is not exist\n");

	sock_release(socket);

	return -1;
}

int tt(void * ptr)
{
	printk("TT\n");
	msleep(2);
	return 100;
}

static int test4(void)
{
	struct task_struct * ts = NULL;
	ts = kthread_run(tt, NULL, "TTT");
	if (!ts)
		return -1;

	//msleep(5);
	printk("check tt task\n");
	printk("state: %ld\n", ts->state);
	printk("exit_state: %d, exit_code: %d\n", ts->exit_state, ts->exit_code);

	return -1;
	
}

int test_init(void)
{
	test4();
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
