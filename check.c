#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/ip.h>
#include <linux/inet.h>

static char * ip;
module_param(ip, charp, 0644);

static int filter;

static struct nf_hook_ops hook;

unsigned int ip_hook(void * priv, struct sk_buff * skb, const struct nf_hook_state * state)
{
	struct iphdr * ip = ip_hdr(skb);
	static const char * who[] = {"You", "Victim"};

	if (!filter || ip->saddr == filter)
	{
		int which;

		if (!filter)
			which = 0;
		else
			which = 1;

		printk("%pI4(%s) -> %pI4\n", &ip->saddr, who[which], &ip->daddr);
	}

	return NF_ACCEPT;
}

int check_init(void)
{
	int ret;

	if (ip)
		filter = in_aton(ip);

	hook.hook = ip_hook;
	hook.hooknum = NF_INET_PRE_ROUTING; //about incoming packet
	hook.pf = NFPROTO_INET; //IPv4

	printk("-----------------------------------\n");

	ret = nf_register_net_hook(&init_net, &hook);

	if (!ret)
		printk("netfilter register success\n");
	else
		printk("netfilter register fail\n");

	return ret;
}	

void check_exit(void)
{
	nf_unregister_net_hook(&init_net, &hook);
}

module_init(check_init);
module_exit(check_exit);
MODULE_AUTHOR("testkernel.tistory.com");
MODULE_DESCRIPTION("checking arp spoof");
MODULE_LICENSE("GPL");
