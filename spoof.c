#include "types.h"
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h> //struct net_device
#include <linux/inetdevice.h>

//int sys_ip = inet_select_addr(dev, 0, RT_SCOPE_UNIVERSE);
//inet_ioctl()
/*neigh = neigh_lookup(&arp_tbl, &gw, dev);
	if (neigh)
	{
		//neighbour."ha" is mac address field.
		memcpy(gw_mac, neigh->ha, ETH_ALEN);*/

//static struct inet_protosw inetsw_array[]

//proc file system, /proc/net/route -> parse


static char * device = NULL;
module_param(device, charp, 0644); //name, type, permission

static struct adr_info host;
static struct net_device * netdev = NULL;

static int init_device(void)
{
	struct in_ifaddr * addrs = NULL;
	struct neigh_table * ntable = NULL;
	unsigned int * gg;

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

	/*ntable = netdev->ip_ptr->arp_parms->tbl;
	gg = (unsigned int *)(ntable->id);
	printk("protocol: %d\n", ntohs(ntable->protocol));
	printk("key_len: %d\n", ntable->key_len);
	printk("id: %pI4\n", gg);

	return -1;*/

	printk("IP address: %pI4\n", &addrs->ifa_address);
	printk("HW address: %pM\n", netdev->dev_addr);
	return 0;
}

static int init_gateway(void)
{
	unsigned int ip;
	
	ip = inet_select_addr(netdev, 0, RTA_GATEWAY);
	printk("gw: %pI4\n", &ip);
	return -1;
}

int spoof_init(void)
{
	if (init_device() < 0)
		return -1;

	if (init_gateway() < 0)
		return -1;

	return 0;
}

void spoof_exit(void)
{

}

module_init(spoof_init);
module_exit(spoof_exit);
MODULE_LICENSE("GPL");
