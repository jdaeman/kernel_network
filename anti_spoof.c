#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_arp.h>
#include <linux/if_arp.h>

#define HOOK_LEN 2

static int req_cnt;

static struct nf_hook_ops hook[HOOK_LEN];

unsigned int arp_send_hook(void * priv, struct sk_buff * skb, const struct nf_hook_state * state)
{
	req_cnt += 1;	

	return NF_ACCEPT;
}

unsigned int arp_rcv_hook(void * priv, struct sk_buff * skb, const struct nf_hook_state * state)
{
	struct arphdr * arp = arp_hdr(skb);
	unsigned char * ptr;

	if (arp->ar_op != htons(ARPOP_REPLY))
		return NF_ACCEPT;
	if (req_cnt--)
		return NF_ACCEPT;	

	ptr = (unsigned char *)(arp + 1);
	printk("Filtered %pI4`s spoofing\n", ptr);

	return NF_DROP;
}
int anti_init(void)
{
	int ret;

	hook[0].hook = arp_send_hook;
	hook[0].hooknum = NF_ARP_OUT; //about outgoing packet
	hook[0].pf = NFPROTO_ARP; //ARP

	hook[1].hook = arp_rcv_hook;
	hook[1].hooknum = NF_ARP_IN; //about incoming packet
	hook[1].pf = NFPROTO_ARP;

	printk("-----------------------------------\n");
	ret = nf_register_net_hooks(&init_net, hook, HOOK_LEN);

	if (!ret)
		printk("netfilter register success\n");
	else
		printk("netfilter register fail\n");

	return ret;
}	

void anti_exit(void)
{
	nf_unregister_net_hooks(&init_net, hook, HOOK_LEN);
}

module_init(anti_init);
module_exit(anti_exit);
MODULE_AUTHOR("testkernel.tistory.com");
MODULE_DESCRIPTION("anti arp spoof module");
MODULE_LICENSE("GPL");
