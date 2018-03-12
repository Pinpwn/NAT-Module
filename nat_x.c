//#include <linux/module.h>
#include <linux/kernel.h>
#include "nat_helper.c"

int init_module()
{
	int ret = register_pernet_subsys(&iptable_nat_net_ops);

	if (ret)
		return ret;

	ret = iptable_nat_table_init(&init_net);
	if (ret)
		unregister_pernet_subsys(&iptable_nat_net_ops);
	return ret;
}

void cleanup_module()
{
	unregister_pernet_subsys(&iptable_nat_net_ops);
}
