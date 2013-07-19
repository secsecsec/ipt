/*
 * ipt: main source
 *	By Benjamin Kittridge. Copyright (C) 2013, All rights reserved.
 *
 */

#include <iostream>
#include <errno.h>
#include <string.h>
#include "ipt.h"

////////////////////////////////////////////////////////////////////////////////
// Class:       main
// Description: Example program

////////////////////////////////////////////////////////////////////////////////
// Section:     Tests the iptables system

int main(int argc, char **argv) {
	bysin::ipt *n;
	
	n = new bysin::ipt("filter");
	
	n->chain_start(NF_IP_LOCAL_IN);
	n->rule_start();
	n->rule_match_src_ip(0x0000000a, 0x000000ff, true);
	n->rule_match_tcp_port(0, 0xffff, false, 80, 80, true);
	n->rule_target(IPT_STANDARD_TARGET, NF_ACCEPT);
	n->rule_end();
	n->chain_end(NF_ACCEPT);
	
	n->chain_start(NF_IP_FORWARD);
	n->chain_end(NF_DROP);
	
	n->chain_start(NF_IP_LOCAL_OUT);
	n->chain_end(NF_ACCEPT);
	
	if (!n->write())
		std::cout << "iptables failed: " << strerror(errno) << std::endl;
	
	delete n;
	return 0;
}
