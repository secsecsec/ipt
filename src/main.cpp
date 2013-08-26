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
// Description: The current test is equivalent to running the following:
//              iptables -t filter -I INPUT -s 10.0.0.0/8 -p tcp --dport 80 -j ACCEPT

int main(int argc, char **argv) {
	bysin::ipt *n;
	
	// Uses the filter table
	n = new bysin::ipt("filter");
	
	// Start of INPUT chain
	n->chain_start(NF_IP_LOCAL_IN);
	n->rule_start();
	// Create a rule that matches 10.0.0.0/8 (or 0x0000000a/0x000000ff)
	n->rule_match_src_ip(0x0000000a, 0x000000ff, false);
	// Match tcp source ports 0 - 0xffff and destination ports from 80 - 80
	n->rule_match_tcp_port(0, 0xffff, false, 80, 80, false);
	// The target, ACCEPT, allows packets that match the above criteria
	n->rule_target(IPT_STANDARD_TARGET, NF_ACCEPT);
	n->rule_end();
	n->chain_end(NF_ACCEPT);
	
	// Start of the FORWARD chain
	n->chain_start(NF_IP_FORWARD);
	n->chain_end(NF_ACCEPT);
	
	// Start of the OUTPUT chain
	n->chain_start(NF_IP_LOCAL_OUT);
	n->chain_end(NF_ACCEPT);
	
	// Write iptables to system
	if (!n->write())
		std::cout << "iptables failed: " << strerror(errno) << std::endl;
	
	delete n;
	return 0;
}
