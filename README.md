IPT
===
Programmatically modify iptables under Linux.
Might not work on all kernels.

Author
----
Benjamin Kittridge

bysin@bysin.net

http://byteworm.com

Example
----

    bysin::ipt n("filter");

    n.chain_start(NF_IP_LOCAL_IN);
    n.rule_start();
    n.rule_match_src_ip(0x0000000a, 0x000000ff, false);
    n.rule_match_tcp_port(0, 0xffff, false, 80, 80, false);
    n.rule_target(IPT_STANDARD_TARGET, NF_ACCEPT);
    n.rule_end();
    n.chain_end(NF_ACCEPT);

    n.chain_start(NF_IP_FORWARD);
    n.chain_end(NF_ACCEPT);

    n.chain_start(NF_IP_LOCAL_OUT);
    n.chain_end(NF_ACCEPT);

    if (!n.write())
        std::cout << "iptables failed: " << strerror(errno) << std::endl;

This is the equivalent to running:

    iptables -t filter -I INPUT -s 10.0.0.0/8 -p tcp --dport 80 -j ACCEPT
