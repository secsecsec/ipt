/*
 * ipt: header
 *	By Benjamin Kittridge. Copyright (C) 2013, All rights reserved.
 *
 */

#pragma once

////////////////////////////////////////////////////////////////////////////////
// Section:     Required includes

#include <stdint.h>
#include <stdbool.h>
#include <limits.h>
#include <netinet/in.h>
#include <net/if.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/xt_tcpudp.h>
#include <linux/netfilter/nf_conntrack_common.h>

////////////////////////////////////////////////////////////////////////////////
// Section:     Namespace

namespace bysin {

////////////////////////////////////////////////////////////////////////////////
// Section:     Missing structs (netfilter_ipv4/ip_tables.h is weird)

#define IPT_BASE_CTL			64

#define IPT_SO_SET_REPLACE		(IPT_BASE_CTL)
#define IPT_SO_SET_ADD_COUNTERS		(IPT_BASE_CTL + 1)
#define IPT_SO_SET_MAX			IPT_SO_SET_ADD_COUNTERS

#define IPT_SO_GET_INFO			(IPT_BASE_CTL)
#define IPT_SO_GET_ENTRIES		(IPT_BASE_CTL + 1)
#define IPT_SO_GET_REVISION_MATCH	(IPT_BASE_CTL + 2)
#define IPT_SO_GET_REVISION_TARGET	(IPT_BASE_CTL + 3)
#define IPT_SO_GET_MAX			IPT_SO_GET_REVISION_TARGET

#define IPT_STANDARD_TARGET		XT_STANDARD_TARGET
#define IPT_ERROR_TARGET		XT_ERROR_TARGET

#define IPT_ICMP_INV			0x01

#define IPT_INV_VIA_IN			0x01
#define IPT_INV_VIA_OUT			0x02
#define IPT_INV_TOS			0x04
#define IPT_INV_SRCIP			0x08
#define IPT_INV_DSTIP			0x10
#define IPT_INV_FRAG			0x20
#define IPT_INV_PROTO			XT_INV_PROTO
#define IPT_INV_MASK			0x7F

struct ipt_ip {
	struct in_addr src, dst;
	struct in_addr smsk, dmsk;
	char iniface[IFNAMSIZ], outiface[IFNAMSIZ];
	unsigned char iniface_mask[IFNAMSIZ], outiface_mask[IFNAMSIZ];
	u_int16_t proto;
	u_int8_t flags;
	u_int8_t invflags;
};

struct ipt_entry {
	struct ipt_ip ip;
	unsigned int nfcache;
	u_int16_t target_offset;
	u_int16_t next_offset;
	unsigned int comefrom;
	struct xt_counters counters;
	unsigned char elems[0];
};

struct ipt_getinfo {
	char name[XT_TABLE_MAXNAMELEN];
	unsigned int valid_hooks;
	unsigned int hook_entry[NF_INET_NUMHOOKS];
	unsigned int underflow[NF_INET_NUMHOOKS];
	unsigned int num_entries;
	unsigned int size;
};

struct ipt_replace {
	char name[XT_TABLE_MAXNAMELEN];
	unsigned int valid_hooks;
	unsigned int num_entries;
	unsigned int size;
	unsigned int hook_entry[NF_INET_NUMHOOKS];
	unsigned int underflow[NF_INET_NUMHOOKS];
	unsigned int num_counters;
	struct xt_counters *counters;
	struct ipt_entry entries[0];
};

struct ipt_get_entries {
	char name[XT_TABLE_MAXNAMELEN];
	unsigned int size;
	struct ipt_entry entrytable[0];
};

struct ipt_icmp {
	u_int8_t type;
	u_int8_t code[2];
	u_int8_t invflags;
};

////////////////////////////////////////////////////////////////////////////////
// Section:     Missing structs (netfilter_ipv4/ip_nat.h is gone?)

#define NF_NAT_RANGE_MAP_IPS 1
#define NF_NAT_RANGE_PROTO_SPECIFIED 2
#define NF_NAT_RANGE_PROTO_RANDOM 4
#define NF_NAT_RANGE_PERSISTENT 8

union ip_conntrack_manip_proto {
	uint16_t all;
	struct { uint16_t port; } tcp;
	struct { uint16_t port; } udp;
	struct { uint16_t id;   } icmp;
};

struct ip_nat_range {
	uint32_t flags;
	uint32_t min_ip, max_ip;
	union ip_conntrack_manip_proto min_proto, max_proto;
};

struct ip_nat_multi_range {
	uint32_t rangesize;
	struct ip_nat_range range[1];
};

////////////////////////////////////////////////////////////////////////////////
// Section:     Redefinition of macro for C++11 compatibility

#if __cplusplus > 199711L
#define __XT_ALIGN_KERNEL(x, a)		__XT_ALIGN_KERNEL_MASK(x, (decltype(x))(a) - 1)
#else
#define __XT_ALIGN_KERNEL(x, a)		__XT_ALIGN_KERNEL_MASK(x, (typeof(x))(a) - 1)
#endif

#define __XT_ALIGN_KERNEL_MASK(x, mask)	(((x) + (mask)) & ~(mask))
#define __XT_ALIGN(s)			__XT_ALIGN_KERNEL(s, __alignof__(struct _xt_align))

////////////////////////////////////////////////////////////////////////////////
// Section:     Implicit void pointer cast

class ipt_anyp {
    public:
	ipt_anyp(void *p) : m_p(p) { }
	
	template <typename T>
	operator T *() {
		return (T *) m_p;
	}
	
    private:
	void *m_p;
};

////////////////////////////////////////////////////////////////////////////////
// Section:     Iptables buffer

struct ipt_buf_data {
	void *ptr;
	uint32_t size;
};

class ipt_buf {
    public:
	ipt_buf();
	~ipt_buf();
	
	ipt_anyp append(uint32_t size);
	ipt_anyp build();
	
	uint32_t len() const { return m_len; }
	
    private:
	ipt_buf_data *m_buf;
	void *m_buf_build;
	uint32_t m_buf_count, m_len;
};

////////////////////////////////////////////////////////////////////////////////
// Section:     Iptables

struct ipt {
    public:
	ipt(const char *table);
	~ipt();
	
	bool write();
	
	void chain_start(uint32_t chain);
	void chain_end(int32_t target);
	
	void rule_start();
	void rule_end();
	void rule_padding(uint16_t *size, uint32_t *offt);
	
	void rule_match_src_ip(in_addr_t ip, in_addr_t mask, bool invert);
	void rule_match_dst_ip(in_addr_t ip, in_addr_t mask, bool invert);
	void rule_match_src_iface(const char *iface, bool invert);
	void rule_match_dst_iface(const char *iface, bool invert);
	void rule_match_tcp_port(uint16_t sport_from, uint16_t sport_to, bool sinvert,
			uint16_t dport_from, uint16_t dport_to, bool dinvert);
	void rule_match_udp_port(uint16_t sport_from, uint16_t sport_to, bool sinvert,
			uint16_t dport_from, uint16_t dport_to, bool dinvert);
	void rule_match_icmp_type(uint8_t type, uint8_t code_from, uint8_t code_to, bool invert);
	
	void rule_target(const char *name, int32_t num);
	void rule_target_txt(const char *name, const char *text);
	void rule_target_nat(const char *name, in_addr_t ip);

    private:
	ipt_buf m_buf;
	struct ipt_replace *m_replace;
	struct ipt_entry *m_entry;
	uint32_t m_prev_offt, m_cur_chain;
};

////////////////////////////////////////////////////////////////////////////////
// Section:     List iteration

#define ipt_list_entry(k, entry)						\
	for (uint32_t __i = 0;							\
	     ((entry) = (struct ipt_entry *)					\
			     ((char *)(k)->m_entries->entrytable + __i)) &&	\
	     __i < (k)->m_entries->size;					\
	     __i += (entry)->next_offset)

#define ipt_list_match(k, entry, match)					\
	for (uint32_t __i = sizeof(*entry);					\
	     ((match) = (char *)entry + __i) &&					\
	     __i < (entry)->target_offset;					\
	     __i += (match)->u.match_size)

#define ipt_list_target(k, entry)						\
	((char *)(entry) + (entry)->target_offset)

#define ipt_list_chain(k, entry) ({						\
		uint32_t __i, __offt, __r_offt, __r_min, __r_chain;		\
										\
		__offt = (char*)(entry) - (char*)(k)->m_entries->entrytable;	\
		__r_min = (uint32_t) -1, __r_chain = 0;				\
		for (__i = 0; __i < NF_INET_NUMHOOKS; __i++) {			\
			if (!((k)->m_info.valid_hooks & (1 << __i)))		\
				continue;					\
			if (__offt < (k)->m_info.hook_entry[__i])		\
				continue;					\
			__r_offt = __offt - (k)->m_info.hook_entry[__i];	\
			if (__r_offt < __r_min) {				\
				__r_chain = __i;				\
				__r_min = __r_offt;				\
			}							\
		}								\
		__r_chain;							\
	})

////////////////////////////////////////////////////////////////////////////////
// Section:     Iptables list

struct ipt_list {
    public:
	ipt_list();
	~ipt_list();

	bool load(const char *table);
	
    public:
	struct ipt_getinfo m_info;
	struct ipt_get_entries *m_entries;
};

////////////////////////////////////////////////////////////////////////////////
// Section:     Namespace end

}
