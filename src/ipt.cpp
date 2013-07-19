/*
 * ipt: source
 *	By Benjamin Kittridge. Copyright (C) 2013, All rights reserved.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>
#include <string.h>
#include <semaphore.h>
#include <limits.h>
#include <netinet/in.h>
#include <net/if.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#include <algorithm>
#include "ipt.h"

////////////////////////////////////////////////////////////////////////////////
// Module:      ipt
// Description: Manages iptables

////////////////////////////////////////////////////////////////////////////////
// Section:     Namespace

namespace bysin {

////////////////////////////////////////////////////////////////////////////////
// Section:     Misc helper function

static void strcpy_s(char *dst, const char *src, int32_t len) {
	if (!dst || !src)
		return;
	strncpy(dst, src, len);
	if (len)
		dst[len-1] = 0;
}

////////////////////////////////////////////////////////////////////////////////
// Section:     Buffer

ipt_buf::ipt_buf()
    : m_buf(NULL), m_buf_build(NULL), m_buf_count(0), m_len(0) { }

ipt_buf::~ipt_buf() {
	uint32_t i;
	
	if (m_buf_build)
		free(m_buf_build);
	for (i = 0; i < m_buf_count; i++)
		free(m_buf[i].ptr);
	free(m_buf);
}

ipt_anyp ipt_buf::append(uint32_t size) {
	void *ptr;
	
	ptr = calloc(size, 1);
	m_len += size;
	
	m_buf = (ipt_buf_data*) realloc(m_buf, sizeof(*m_buf) * (m_buf_count + 1));
	m_buf[m_buf_count].ptr = ptr;
	m_buf[m_buf_count++].size = size;
	return ptr;
}

ipt_anyp ipt_buf::build() {
	void *ptr;
	uint32_t i;
	
	if (m_buf_build)
		free(m_buf_build);
	m_buf_build = calloc(m_len, 1);
	
	ptr = m_buf_build;
	for (i = 0; i < m_buf_count; i++) {
		memcpy(ptr, m_buf[i].ptr, m_buf[i].size);
		ptr = (char*)ptr + m_buf[i].size;
	}
	return m_buf_build;
}

////////////////////////////////////////////////////////////////////////////////
// Section:     Tables

ipt::ipt(const char *table)
    : m_entry(NULL), m_prev_offt(0), m_cur_chain(0) {
	m_replace = m_buf.append(sizeof(*m_replace));
	strcpy_s(m_replace->name, table, sizeof(m_replace->name));
}

ipt::~ipt() {
	if (m_replace->counters)
		free(m_replace->counters);
}

bool ipt::write() {
	int32_t fd, ret;
	struct ipt_getinfo info;
	socklen_t slen;

	rule_start();
	rule_target_txt(IPT_ERROR_TARGET, IPT_ERROR_TARGET);
	rule_end();

	if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
		return false;

	slen = sizeof(info);
	strcpy_s(info.name, m_replace->name, sizeof(info.name));
	if (getsockopt(fd, IPPROTO_IP, IPT_SO_GET_INFO, &info, &slen) < 0) {
		close(fd);
		return NULL;
	}
	
	m_replace->num_counters = info.num_entries;
	m_replace->counters = (struct xt_counters*) 
					calloc(sizeof(struct xt_counters), info.num_entries);
	m_replace->size = m_buf.len() - sizeof(*m_replace);

#ifdef FIREWALL_DISABLED
	ret = 0;
#else
	ret = setsockopt(fd, IPPROTO_IP, IPT_SO_SET_REPLACE, m_buf.build(), m_buf.len());
#endif
	close(fd);
	return (ret >= 0);
}

////////////////////////////////////////////////////////////////////////////////
// Section:     Chaining

void ipt::chain_start(uint32_t chain) {
	m_cur_chain = chain;
	
	m_replace->valid_hooks |= (1 << m_cur_chain);
	m_replace->hook_entry[m_cur_chain] = m_buf.len() - sizeof(*m_replace);
}

void ipt::chain_end(int32_t target) {
	m_replace->underflow[m_cur_chain] = m_buf.len() - sizeof(*m_replace);
	
	rule_start();
	rule_target(IPT_STANDARD_TARGET, target);
	rule_end();
}

////////////////////////////////////////////////////////////////////////////////
// Section:     Rule

void ipt::rule_start() {
	m_entry = m_buf.append(sizeof(*m_entry));
	m_entry->target_offset = sizeof(*m_entry);
	m_entry->next_offset = sizeof(*m_entry);
	m_entry->comefrom = m_prev_offt;

	m_replace->num_entries++;
}

void ipt::rule_end() {
	rule_padding(&m_entry->next_offset, &m_prev_offt);
}

void ipt::rule_padding(uint16_t *size, uint32_t *offt) {
	uint32_t align, pad;
	uint16_t n_size;

	n_size = *size;
	align = __XT_ALIGN(n_size);
	pad = align - *size;
	*size = align;

	m_buf.append(pad);
	if (offt)
		*offt = pad;
}

////////////////////////////////////////////////////////////////////////////////
// Section:     Rule match

void ipt::rule_match_src_ip(in_addr_t ip, in_addr_t mask, bool invert) {
	m_entry->ip.src.s_addr = ip;
	m_entry->ip.smsk.s_addr = mask;
	if (!m_entry->ip.proto)
		m_entry->ip.proto = IPPROTO_IP;
	if (invert)
		m_entry->ip.invflags |= IPT_INV_SRCIP;
}

void ipt::rule_match_dst_ip(in_addr_t ip, in_addr_t mask, bool invert) {
	m_entry->ip.dst.s_addr = ip;
	m_entry->ip.dmsk.s_addr = mask;
	if (!m_entry->ip.proto)
		m_entry->ip.proto = IPPROTO_IP;
	if (invert)
		m_entry->ip.invflags |= IPT_INV_DSTIP;
}

void ipt::rule_match_src_iface(const char *iface, bool invert) {
	strncpy(m_entry->ip.iniface, iface, IFNAMSIZ - 1);
	memset(m_entry->ip.iniface_mask, 0xff, std::min<uint32_t>(IFNAMSIZ - 1, strlen(iface) + 1));
	if (!m_entry->ip.proto)
		m_entry->ip.proto = IPPROTO_IP;
	if (invert)
		m_entry->ip.invflags |= IPT_INV_VIA_IN;
}

void ipt::rule_match_dst_iface(const char *iface, bool invert) {
	strncpy(m_entry->ip.outiface, iface, IFNAMSIZ - 1);
	memset(m_entry->ip.outiface_mask, 0xff, std::min<uint32_t>(IFNAMSIZ - 1, strlen(iface) + 1));
	if (!m_entry->ip.proto)
		m_entry->ip.proto = IPPROTO_IP;
	if (invert)
		m_entry->ip.invflags |= IPT_INV_VIA_OUT;
}

void ipt::rule_match_tcp_port(uint16_t sport_from, uint16_t sport_to, bool sinvert,
		uint16_t dport_from, uint16_t dport_to, bool dinvert) {
	struct xt_entry_match *match;
	struct xt_tcp *tcp;

	match = m_buf.append(sizeof(*match));
	match->u.user.match_size = sizeof(*match) + sizeof(*tcp);
	strcpy(match->u.user.name, "tcp");

	tcp = m_buf.append(sizeof(*tcp));
	tcp->spts[0] = sport_from;
	tcp->spts[1] = sport_to;
	tcp->dpts[0] = dport_from;
	tcp->dpts[1] = dport_to;
	if (sinvert)
		tcp->invflags |= XT_TCP_INV_SRCPT;
	if (dinvert)
		tcp->invflags |= XT_TCP_INV_DSTPT;

	m_entry->ip.proto = IPPROTO_TCP;
	
	rule_padding(&match->u.user.match_size, NULL);
	m_entry->target_offset += match->u.user.match_size;
	m_entry->next_offset   += match->u.user.match_size;
}

void ipt::rule_match_udp_port(uint16_t sport_from, uint16_t sport_to, bool sinvert,
		uint16_t dport_from, uint16_t dport_to, bool dinvert) {
	struct xt_entry_match *match;
	struct xt_udp *udp;

	match = m_buf.append(sizeof(*match));
	match->u.user.match_size = sizeof(*match) + sizeof(*udp);
	strcpy(match->u.user.name, "udp");

	udp = m_buf.append(sizeof(*udp));
	udp->spts[0] = sport_from;
	udp->spts[1] = sport_to;
	udp->dpts[0] = dport_from;
	udp->dpts[1] = dport_to;
	if (sinvert)
		udp->invflags |= XT_UDP_INV_SRCPT;
	if (dinvert)
		udp->invflags |= XT_UDP_INV_DSTPT;

	m_entry->ip.proto = IPPROTO_UDP;
	
	rule_padding(&match->u.user.match_size, NULL);
	m_entry->target_offset += match->u.user.match_size;
	m_entry->next_offset   += match->u.user.match_size;
}

void ipt::rule_match_icmp_type(uint8_t type, uint8_t code_from, uint8_t code_to, bool invert) {
	struct xt_entry_match *match;
	struct ipt_icmp *icmp;

	match = m_buf.append(sizeof(*match));
	match->u.user.match_size = sizeof(*match) + sizeof(*icmp);
	strcpy(match->u.user.name, "icmp");

	icmp = m_buf.append(sizeof(*icmp));
	icmp->type = type;
	icmp->code[0] = code_from;
	icmp->code[1] = code_to;
	if (invert)
		icmp->invflags |= IPT_ICMP_INV;

	m_entry->ip.proto = IPPROTO_ICMP;
	
	rule_padding(&match->u.user.match_size, NULL);
	m_entry->target_offset += match->u.user.match_size;
	m_entry->next_offset   += match->u.user.match_size;
}

////////////////////////////////////////////////////////////////////////////////
// Section:     Rule target

void ipt::rule_target(const char *name, int32_t num) {
	struct xt_entry_target *target;
	int32_t *verdict;

	target = m_buf.append(sizeof(*target));
	target->u.target_size = sizeof(*target) + sizeof(*verdict);
	strcpy(target->u.user.name, name);
	
	verdict = m_buf.append(sizeof(*verdict));
	*verdict = (-num) - 1;
	
	rule_padding(&target->u.user.target_size, NULL);
	m_entry->next_offset += target->u.user.target_size;
}

void ipt::rule_target_txt(const char *name, const char *text) {
	struct xt_entry_target *target;
	char *pad;

	target = m_buf.append(sizeof(*target));
	target->u.target_size = sizeof(*target) + XT_TABLE_MAXNAMELEN;
	strcpy(target->u.user.name, name);
	
	pad = m_buf.append(XT_TABLE_MAXNAMELEN);
	strcpy(pad, text);
	
	rule_padding(&target->u.user.target_size, NULL);
	m_entry->next_offset += target->u.user.target_size;
}

void ipt::rule_target_nat(const char *name, in_addr_t ip) {
	struct xt_entry_target *target;
	struct ip_nat_multi_range *nat;
	
	target = m_buf.append(sizeof(*target));
	target->u.target_size = sizeof(*target) + sizeof(*nat);
	strcpy(target->u.user.name, name);
	
	nat = m_buf.append(sizeof(*nat));
	nat->rangesize = 1;
	nat->range->flags = NF_NAT_RANGE_MAP_IPS;
	nat->range->min_ip = ip;
	nat->range->max_ip = nat->range->min_ip;
	
	rule_padding(&target->u.user.target_size, NULL);
	m_entry->next_offset += target->u.user.target_size;
}

////////////////////////////////////////////////////////////////////////////////
// Section:     Iptables list

ipt_list::ipt_list()
    : m_info(), m_entries(NULL) { }

ipt_list::~ipt_list() {
	if (m_entries)
		free(m_entries);
}

bool ipt_list::load(const char *table) {
	int32_t fd;
	socklen_t slen;
	
	if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
		return false;

	strcpy_s(m_info.name, table, sizeof(m_info.name));
	slen = sizeof(m_info);
	if (getsockopt(fd, IPPROTO_IP, IPT_SO_GET_INFO, &m_info, &slen) < 0) {
		close(fd);
		return false;
	}
	
	m_entries = (struct ipt_get_entries *) calloc(sizeof(*m_entries) + m_info.size, 1);
	strcpy_s(m_entries->name, table, sizeof(m_entries->name));
	m_entries->size = m_info.size;
	
	slen = sizeof(*m_entries) + m_info.size;
	if (getsockopt(fd, IPPROTO_IP, IPT_SO_GET_ENTRIES, m_entries, &slen) < 0) {
		close(fd);
		return false;
	}
	
	close(fd);
	return true;
}

////////////////////////////////////////////////////////////////////////////////
// Section:     Namespace end

}
