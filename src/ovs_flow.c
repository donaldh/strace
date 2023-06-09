#include "defs.h"
#include "netlink.h"
#include "nlattr.h"
#include <linux/genetlink.h>
#include <linux/openvswitch.h>
#include "netlink_generic.h"
#include "xlat/ovs_flow_ovs_frag_type.h"
#include "xlat/ovs_flow_ovs_ufid_flags.h"
#include "xlat/ovs_flow_ovs_hash_alg.h"
#include "xlat/ovs_flow_ct_state_flags.h"
#include "xlat/ovs_flow_attr.h"
#include "xlat/ovs_key_attr.h"
#include "xlat/ovs_action_attr.h"
#include "xlat/ovs_tunnel_key_attr.h"
#include "xlat/ovs_check_pkt_len_attr.h"
#include "xlat/ovs_sample_attr.h"
#include "xlat/ovs_userspace_attr.h"
#include "xlat/ovs_nsh_key_attr.h"
#include "xlat/ovs_ct_attr.h"
#include "xlat/ovs_nat_attr.h"
#include "xlat/ovs_dec_ttl_attr.h"
#include "xlat/ovs_vxlan_ext_attr.h"
#include "xlat/ovs_flow_cmds.h"

static bool
decode_ovs_flow_stats(struct tcb *const tcp,
		const kernel_ulong_t addr,
		const unsigned int len,
		const void *const opaque_data)
{
	struct ovs_flow_stats ovs_flow_stats;
	umove_or_printaddr(tcp, addr, &ovs_flow_stats);

	PRINT_FIELD_U(ovs_flow_stats, n_packets);
	tprint_struct_next();
	PRINT_FIELD_U(ovs_flow_stats, n_bytes);
	tprint_struct_next();
	return true;
}

static bool
decode_ovs_key_mpls(struct tcb *const tcp,
		const kernel_ulong_t addr,
		const unsigned int len,
		const void *const opaque_data)
{
	struct ovs_key_mpls ovs_key_mpls;
	umove_or_printaddr(tcp, addr, &ovs_key_mpls);

	PRINT_FIELD_U(ovs_key_mpls, mpls_lse);
	tprint_struct_next();
	return true;
}

static bool
decode_ovs_key_ipv4(struct tcb *const tcp,
		const kernel_ulong_t addr,
		const unsigned int len,
		const void *const opaque_data)
{
	struct ovs_key_ipv4 ovs_key_ipv4;
	umove_or_printaddr(tcp, addr, &ovs_key_ipv4);

	PRINT_FIELD_U(ovs_key_ipv4, ipv4_src);
	tprint_struct_next();
	PRINT_FIELD_U(ovs_key_ipv4, ipv4_dst);
	tprint_struct_next();
	PRINT_FIELD_U(ovs_key_ipv4, ipv4_proto);
	tprint_struct_next();
	PRINT_FIELD_U(ovs_key_ipv4, ipv4_tos);
	tprint_struct_next();
	PRINT_FIELD_U(ovs_key_ipv4, ipv4_ttl);
	tprint_struct_next();
	PRINT_FIELD_U(ovs_key_ipv4, ipv4_frag);
	tprint_struct_next();
	return true;
}

#if 0
static bool
decode_ovs_frag_type(struct tcb *const tcp,
		const kernel_ulong_t addr,
		const unsigned int len,
		const void *const opaque_data)
{
	static const struct decode_nla_xlat_opts opts = {
		ovs_flow_ovs_frag_type, "OVS_FRAG_TYPE_???", .size = 4
	};
	return decode_nla_xval(tcp, addr, len, &opts);
}
#endif

static bool
decode_ovs_key_tcp(struct tcb *const tcp,
		const kernel_ulong_t addr,
		const unsigned int len,
		const void *const opaque_data)
{
	struct ovs_key_tcp ovs_key_tcp;
	umove_or_printaddr(tcp, addr, &ovs_key_tcp);

	PRINT_FIELD_U(ovs_key_tcp, tcp_src);
	tprint_struct_next();
	PRINT_FIELD_U(ovs_key_tcp, tcp_dst);
	tprint_struct_next();
	return true;
}

static bool
decode_ovs_key_udp(struct tcb *const tcp,
		const kernel_ulong_t addr,
		const unsigned int len,
		const void *const opaque_data)
{
	struct ovs_key_udp ovs_key_udp;
	umove_or_printaddr(tcp, addr, &ovs_key_udp);

	PRINT_FIELD_U(ovs_key_udp, udp_src);
	tprint_struct_next();
	PRINT_FIELD_U(ovs_key_udp, udp_dst);
	tprint_struct_next();
	return true;
}

static bool
decode_ovs_key_sctp(struct tcb *const tcp,
		const kernel_ulong_t addr,
		const unsigned int len,
		const void *const opaque_data)
{
	struct ovs_key_sctp ovs_key_sctp;
	umove_or_printaddr(tcp, addr, &ovs_key_sctp);

	PRINT_FIELD_U(ovs_key_sctp, sctp_src);
	tprint_struct_next();
	PRINT_FIELD_U(ovs_key_sctp, sctp_dst);
	tprint_struct_next();
	return true;
}

static bool
decode_ovs_key_icmp(struct tcb *const tcp,
		const kernel_ulong_t addr,
		const unsigned int len,
		const void *const opaque_data)
{
	struct ovs_key_icmp ovs_key_icmp;
	umove_or_printaddr(tcp, addr, &ovs_key_icmp);

	PRINT_FIELD_U(ovs_key_icmp, icmp_type);
	tprint_struct_next();
	PRINT_FIELD_U(ovs_key_icmp, icmp_code);
	tprint_struct_next();
	return true;
}

static bool
decode_ovs_key_ct_tuple_ipv4(struct tcb *const tcp,
		const kernel_ulong_t addr,
		const unsigned int len,
		const void *const opaque_data)
{
	struct ovs_key_ct_tuple_ipv4 ovs_key_ct_tuple_ipv4;
	umove_or_printaddr(tcp, addr, &ovs_key_ct_tuple_ipv4);

	PRINT_FIELD_U(ovs_key_ct_tuple_ipv4, ipv4_src);
	tprint_struct_next();
	PRINT_FIELD_U(ovs_key_ct_tuple_ipv4, ipv4_dst);
	tprint_struct_next();
	PRINT_FIELD_U(ovs_key_ct_tuple_ipv4, src_port);
	tprint_struct_next();
	PRINT_FIELD_U(ovs_key_ct_tuple_ipv4, dst_port);
	tprint_struct_next();
	PRINT_FIELD_U(ovs_key_ct_tuple_ipv4, ipv4_proto);
	tprint_struct_next();
	return true;
}

static bool
decode_ovs_action_push_vlan(struct tcb *const tcp,
		const kernel_ulong_t addr,
		const unsigned int len,
		const void *const opaque_data)
{
	struct ovs_action_push_vlan ovs_action_push_vlan;
	umove_or_printaddr(tcp, addr, &ovs_action_push_vlan);

	PRINT_FIELD_U(ovs_action_push_vlan, vlan_tpid);
	tprint_struct_next();
	PRINT_FIELD_U(ovs_action_push_vlan, vlan_tci);
	tprint_struct_next();
	return true;
}

static bool
decode_ovs_ufid_flags(struct tcb *const tcp,
		const kernel_ulong_t addr,
		const unsigned int len,
		const void *const opaque_data)
{
	static const struct decode_nla_xlat_opts opts = {
		ovs_flow_ovs_ufid_flags, "OVS_UFID_F_???", .size = 4
	};
	return decode_nla_flags(tcp, addr, len, &opts);
}

static bool
decode_ovs_action_hash(struct tcb *const tcp,
		const kernel_ulong_t addr,
		const unsigned int len,
		const void *const opaque_data)
{
	struct ovs_action_hash ovs_action_hash;
	umove_or_printaddr(tcp, addr, &ovs_action_hash);

	PRINT_FIELD_U(ovs_action_hash, hash_alg);
	tprint_struct_next();
	PRINT_FIELD_U(ovs_action_hash, hash_basis);
	tprint_struct_next();
	return true;
}

#if 0
static bool
decode_ovs_hash_alg(struct tcb *const tcp,
		const kernel_ulong_t addr,
		const unsigned int len,
		const void *const opaque_data)
{
	static const struct decode_nla_xlat_opts opts = {
		ovs_flow_ovs_hash_alg, "OVS_FLOW_OVS_HASH_ALG_???", .size = 4
	};
	return decode_nla_xval(tcp, addr, len, &opts);
}
#endif

static bool
decode_ovs_action_push_mpls(struct tcb *const tcp,
		const kernel_ulong_t addr,
		const unsigned int len,
		const void *const opaque_data)
{
	struct ovs_action_push_mpls ovs_action_push_mpls;
	umove_or_printaddr(tcp, addr, &ovs_action_push_mpls);

	PRINT_FIELD_U(ovs_action_push_mpls, mpls_lse);
	tprint_struct_next();
	PRINT_FIELD_U(ovs_action_push_mpls, mpls_ethertype);
	tprint_struct_next();
	return true;
}

static bool
decode_ovs_action_add_mpls(struct tcb *const tcp,
		const kernel_ulong_t addr,
		const unsigned int len,
		const void *const opaque_data)
{
	struct ovs_action_add_mpls ovs_action_add_mpls;
	umove_or_printaddr(tcp, addr, &ovs_action_add_mpls);

	PRINT_FIELD_U(ovs_action_add_mpls, mpls_lse);
	tprint_struct_next();
	PRINT_FIELD_U(ovs_action_add_mpls, mpls_ethertype);
	tprint_struct_next();
	PRINT_FIELD_U(ovs_action_add_mpls, tun_flags);
	tprint_struct_next();
	return true;
}

static bool
decode_ct_state_flags(struct tcb *const tcp,
		const kernel_ulong_t addr,
		const unsigned int len,
		const void *const opaque_data)
{
	static const struct decode_nla_xlat_opts opts = {
		ovs_flow_ct_state_flags, "OVS_CS_F_???", .size = 4
	};
	return decode_nla_flags(tcp, addr, len, &opts);
}

static const nla_decoder_t vxlan_ext_attrs_attr_decoders[] = {
	[OVS_VXLAN_EXT_GBP] = decode_nla_u32,
};

static bool
decode_ovs_tunnel_key_attr_vxlan_opts(struct tcb *const tcp,
	const kernel_ulong_t addr,
	const unsigned int len,
	const void *const opaque_data)
{
	decode_nlattr(tcp, addr, len, ovs_vxlan_ext_attr,
		"OVS_VXLAN_EXT_???",
		ARRSZ_PAIR(vxlan_ext_attrs_attr_decoders),
		NULL);
	return true;
}

static const nla_decoder_t tunnel_key_attrs_attr_decoders[] = {
	[OVS_TUNNEL_KEY_ATTR_ID] = decode_nla_u64,
	[OVS_TUNNEL_KEY_ATTR_IPV4_SRC] = decode_nla_u32,
	[OVS_TUNNEL_KEY_ATTR_IPV4_DST] = decode_nla_u32,
	[OVS_TUNNEL_KEY_ATTR_TOS] = decode_nla_u8,
	[OVS_TUNNEL_KEY_ATTR_TTL] = decode_nla_u8,
	[OVS_TUNNEL_KEY_ATTR_DONT_FRAGMENT] = NULL,
	[OVS_TUNNEL_KEY_ATTR_CSUM] = NULL,
	[OVS_TUNNEL_KEY_ATTR_OAM] = NULL,
	[OVS_TUNNEL_KEY_ATTR_GENEVE_OPTS] = NULL,
	[OVS_TUNNEL_KEY_ATTR_TP_SRC] = decode_nla_u16,
	[OVS_TUNNEL_KEY_ATTR_TP_DST] = decode_nla_u16,
	[OVS_TUNNEL_KEY_ATTR_VXLAN_OPTS] = decode_ovs_tunnel_key_attr_vxlan_opts,
	[OVS_TUNNEL_KEY_ATTR_IPV6_SRC] = NULL,
	[OVS_TUNNEL_KEY_ATTR_IPV6_DST] = NULL,
	[OVS_TUNNEL_KEY_ATTR_PAD] = NULL,
	[OVS_TUNNEL_KEY_ATTR_ERSPAN_OPTS] = NULL,
	[OVS_TUNNEL_KEY_ATTR_IPV4_INFO_BRIDGE] = NULL,
};

static bool
decode_ovs_key_attr_tunnel(struct tcb *const tcp,
	const kernel_ulong_t addr,
	const unsigned int len,
	const void *const opaque_data)
{
	decode_nlattr(tcp, addr, len, ovs_tunnel_key_attr,
		"OVS_TUNNEL_KEY_ATTR_???",
		ARRSZ_PAIR(tunnel_key_attrs_attr_decoders),
		NULL);
	return true;
}

static const nla_decoder_t ovs_nsh_key_attrs_attr_decoders[] = {
	[OVS_NSH_KEY_ATTR_BASE] = NULL,
	[OVS_NSH_KEY_ATTR_MD1] = NULL,
	[OVS_NSH_KEY_ATTR_MD2] = NULL,
};

static bool
decode_ovs_key_attr_nsh(struct tcb *const tcp,
	const kernel_ulong_t addr,
	const unsigned int len,
	const void *const opaque_data)
{
	decode_nlattr(tcp, addr, len, ovs_nsh_key_attr,
		"OVS_NSH_KEY_ATTR_???",
		ARRSZ_PAIR(ovs_nsh_key_attrs_attr_decoders),
		NULL);
	return true;
}

static bool
decode_ovs_key_attr_encap(struct tcb *const tcp,
	const kernel_ulong_t addr,
	const unsigned int len,
	const void *const opaque_data);

static const nla_decoder_t key_attrs_attr_decoders[] = {
	[OVS_KEY_ATTR_ENCAP] = decode_ovs_key_attr_encap,
	[OVS_KEY_ATTR_PRIORITY] = decode_nla_u32,
	[OVS_KEY_ATTR_IN_PORT] = decode_nla_u32,
	[OVS_KEY_ATTR_ETHERNET] = NULL,
	[OVS_KEY_ATTR_VLAN] = decode_nla_u16,
	[OVS_KEY_ATTR_ETHERTYPE] = decode_nla_u16,
	[OVS_KEY_ATTR_IPV4] = decode_ovs_key_ipv4,
	[OVS_KEY_ATTR_IPV6] = NULL,
	[OVS_KEY_ATTR_TCP] = decode_ovs_key_tcp,
	[OVS_KEY_ATTR_UDP] = decode_ovs_key_udp,
	[OVS_KEY_ATTR_ICMP] = decode_ovs_key_icmp,
	[OVS_KEY_ATTR_ICMPV6] = decode_ovs_key_icmp,
	[OVS_KEY_ATTR_ARP] = NULL,
	[OVS_KEY_ATTR_ND] = NULL,
	[OVS_KEY_ATTR_SKB_MARK] = decode_nla_u32,
	[OVS_KEY_ATTR_TUNNEL] = decode_ovs_key_attr_tunnel,
	[OVS_KEY_ATTR_SCTP] = decode_ovs_key_sctp,
	[OVS_KEY_ATTR_TCP_FLAGS] = decode_nla_u16,
	[OVS_KEY_ATTR_DP_HASH] = decode_nla_u32,
	[OVS_KEY_ATTR_RECIRC_ID] = decode_nla_u32,
	[OVS_KEY_ATTR_MPLS] = decode_ovs_key_mpls,
	[OVS_KEY_ATTR_CT_STATE] = decode_ct_state_flags,
	[OVS_KEY_ATTR_CT_ZONE] = decode_nla_u16,
	[OVS_KEY_ATTR_CT_MARK] = decode_nla_u32,
	[OVS_KEY_ATTR_CT_LABELS] = NULL,
	[OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV4] = decode_ovs_key_ct_tuple_ipv4,
	[OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV6] = NULL,
	[OVS_KEY_ATTR_NSH] = decode_ovs_key_attr_nsh,
	[OVS_KEY_ATTR_PACKET_TYPE] = decode_nla_u32,
	[OVS_KEY_ATTR_ND_EXTENSIONS] = NULL,
	[OVS_KEY_ATTR_TUNNEL_INFO] = NULL,
	[OVS_KEY_ATTR_IPV6_EXTHDRS] = NULL,
};

static bool
decode_ovs_flow_attr_mask(struct tcb *const tcp,
	const kernel_ulong_t addr,
	const unsigned int len,
	const void *const opaque_data)
{
	decode_nlattr(tcp, addr, len, ovs_key_attr, "OVS_KEY_ATTR_???",
		      ARRSZ_PAIR(key_attrs_attr_decoders), opaque_data);
	return true;
}

static bool
decode_ovs_key_attr_encap(struct tcb *const tcp,
	const kernel_ulong_t addr,
	const unsigned int len,
	const void *const opaque_data)
{
	decode_nlattr(tcp, addr, len, ovs_key_attr, "OVS_KEY_ATTR_???",
		      ARRSZ_PAIR(key_attrs_attr_decoders), opaque_data);
	return true;
}

static bool
decode_ovs_flow_attr_key(struct tcb *const tcp,
	const kernel_ulong_t addr,
	const unsigned int len,
	const void *const opaque_data)
{
	decode_nlattr(tcp, addr, len, ovs_key_attr,
		      "OVS_KEY_ATTR_???", key_attrs_attr_decoders,
		      ARRAY_SIZE(key_attrs_attr_decoders), opaque_data);
	return true;
}

static const nla_decoder_t userspace_attrs_attr_decoders[] = {
	[OVS_USERSPACE_ATTR_PID] = decode_nla_u32,
	[OVS_USERSPACE_ATTR_USERDATA] = NULL,
	[OVS_USERSPACE_ATTR_EGRESS_TUN_PORT] = decode_nla_u32,
	[OVS_USERSPACE_ATTR_ACTIONS] = NULL,
};

static bool
decode_ovs_action_attr_userspace(struct tcb *const tcp,
	const kernel_ulong_t addr,
	const unsigned int len,
	const void *const opaque_data)
{
	decode_nlattr(tcp, addr, len, ovs_userspace_attr,
		      "OVS_USERSPACE_ATTR_???",
		      ARRSZ_PAIR(userspace_attrs_attr_decoders),
		      opaque_data);
	return true;
}

static bool
decode_ovs_action_attr_set(struct tcb *const tcp,
	const kernel_ulong_t addr,
	const unsigned int len,
	const void *const opaque_data)
{
	decode_nlattr(tcp, addr, len, ovs_key_attr,
		      "OVS_KEY_ATTR_???",
		      ARRSZ_PAIR(key_attrs_attr_decoders),
		      NULL);
	return true;
}

static bool
decode_ovs_sample_attr_actions(struct tcb *const tcp,
	const kernel_ulong_t addr,
	const unsigned int len,
	const void *const opaque_data);

static const nla_decoder_t sample_attrs_attr_decoders[] = {
	[OVS_SAMPLE_ATTR_PROBABILITY] = decode_nla_u32,
	[OVS_SAMPLE_ATTR_ACTIONS] = decode_ovs_sample_attr_actions,
};

static bool
decode_ovs_action_attr_sample(struct tcb *const tcp,
	const kernel_ulong_t addr,
	const unsigned int len,
	const void *const opaque_data)
{
	decode_nlattr(tcp, addr, len, ovs_sample_attr,
		"OVS_SAMPLE_ATTR_???",
		ARRSZ_PAIR(sample_attrs_attr_decoders),
		NULL);
	return true;
}

static bool
decode_ovs_action_attr_set_masked(struct tcb *const tcp,
	const kernel_ulong_t addr,
	const unsigned int len,
	const void *const opaque_data)
{
	decode_nlattr(tcp, addr, len, ovs_key_attr,
		"OVS_KEY_ATTR_???",
		ARRSZ_PAIR(key_attrs_attr_decoders),
		NULL);
	return true;
}

static bool
decode_ovs_action_attr_push_nsh(struct tcb *const tcp,
	const kernel_ulong_t addr,
	const unsigned int len,
	const void *const opaque_data)
{
	decode_nlattr(tcp, addr, len, ovs_nsh_key_attr,
		"OVS_NSH_KEY_ATTR_???",
		ARRSZ_PAIR(ovs_nsh_key_attrs_attr_decoders),
		NULL);
	return true;
}

static bool
decode_ovs_action_attr_check_pkt_len(struct tcb *const tcp,
	const kernel_ulong_t addr,
	const unsigned int len,
	const void *const opaque_data);

static bool
decode_ovs_action_attr_clone(struct tcb *const tcp,
	const kernel_ulong_t addr,
	const unsigned int len,
	const void *const opaque_data);

static bool
decode_ovs_action_attr_ct(struct tcb *const tcp,
	const kernel_ulong_t addr,
	const unsigned int len,
	const void *const opaque_data);

static bool
decode_ovs_action_attr_dec_ttl(struct tcb *const tcp,
	const kernel_ulong_t addr,
	const unsigned int len,
	const void *const opaque_data);

static const nla_decoder_t action_attrs_attr_decoders[] = {
	[OVS_ACTION_ATTR_OUTPUT] = decode_nla_u32,
	[OVS_ACTION_ATTR_USERSPACE] = decode_ovs_action_attr_userspace,
	[OVS_ACTION_ATTR_SET] = decode_ovs_action_attr_set,
	[OVS_ACTION_ATTR_PUSH_VLAN] = decode_ovs_action_push_vlan,
	[OVS_ACTION_ATTR_POP_VLAN] = NULL,
	[OVS_ACTION_ATTR_SAMPLE] = decode_ovs_action_attr_sample,
	[OVS_ACTION_ATTR_RECIRC] = decode_nla_u32,
	[OVS_ACTION_ATTR_HASH] = decode_ovs_action_hash,
	[OVS_ACTION_ATTR_PUSH_MPLS] = decode_ovs_action_push_mpls,
	[OVS_ACTION_ATTR_POP_MPLS] = decode_nla_u16,
	[OVS_ACTION_ATTR_SET_MASKED] = decode_ovs_action_attr_set_masked,
	[OVS_ACTION_ATTR_CT] = decode_ovs_action_attr_ct,
	[OVS_ACTION_ATTR_TRUNC] = decode_nla_u32,
	[OVS_ACTION_ATTR_PUSH_ETH] = NULL,
	[OVS_ACTION_ATTR_POP_ETH] = NULL,
	[OVS_ACTION_ATTR_CT_CLEAR] = NULL,
	[OVS_ACTION_ATTR_PUSH_NSH] = decode_ovs_action_attr_push_nsh,
	[OVS_ACTION_ATTR_POP_NSH] = NULL,
	[OVS_ACTION_ATTR_METER] = decode_nla_u32,
	[OVS_ACTION_ATTR_CLONE] = decode_ovs_action_attr_clone,
	[OVS_ACTION_ATTR_CHECK_PKT_LEN] = decode_ovs_action_attr_check_pkt_len,
	[OVS_ACTION_ATTR_ADD_MPLS] = decode_ovs_action_add_mpls,
	[OVS_ACTION_ATTR_DEC_TTL] = decode_ovs_action_attr_dec_ttl,
};

static bool
decode_ovs_action_attr_clone(struct tcb *const tcp,
	const kernel_ulong_t addr,
	const unsigned int len,
	const void *const opaque_data)
{
	decode_nlattr(tcp, addr, len, ovs_action_attr,
		"OVS_ACTION_ATTR_???",
		ARRSZ_PAIR(action_attrs_attr_decoders),
		NULL);
	return true;
}

static bool
decode_ovs_flow_attr_actions(struct tcb *const tcp,
	const kernel_ulong_t addr,
	const unsigned int len,
	const void *const opaque_data)
{
	decode_nlattr(tcp, addr, len, ovs_action_attr,
		"OVS_ACTION_ATTR_???",
		ARRSZ_PAIR(action_attrs_attr_decoders),
		NULL);
	return true;
}

static bool
decode_ovs_check_pkt_len_attr_actions_if_greater(struct tcb *const tcp,
	const kernel_ulong_t addr,
	const unsigned int len,
	const void *const opaque_data)
{
	decode_nlattr(tcp, addr, len, ovs_action_attr,
		"OVS_ACTION_ATTR_???",
		ARRSZ_PAIR(action_attrs_attr_decoders),
		NULL);
	return true;
}

static bool
decode_ovs_check_pkt_len_attr_actions_if_less_equal(struct tcb *const tcp,
	const kernel_ulong_t addr,
	const unsigned int len,
	const void *const opaque_data)
{
	decode_nlattr(tcp, addr, len, ovs_action_attr,
		"OVS_ACTION_ATTR_???",
		ARRSZ_PAIR(action_attrs_attr_decoders),
		NULL);
	return true;
}

static const nla_decoder_t check_pkt_len_attrs_attr_decoders[] = {
	[OVS_CHECK_PKT_LEN_ATTR_PKT_LEN] = decode_nla_u16,
	[OVS_CHECK_PKT_LEN_ATTR_ACTIONS_IF_GREATER] = decode_ovs_check_pkt_len_attr_actions_if_greater,
	[OVS_CHECK_PKT_LEN_ATTR_ACTIONS_IF_LESS_EQUAL] = decode_ovs_check_pkt_len_attr_actions_if_less_equal,
};

static bool
decode_ovs_action_attr_check_pkt_len(struct tcb *const tcp,
	const kernel_ulong_t addr,
	const unsigned int len,
	const void *const opaque_data)
{
	decode_nlattr(tcp, addr, len, ovs_check_pkt_len_attr,
		"OVS_CHECK_PKT_LEN_ATTR_???",
		ARRSZ_PAIR(check_pkt_len_attrs_attr_decoders),
		NULL);
	return true;
}

static bool
decode_ovs_sample_attr_actions(struct tcb *const tcp,
	const kernel_ulong_t addr,
	const unsigned int len,
	const void *const opaque_data)
{
	decode_nlattr(tcp, addr, len, ovs_action_attr,
		"OVS_ACTION_ATTR_???",
		ARRSZ_PAIR(action_attrs_attr_decoders),
		NULL);
	return true;
}

static bool
decode_ovs_ct_attr_nat(struct tcb *const tcp,
	const kernel_ulong_t addr,
	const unsigned int len,
	const void *const opaque_data);

static const nla_decoder_t ct_attrs_attr_decoders[] = {
	[OVS_CT_ATTR_COMMIT] = NULL,
	[OVS_CT_ATTR_ZONE] = decode_nla_u16,
	[OVS_CT_ATTR_MARK] = NULL,
	[OVS_CT_ATTR_LABELS] = NULL,
	[OVS_CT_ATTR_HELPER] = decode_nla_str,
	[OVS_CT_ATTR_NAT] = decode_ovs_ct_attr_nat,
	[OVS_CT_ATTR_FORCE_COMMIT] = NULL,
	[OVS_CT_ATTR_EVENTMASK] = decode_nla_u32,
	[OVS_CT_ATTR_TIMEOUT] = decode_nla_str,
};

static bool
decode_ovs_action_attr_ct(struct tcb *const tcp,
	const kernel_ulong_t addr,
	const unsigned int len,
	const void *const opaque_data)
{
	decode_nlattr(tcp, addr, len, ovs_ct_attr,
		"OVS_CT_ATTR_???",
		ARRSZ_PAIR(ct_attrs_attr_decoders),
		NULL);
	return true;
}

static const nla_decoder_t nat_attrs_attr_decoders[] = {
	[OVS_NAT_ATTR_SRC] = NULL,
	[OVS_NAT_ATTR_DST] = NULL,
	[OVS_NAT_ATTR_IP_MIN] = NULL,
	[OVS_NAT_ATTR_IP_MAX] = NULL,
	[OVS_NAT_ATTR_PROTO_MIN] = decode_nla_u16,
	[OVS_NAT_ATTR_PROTO_MAX] = decode_nla_u16,
	[OVS_NAT_ATTR_PERSISTENT] = NULL,
	[OVS_NAT_ATTR_PROTO_HASH] = NULL,
	[OVS_NAT_ATTR_PROTO_RANDOM] = NULL,
};

static bool
decode_ovs_ct_attr_nat(struct tcb *const tcp,
	const kernel_ulong_t addr,
	const unsigned int len,
	const void *const opaque_data)
{
	decode_nlattr(tcp, addr, len, ovs_nat_attr,
		"OVS_NAT_ATTR_???",
		ARRSZ_PAIR(nat_attrs_attr_decoders),
		NULL);
	return true;
}

static bool
decode_ovs_dec_ttl_attr_action(struct tcb *const tcp,
	const kernel_ulong_t addr,
	const unsigned int len,
	const void *const opaque_data)
{
	decode_nlattr(tcp, addr, len, ovs_action_attr,
		"OVS_ACTION_ATTR_???",
		ARRSZ_PAIR(action_attrs_attr_decoders),
		NULL);
	return true;
}

static const nla_decoder_t dec_ttl_attrs_attr_decoders[] = {
	[OVS_DEC_TTL_ATTR_ACTION] = decode_ovs_dec_ttl_attr_action,
};

static bool
decode_ovs_action_attr_dec_ttl(struct tcb *const tcp,
	const kernel_ulong_t addr,
	const unsigned int len,
	const void *const opaque_data)
{
	decode_nlattr(tcp, addr, len, ovs_dec_ttl_attr,
		"OVS_DEC_TTL_ATTR_???",
		ARRSZ_PAIR(dec_ttl_attrs_attr_decoders),
		NULL);
	return true;
}

static const nla_decoder_t flow_attrs_attr_decoders[] = {
	[OVS_FLOW_ATTR_KEY] = decode_ovs_flow_attr_key,
	[OVS_FLOW_ATTR_ACTIONS] = decode_ovs_flow_attr_actions,
	[OVS_FLOW_ATTR_STATS] = decode_ovs_flow_stats,
	[OVS_FLOW_ATTR_TCP_FLAGS] = decode_nla_u8,
	[OVS_FLOW_ATTR_USED] = decode_nla_u64,
	[OVS_FLOW_ATTR_CLEAR] = NULL,
	[OVS_FLOW_ATTR_MASK] = decode_ovs_flow_attr_mask,
	[OVS_FLOW_ATTR_PROBE] = NULL,
	[OVS_FLOW_ATTR_UFID] = NULL,
	[OVS_FLOW_ATTR_UFID_FLAGS] = decode_ovs_ufid_flags,
	[OVS_FLOW_ATTR_PAD] = NULL,
};

DECL_NETLINK_GENERIC_DECODER(decode_ovs_flow_msg) {
	struct ovs_header header;
	size_t offset = sizeof(struct ovs_header);

	tprint_struct_begin();
	PRINT_FIELD_XVAL(*genl, cmd, ovs_flow_cmds, "OVS_FLOW_CMD_???");
	tprint_struct_next();
	PRINT_FIELD_U(*genl, version);
	tprint_struct_next();
	if (umove_or_printaddr(tcp, addr, &header))
		return;
	PRINT_FIELD_U(header, dp_ifindex);
	tprint_struct_next();

	decode_nlattr(tcp, addr + offset, len - offset,
		ovs_flow_attr,
		"OVS_FLOW_ATTR_???",
		ARRSZ_PAIR(flow_attrs_attr_decoders),
		NULL);
	tprint_struct_end();
}
