#include "defs.h"
#include "netlink.h"
#include "nlattr.h"
#include <linux/genetlink.h>
#include <linux/openvswitch.h>
#include "netlink_generic.h"
#include "xlat/ovs_vport_vport_type.h"
#include "xlat/ovs_vport_options.h"
#include "xlat/ovs_vport_attr.h"
#include "xlat/ovs_vport_cmds.h"

static bool
decode_vport_type(struct tcb *const tcp,
		const kernel_ulong_t addr,
		const unsigned int len,
		const void *const opaque_data)
{
	static const struct decode_nla_xlat_opts opts = {
		ovs_vport_vport_type, "OVS_VPORT_TYPE_???", .size = 4
	};
	return decode_nla_xval(tcp, addr, len, &opts);
}

static bool
decode_ovs_vport_stats(struct tcb *const tcp,
		const kernel_ulong_t addr,
		const unsigned int len,
		const void *const opaque_data)
{
	struct ovs_vport_stats vport_stats;
	umove_or_printaddr(tcp, addr, &vport_stats);

	PRINT_FIELD_U(vport_stats, rx_packets);
	tprint_struct_next();
	PRINT_FIELD_U(vport_stats, tx_packets);
	tprint_struct_next();
	PRINT_FIELD_U(vport_stats, rx_bytes);
	tprint_struct_next();
	PRINT_FIELD_U(vport_stats, tx_bytes);
	tprint_struct_next();
	PRINT_FIELD_U(vport_stats, rx_errors);
	tprint_struct_next();
	PRINT_FIELD_U(vport_stats, tx_errors);
	tprint_struct_next();
	PRINT_FIELD_U(vport_stats, rx_dropped);
	tprint_struct_next();
	PRINT_FIELD_U(vport_stats, tx_dropped);
	tprint_struct_next();
	return true;
}

static const nla_decoder_t vport_options_attr_decoders[] = {
	[OVS_TUNNEL_ATTR_DST_PORT] = decode_nla_u32,
	[OVS_TUNNEL_ATTR_EXTENSION] = decode_nla_u32,
};

static bool
decode_ovs_vport_attr_options_item(struct tcb *const tcp,
	const kernel_ulong_t addr,
	const unsigned int len,
	const void *const opaque_data)
{
	decode_nlattr(tcp, addr, len, ovs_vport_options,
		"OVS_TUNNEL_ATTR_???",
	ARRSZ_PAIR(vport_options_attr_decoders),
		NULL);
	return true;
}

static bool
decode_ovs_vport_attr_options(struct tcb *const tcp,
	const kernel_ulong_t addr,
	const unsigned int len,
	const void *const opaque_data)
{
	nla_decoder_t decoder = &decode_ovs_vport_attr_options_item;
	decode_nlattr(tcp, addr, len, NULL, NULL, &decoder, 0, NULL);
	return true;
}

static const nla_decoder_t vport_attr_decoders[] = {
	[OVS_VPORT_ATTR_PORT_NO] = decode_nla_u32,
	[OVS_VPORT_ATTR_TYPE] = decode_vport_type,
	[OVS_VPORT_ATTR_NAME] = decode_nla_str,
	[OVS_VPORT_ATTR_OPTIONS] = decode_ovs_vport_attr_options,
	[OVS_VPORT_ATTR_UPCALL_PID] = NULL,
	[OVS_VPORT_ATTR_STATS] = decode_ovs_vport_stats,
	[OVS_VPORT_ATTR_PAD] = NULL,
	[OVS_VPORT_ATTR_IFINDEX] = decode_nla_u32,
	[OVS_VPORT_ATTR_NETNSID] = decode_nla_u32,
};

DECL_NETLINK_GENERIC_DECODER(decode_ovs_vport_msg) {
	struct ovs_header header;
	umove_or_printaddr(tcp, addr, &header);
	size_t offset = sizeof(struct ovs_header);

	tprint_struct_begin();
	PRINT_FIELD_XVAL(*genl, cmd, ovs_vport_cmds, "OVS_VPORT_CMD_???");
	tprint_struct_next();
	PRINT_FIELD_U(*genl, version);
	tprint_struct_next();
	PRINT_FIELD_U(header, dp_ifindex);
	tprint_struct_next();

	decode_nlattr(tcp, addr + offset, len - offset,
		ovs_vport_attr,
		"OVS_VPORT_ATTR_???",
		ARRSZ_PAIR(vport_attr_decoders),
		NULL);
	tprint_struct_end();
}
