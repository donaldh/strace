#include "defs.h"
#include "netlink.h"
#include "nlattr.h"
#include <linux/genetlink.h>
#include <linux/openvswitch.h>
#include "netlink_generic.h"
#include "xlat/ovs_datapath_user_features.h"
#include "xlat/ovs_datapath_attrs.h"
#include "xlat/ovs_datapath_cmds.h"

static bool
decode_user_features(struct tcb *const tcp,
		const kernel_ulong_t addr,
		const unsigned int len,
		const void *const opaque_data)
{
	static const struct decode_nla_xlat_opts opts = {
		ovs_datapath_user_features, "OVS_DP_F_???", .size = 4
	};
	return decode_nla_flags(tcp, addr, len, &opts);
}

static bool
decode_ovs_dp_stats(struct tcb *const tcp,
		const kernel_ulong_t addr,
		const unsigned int len,
		const void *const opaque_data)
{
	struct ovs_dp_stats datapath_stats;
	umove_or_printaddr(tcp, addr, &datapath_stats);

	PRINT_FIELD_U(datapath_stats, n_hit);
	tprint_struct_next();
	PRINT_FIELD_U(datapath_stats, n_missed);
	tprint_struct_next();
	PRINT_FIELD_U(datapath_stats, n_lost);
	tprint_struct_next();
	PRINT_FIELD_U(datapath_stats, n_flows);
	tprint_struct_next();
	return true;
}

static bool
decode_ovs_dp_megaflow_stats(struct tcb *const tcp,
		const kernel_ulong_t addr,
		const unsigned int len,
		const void *const opaque_data)
{
	struct ovs_dp_megaflow_stats megaflow_stats;
	umove_or_printaddr(tcp, addr, &megaflow_stats);

	PRINT_FIELD_U(megaflow_stats, n_mask_hit);
	tprint_struct_next();
	PRINT_FIELD_U(megaflow_stats, n_masks);
	tprint_struct_next();
	PRINT_FIELD_U(megaflow_stats, n_cache_hit);
	tprint_struct_next();
	return true;
}

static const nla_decoder_t datapath_attr_decoders[] = {
	[OVS_DP_ATTR_NAME] = decode_nla_str,
	[OVS_DP_ATTR_UPCALL_PID] = decode_nla_u32,
	[OVS_DP_ATTR_STATS] = decode_ovs_dp_stats,
	[OVS_DP_ATTR_MEGAFLOW_STATS] = decode_ovs_dp_megaflow_stats,
	[OVS_DP_ATTR_USER_FEATURES] = decode_user_features,
	[OVS_DP_ATTR_PAD] = NULL,
	[OVS_DP_ATTR_MASKS_CACHE_SIZE] = decode_nla_u32,
	[OVS_DP_ATTR_PER_CPU_PIDS] = NULL,
	[OVS_DP_ATTR_IFINDEX] = decode_nla_u32,
};

DECL_NETLINK_GENERIC_DECODER(decode_ovs_datapath_msg) {
	struct ovs_header header;
	umove_or_printaddr(tcp, addr, &header);
	size_t offset = sizeof(struct ovs_header);

	tprint_struct_begin();
	PRINT_FIELD_XVAL(*genl, cmd, ovs_datapath_cmds, "OVS_DP_CMD_???");
	tprint_struct_next();
	PRINT_FIELD_U(*genl, version);
	tprint_struct_next();
	PRINT_FIELD_U(header, dp_ifindex);
	tprint_struct_next();

	decode_nlattr(tcp, addr + offset, len - offset,
			       ovs_datapath_attrs,
			       "OVS_DP_ATTR_???",
			       ARRSZ_PAIR(datapath_attr_decoders),
			       NULL);
	tprint_struct_end();
}
