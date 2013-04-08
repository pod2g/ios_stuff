from idaapi import *
from idc import *
import idautils

def register_mac_policy():
	macpolicy = """
struct mac_policy_ops {
	int		*mpo_audit_check_postselect;
	int		*mpo_audit_check_preselect;
	int		*mpo_bpfdesc_label_associate;
	int		*mpo_bpfdesc_label_destroy;
	int		*mpo_bpfdesc_label_init;
	int		*mpo_bpfdesc_check_receive;
	int		*mpo_cred_check_label_update_execve;
	int		*mpo_cred_check_label_update;
	int		*mpo_cred_check_visible;
	int		*mpo_cred_label_associate_fork;
	int		*mpo_cred_label_associate_kernel;
	int		*mpo_cred_label_associate;
	int		*mpo_cred_label_associate_user;
	int		*mpo_cred_label_destroy;
	int		*mpo_cred_label_externalize_audit;
	int		*mpo_cred_label_externalize;
	int		*mpo_cred_label_init;
	int		*mpo_cred_label_internalize;
	int		*mpo_cred_label_update_execve;
	int		*mpo_cred_label_update;
	int		*mpo_devfs_label_associate_device;
	int		*mpo_devfs_label_associate_directory;
	int		*mpo_devfs_label_copy;
	int		*mpo_devfs_label_destroy;
	int		*mpo_devfs_label_init;
	int		*mpo_devfs_label_update;
	int		*mpo_file_check_change_offset;
	int		*mpo_file_check_create;
	int		*mpo_file_check_dup;
	int		*mpo_file_check_fcntl;
	int		*mpo_file_check_get_offset;
	int		*mpo_file_check_get;
	int		*mpo_file_check_inherit;
	int		*mpo_file_check_ioctl;
	int		*mpo_file_check_lock;
	int		*mpo_file_check_mmap_downgrade;
	int		*mpo_file_check_mmap;
	int		*mpo_file_check_receive;
	int		*mpo_file_check_set;
	int		*mpo_file_label_init;
	int		*mpo_file_label_destroy;
	int		*mpo_file_label_associate;
	int		*mpo_ifnet_check_label_update;
	int		*mpo_ifnet_check_transmit;
	int		*mpo_ifnet_label_associate;
	int		*mpo_ifnet_label_copy;
	int		*mpo_ifnet_label_destroy;
	int		*mpo_ifnet_label_externalize;
	int		*mpo_ifnet_label_init;
	int		*mpo_ifnet_label_internalize;
	int		*mpo_ifnet_label_update;
	int		*mpo_ifnet_label_recycle;
	int		*mpo_inpcb_check_deliver;
	int		*mpo_inpcb_label_associate;
	int		*mpo_inpcb_label_destroy;
	int		*mpo_inpcb_label_init;
	int		*mpo_inpcb_label_recycle;
	int		*mpo_inpcb_label_update;
	int		*mpo_iokit_check_device;
	int		*mpo_ipq_label_associate;
	int		*mpo_ipq_label_compare;
	int		*mpo_ipq_label_destroy;
	int		*mpo_ipq_label_init;
	int		*mpo_ipq_label_update;
	int		*mpo_lctx_check_label_update;
	int		*mpo_lctx_label_destroy;
	int		*mpo_lctx_label_externalize;
	int		*mpo_lctx_label_init;
	int		*mpo_lctx_label_internalize;
	int		*mpo_lctx_label_update;
	int		*mpo_lctx_notify_create;
	int		*mpo_lctx_notify_join;
	int		*mpo_lctx_notify_leave;
	int		*mpo_mbuf_label_associate_bpfdesc;
	int		*mpo_mbuf_label_associate_ifnet;
	int		*mpo_mbuf_label_associate_inpcb;
	int		*mpo_mbuf_label_associate_ipq;
	int		*mpo_mbuf_label_associate_linklayer;
	int 	*mpo_mbuf_label_associate_multicast_encap;
	int		*mpo_mbuf_label_associate_netlayer;
	int		*mpo_mbuf_label_associate_socket;
	int		*mpo_mbuf_label_copy;
	int		*mpo_mbuf_label_destroy;
	int		*mpo_mbuf_label_init;
	int		*mpo_mount_check_fsctl;
	int		*mpo_mount_check_getattr;
	int		*mpo_mount_check_label_update;
	int		*mpo_mount_check_mount;
	int		*mpo_mount_check_remount;
	int		*mpo_mount_check_setattr;
	int		*mpo_mount_check_stat;
	int		*mpo_mount_check_umount;
	int		*mpo_mount_label_associate;
	int		*mpo_mount_label_destroy;
	int		*mpo_mount_label_externalize;
	int		*mpo_mount_label_init;
	int		*mpo_mount_label_internalize;
	int		*mpo_netinet_fragment;
	int		*mpo_netinet_icmp_reply;
	int		*mpo_netinet_tcp_reply;
	int		*mpo_pipe_check_ioctl;
	int		*mpo_pipe_check_kqfilter;
	int		*mpo_pipe_check_label_update;
	int		*mpo_pipe_check_read;
	int		*mpo_pipe_check_select;
	int		*mpo_pipe_check_stat;
	int		*mpo_pipe_check_write;
	int		*mpo_pipe_label_associate;
	int		*mpo_pipe_label_copy;
	int		*mpo_pipe_label_destroy;
	int		*mpo_pipe_label_externalize;
	int		*mpo_pipe_label_init;
	int		*mpo_pipe_label_internalize;
	int		*mpo_pipe_label_update;
	int		*mpo_policy_destroy;
	int		*mpo_policy_init;
	int		*mpo_policy_initbsd;
	int		*mpo_policy_syscall;
	int		*mpo_port_check_copy_send;
	int		*mpo_port_check_hold_receive;
	int		*mpo_port_check_hold_send_once;
	int		*mpo_port_check_hold_send;
	int		*mpo_port_check_label_update;
	int		*mpo_port_check_make_send_once;
	int		*mpo_port_check_make_send;
	int		*mpo_port_check_method;
	int		*mpo_port_check_move_receive;
	int		*mpo_port_check_move_send_once;
	int		*mpo_port_check_move_send;
	int		*mpo_port_check_receive;
	int		*mpo_port_check_send;
	int		*mpo_port_check_service;
	int		*mpo_port_label_associate_kernel;
	int		*mpo_port_label_associate;
	int		*mpo_port_label_compute;
	int		*mpo_port_label_copy;
	int		*mpo_port_label_destroy;
	int		*mpo_port_label_init;
	int		*mpo_port_label_update_cred;
	int		*mpo_port_label_update_kobject;
	int		*mpo_posixsem_check_create;
	int		*mpo_posixsem_check_open;
	int		*mpo_posixsem_check_post;
	int		*mpo_posixsem_check_unlink;
	int		*mpo_posixsem_check_wait;
	int		*mpo_posixsem_label_associate;
	int		*mpo_posixsem_label_destroy;
	int		*mpo_posixsem_label_init;
	int		*mpo_posixshm_check_create;
	int		*mpo_posixshm_check_mmap;
	int		*mpo_posixshm_check_open;
	int		*mpo_posixshm_check_stat;
	int		*mpo_posixshm_check_truncate;
	int		*mpo_posixshm_check_unlink;
	int		*mpo_posixshm_label_associate;
	int		*mpo_posixshm_label_destroy;
	int		*mpo_posixshm_label_init;
	int		*mpo_proc_check_debug;
	int		*mpo_proc_check_fork;
	int		*mpo_proc_check_get_task_name;
	int		*mpo_proc_check_get_task;
	int		*mpo_proc_check_getaudit;
	int		*mpo_proc_check_getauid;
	int		*mpo_proc_check_getlcid;
	int		*mpo_proc_check_mprotect;
	int		*mpo_proc_check_sched;
	int		*mpo_proc_check_setaudit;
	int		*mpo_proc_check_setauid;
	int		*mpo_proc_check_setlcid;
	int		*mpo_proc_check_signal;
	int		*mpo_proc_check_wait;
	int		*mpo_proc_label_destroy;
	int		*mpo_proc_label_init;
	int		*mpo_socket_check_accept;
	int		*mpo_socket_check_accepted;
	int		*mpo_socket_check_bind;
	int		*mpo_socket_check_connect;
	int		*mpo_socket_check_create;
	int		*mpo_socket_check_deliver;
	int		*mpo_socket_check_kqfilter;
	int		*mpo_socket_check_label_update;
	int		*mpo_socket_check_listen;
	int		*mpo_socket_check_receive;
	int		*mpo_socket_check_received;
	int		*mpo_socket_check_select;
	int		*mpo_socket_check_send;
	int		*mpo_socket_check_stat;
	int		*mpo_socket_check_setsockopt;
	int		*mpo_socket_check_getsockopt;
	int		*mpo_socket_label_associate_accept;
	int		*mpo_socket_label_associate;
	int		*mpo_socket_label_copy;
	int		*mpo_socket_label_destroy;
	int		*mpo_socket_label_externalize;
	int		*mpo_socket_label_init;
	int		*mpo_socket_label_internalize;
	int		*mpo_socket_label_update;
	int		*mpo_socketpeer_label_associate_mbuf;
	int		*mpo_socketpeer_label_associate_socket;
	int		*mpo_socketpeer_label_destroy;
	int		*mpo_socketpeer_label_externalize;
	int		*mpo_socketpeer_label_init;
	int		*mpo_system_check_acct;
	int		*mpo_system_check_audit;
	int		*mpo_system_check_auditctl;
	int		*mpo_system_check_auditon;
	int		*mpo_system_check_host_priv;
	int		*mpo_system_check_nfsd;
	int		*mpo_system_check_reboot;
	int		*mpo_system_check_settime;
	int		*mpo_system_check_swapoff;
	int		*mpo_system_check_swapon;
	int		*mpo_system_check_sysctl;
	int		*mpo_sysvmsg_label_associate;
	int		*mpo_sysvmsg_label_destroy;
	int		*mpo_sysvmsg_label_init;
	int		*mpo_sysvmsg_label_recycle;
	int		*mpo_sysvmsq_check_enqueue;
	int		*mpo_sysvmsq_check_msgrcv;
	int		*mpo_sysvmsq_check_msgrmid;
	int		*mpo_sysvmsq_check_msqctl;
	int		*mpo_sysvmsq_check_msqget;
	int		*mpo_sysvmsq_check_msqrcv;
	int		*mpo_sysvmsq_check_msqsnd;
	int		*mpo_sysvmsq_label_associate;
	int		*mpo_sysvmsq_label_destroy;
	int		*mpo_sysvmsq_label_init;
	int		*mpo_sysvmsq_label_recycle;
	int		*mpo_sysvsem_check_semctl;
	int		*mpo_sysvsem_check_semget;
	int		*mpo_sysvsem_check_semop;
	int		*mpo_sysvsem_label_associate;
	int		*mpo_sysvsem_label_destroy;
	int		*mpo_sysvsem_label_init;
	int		*mpo_sysvsem_label_recycle;
	int		*mpo_sysvshm_check_shmat;
	int		*mpo_sysvshm_check_shmctl;
	int		*mpo_sysvshm_check_shmdt;
	int		*mpo_sysvshm_check_shmget;
	int		*mpo_sysvshm_label_associate;
	int		*mpo_sysvshm_label_destroy;
	int		*mpo_sysvshm_label_init;
	int		*mpo_sysvshm_label_recycle;
	int		*mpo_task_label_associate_kernel;
	int		*mpo_task_label_associate;
	int		*mpo_task_label_copy;
	int		*mpo_task_label_destroy;
	int		*mpo_task_label_externalize;
	int		*mpo_task_label_init;
	int		*mpo_task_label_internalize;
	int		*mpo_task_label_update;
	int		*mpo_iokit_check_hid_control;
	int		*mpo_vnode_check_access;
	int		*mpo_vnode_check_chdir;
	int		*mpo_vnode_check_chroot;
	int		*mpo_vnode_check_create;
	int		*mpo_vnode_check_deleteextattr;
	int		*mpo_vnode_check_exchangedata;
	int		*mpo_vnode_check_exec;
	int		*mpo_vnode_check_getattrlist;
	int		*mpo_vnode_check_getextattr;
	int		*mpo_vnode_check_ioctl;
	int		*mpo_vnode_check_kqfilter;
	int		*mpo_vnode_check_label_update;
	int		*mpo_vnode_check_link;
	int		*mpo_vnode_check_listextattr;
	int		*mpo_vnode_check_lookup;
	int		*mpo_vnode_check_open;
	int		*mpo_vnode_check_read;
	int		*mpo_vnode_check_readdir;
	int		*mpo_vnode_check_readlink;
	int		*mpo_vnode_check_rename_from;
	int		*mpo_vnode_check_rename_to;
	int		*mpo_vnode_check_revoke;
	int		*mpo_vnode_check_select;
	int		*mpo_vnode_check_setattrlist;
	int		*mpo_vnode_check_setextattr;
	int		*mpo_vnode_check_setflags;
	int		*mpo_vnode_check_setmode;
	int		*mpo_vnode_check_setowner;
	int		*mpo_vnode_check_setutimes;
	int		*mpo_vnode_check_stat;
	int		*mpo_vnode_check_truncate;
	int		*mpo_vnode_check_unlink;
	int		*mpo_vnode_check_write;
	int		*mpo_vnode_label_associate_devfs;
	int		*mpo_vnode_label_associate_extattr;
	int		*mpo_vnode_label_associate_file;
	int		*mpo_vnode_label_associate_pipe;
	int		*mpo_vnode_label_associate_posixsem;
	int		*mpo_vnode_label_associate_posixshm;
	int		*mpo_vnode_label_associate_singlelabel;
	int		*mpo_vnode_label_associate_socket;
	int		*mpo_vnode_label_copy;
	int		*mpo_vnode_label_destroy;
	int		*mpo_vnode_label_externalize_audit;
	int		*mpo_vnode_label_externalize;
	int		*mpo_vnode_label_init;
	int		*mpo_vnode_label_internalize;
	int		*mpo_vnode_label_recycle;
	int		*mpo_vnode_label_store;
	int		*mpo_vnode_label_update_extattr;
	int		*mpo_vnode_label_update;
	int		*mpo_vnode_notify_create;
	int		*mpo_vnode_check_signature;
	int		*mpo_vnode_check_uipc_bind;
	int		*mpo_vnode_check_uipc_connect;
	int		*mpo_proc_check_run_cs_invalid;
	int		*mpo_proc_check_suspend_resume;
	int		*mpo_thread_userret;
	int		*mpo_iokit_check_set_properties;
	int		*mpo_system_check_chud;
	int		*mpo_vnode_check_searchfs;
	int		*mpo_priv_check;
	int		*mpo_priv_grant;
	int		*mpo_proc_check_map_anon;
	int		*mpo_vnode_check_fsgetpath;
	int		*mpo_iokit_check_open;
 	int		*mpo_proc_check_ledger;
	int		*mpo_vnode_notify_rename;
	int		*mpo_thread_label_init;
	int		*mpo_thread_label_destroy;
	int		*mpo_system_check_kas_info;
	int		*mpo_reserved18;
	int		*mpo_reserved19;
	int		*mpo_reserved20;
	int		*mpo_reserved21;
	int		*mpo_reserved22;
	int		*mpo_reserved23;
	int		*mpo_reserved24;
	int		*mpo_reserved25;
	int		*mpo_reserved26;
	int		*mpo_reserved27;
	int		*mpo_reserved28;
	int		*mpo_reserved29;
};

struct mac_policy_conf {
   const char *mpc_name; /** policy name */
   const char *mpc_fullname; /** full name */
   const char **mpc_labelnames; /** managed label namespaces */
   unsigned int mpc_labelname_count; /** number of managed label namespaces
   */
   struct mac_policy_ops *mpc_ops; /** operation vector */
   int mpc_loadtime_flags; /** load time flags */
   int *mpc_field_off; /** label slot */
   int mpc_runtime_flags; /** run time flags */
   void* mpc_list; /** List reference */
   void *mpc_data; /** module data */
};

int mac_policy_register(
   struct mac_policy_conf *mpc,
   void *handlep,
   void *xd);
   
"""
	idc.ParseTypes(macpolicy, 0)
	
def fix_policy_ops_names(struct_addr, nameprefix):
	idx, sid, name = [x for x in Structs() if x[2] == "mac_policy_ops"][0]

	for offset, field_name, sz in StructMembers(sid):
		d = Dword(struct_addr+offset)
		if d != 0:
			n = Name(d & ~1)
			if n.startswith("sub_") or n.startswith("loc_"):
				newname = "%s_%s" % (nameprefix, field_name)
				print "Renaming %s to %s" % (n, newname)
				MakeName(d & ~1, newname)

mac_policy_ops = GetStrucIdByName("mac_policy_ops")
if mac_policy_ops == 0xffffffff:
	register_mac_policy()

for seg_ea in Segments():
	name = SegName(seg_ea)
	if name == "com.apple.security.sandbox:__data":
		seg_end = SegEnd(seg_ea)
		i = seg_ea
		while i < seg_end:
			x = GetString(Dword(i))
			if x == "Seatbelt sandbox policy":
				mpc_ops = Dword(i+12)
				print "Found sandbox mpc_ops at 0x%x" % mpc_ops
				MakeStructEx(mpc_ops, -1, "mac_policy_ops")
				fix_policy_ops_names(mpc_ops, "sb")
			i+=4
	
