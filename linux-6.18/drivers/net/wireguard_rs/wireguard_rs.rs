// SPDX-License-Identifier: GPL-2.0
//! Wireguard Rust experimental kernel module.
use kernel::prelude::*;
use kernel::{bindings, types::Opaque};

module! {
    type: WireguardRs,
    name: "wireguard_rs",
    authors: ["Anonymous"],
    description: "Rust wireguard_rs",
    license: "GPL",
}

struct WireguardRs {}

impl kernel::Module for WireguardRs {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        let ptr = LINK_OPS.as_ptr();
        // SAFETY: ptr points to a properly initialized rtnl_link_ops.
        // And the table is a static, so it stays valid for as long as the module is loaded.
        // Opaque wraps an UnsafeCell so it makes writing through a pointer we got
        // from a non-mut static legal.
        // The table isn't registered twice because the kernel only calls init once.
        kernel::error::to_result(unsafe { bindings::rtnl_link_register(ptr) })?;

        Ok(WireguardRs {})
    }
}

impl Drop for WireguardRs {
    fn drop(&mut self) {
        let ptr = LINK_OPS.as_ptr();
        // SAFETY: The table is definitely registered when drop runs because there is no
        // drop without a full init, the ? operator returns early on failure, so Ok implies
        // registered.
        // ptr points to a properly initialized rtnl_link_ops, it is the same pointer
        // that was registered.
        // rtnl_link_unregister takes rtnl_lock itself
        // therefore the caller must not hold it, and drop doesn't,
        // because module exit isn't called under rtnl.
        unsafe {
            bindings::rtnl_link_unregister(ptr);
        }
    }
}

// SAFETY: We initialize a net_device_ops zeroed out,
// All the fields are Options of function pointers that will be None (NULL for C)
static WG_NETDEV_OPS: bindings::net_device_ops = unsafe { core::mem::zeroed() };

/// # Safety
///
/// dev points to a valid, freshly allocated net_device
unsafe extern "C" fn wg_setup(dev: *mut bindings::net_device) {
    pr_info!("wg_setup called\n");
    // SAFETY: It is OK to write through dev because it points to a valid freshly allocated net_device
    // WG_NETDEV_OPS is a static, so it lives as long as the module is loaded
    // and the device holding the pointer can't outlive the module because of rtnl_link_unregister
    // in Drop that destroysbevery remaining link of this kind before it returns
    unsafe {
        (*dev).netdev_ops = core::ptr::addr_of!(WG_NETDEV_OPS);
    }
}

struct LinkOps(Opaque<bindings::rtnl_link_ops>);
// SAFETY: LinkOps is only ever handed to the kernel by pointer, so sharing it is fine:
// Safe Rust code holding a &LinkOps can only obtain a raw pointer. It can never read
// or write the data without unsafe
// The kernel serializes writers with link_ops_mutex, protects list traversal with RCU,
// and protects the table while in use via its own SRCU.
unsafe impl Sync for LinkOps {}

impl LinkOps {
    const fn new() -> LinkOps {
        LinkOps(Opaque::new(bindings::rtnl_link_ops {
            kind: kernel::str::as_char_ptr_in_const_context(kernel::c_str!("wireguard_rs")),
            priv_size: 0,
            setup: Some(wg_setup),

            // SAFETY: The rest is zeroed out to initialize `struct rtnl_link_ops`,
            // For Option (alloc, newlink, dellink, validate): None, NULL for C
            // For Raw pointers (policy, slave_policy): NULL
            // Integers and bools (maxtype, peer_type, netns_refund): 0/false
            // Embedded structs (list, srcu): plain zeroed data the kernel initializes
            // them itself in rtnl_link_register, and nothing reads them before that
            // all-zero is therefore a valid rtnl_link_ops value
            ..unsafe { core::mem::MaybeUninit::<bindings::rtnl_link_ops>::zeroed().assume_init() }
        }))
    }
    fn as_ptr(&self) -> *mut bindings::rtnl_link_ops {
        self.0.get()
    }
}

static LINK_OPS: LinkOps = LinkOps::new();
