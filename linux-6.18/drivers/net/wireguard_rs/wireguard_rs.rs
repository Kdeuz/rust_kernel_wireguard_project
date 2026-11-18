// SPDX-License-Identifier: GPL-2.0
//! Wireguard Rust experimental kernel module.
use core::sync::atomic::{AtomicU64, Ordering};
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

static WG_NETDEV_OPS: bindings::net_device_ops = bindings::net_device_ops {
    ndo_start_xmit: Some(wg_xmit),

    // SAFETY: We initialize a net_device_ops zeroed out,
    // Every remaining field is an Option of function pointers that will be None (NULL for C)
    ..unsafe { core::mem::zeroed() }
};

/// # Safety
///
/// dev points to a valid, freshly allocated net_device which comes from LINK_OPS
unsafe extern "C" fn wg_setup(dev: *mut bindings::net_device) {
    pr_info!("wg_setup called\n");
    // SAFETY: It is OK to write through dev because it points to a valid freshly allocated net_device
    // WG_NETDEV_OPS is a static, so it lives as long as the module is loaded
    // and the device holding the pointer can't outlive the module because of rtnl_link_unregister
    // in Drop that destroys every remaining link of this kind before it returns
    unsafe {
        (*dev).netdev_ops = core::ptr::addr_of!(WG_NETDEV_OPS);
        (*dev).needs_free_netdev = true;
    }

    // SAFETY:
    // dev meets wg_priv's # Safety contract because it is a validly allocated net_device
    // and it comes from LINK_OPS.
    // priv_ptr has room for a whole WgDevice because the private area is priv_size bytes,
    // and priv_size is size_of::<WgDevice>()
    // The pointer is aligned well enough because ____cacheline_aligned on priv guarantees the
    // alignment.
    // The const assertion checks that WgDevice needs no more than that
    // We can use ptr::write because no old value should be dropped. And nothing can race,
    // because the device isn't registered yet.
    unsafe {
        let priv_ptr = wg_priv(dev);
        core::ptr::write(
            priv_ptr,
            WgDevice {
                tx_dropped: AtomicU64::new(0),
            },
        );
    }
}

/// # Safety
///
/// dev points to a valid allocated net_device created through LINK_OPS
/// skb points to a validly allocated sk_buff and it is owned by this function
unsafe extern "C" fn wg_xmit(
    skb: *mut bindings::sk_buff,
    dev: *mut bindings::net_device,
) -> bindings::netdev_tx_t {
    pr_info!("wg_xmit called\n");

    // SAFETY: dev has been created through LINK_OPS because wg_xmit is only accessible through
    // WG_NETDEV_OPS, and only wg_setup (called by LINK_OPS), installs this table on dev.
    // And dev is valid, guaranteed by # Safety of wg_xmit.
    // We can use "&*" because :
    // - wg_setup wrote the WgDevice before it was registered, and wg_xmit can only be called after
    // the interface was registered and up.
    // - The shared access is valid because all the concurrent accesses are through AtomicU64
    // - The Kernel doesn't free net_device while wg_xmit is executing
    let wg_dev = unsafe { &*wg_priv(dev) };

    // SAFETY: "skb" is valid and owned by this function per the "# Safety" contract,
    // and "dev_kfree_skb_any_reason" is safe to call from any execution context.
    unsafe {
        bindings::dev_kfree_skb_any_reason(
            skb,
            bindings::skb_drop_reason_SKB_DROP_REASON_NOT_SPECIFIED,
        );
    }

    let tx_dropped_value = wg_dev.tx_dropped.fetch_add(1, Ordering::Relaxed);
    pr_info!(
        "The number of dropped packets is: {}\n",
        tx_dropped_value + 1
    );

    bindings::netdev_tx_NETDEV_TX_OK
}

/// Per-device state of a wireguard_rs interface, it lives in the net_device private area
/// and it can be reached through priv_.
struct WgDevice {
    /// It counts packets dropped in wg_xmit
    tx_dropped: AtomicU64,
}

/// This function returns the private-area pointer of a wireguard_rs device
///
/// The returned pointer only points to a valid WgDevice after wg_setup has written one.
///
/// # Safety
///
/// dev must have been created through LINK_OPS so it has been allocated with at least
/// "size_of::<WgDevice>()" bytes of private data because it is the value of
/// LINK_OPS.priv_size.
/// dev must be a valid, non-null pointer to an allocated bindings::net_device.
unsafe fn wg_priv(dev: *mut bindings::net_device) -> *mut WgDevice {
    // SAFETY: The caller guarantees dev is valid and has priv_ space for WgDevice.
    // Using addr_of_mut! avoids creating an intermediate &mut reference to net_device.
    unsafe { core::ptr::addr_of_mut!((*dev).priv_).cast::<WgDevice>() }
}

// We use this assertion because the private area is only guaranteed cache_line aligned
const _: () = assert!(core::mem::align_of::<WgDevice>() <= bindings::SMP_CACHE_BYTES as usize);

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
            priv_size: core::mem::size_of::<WgDevice>(),
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
