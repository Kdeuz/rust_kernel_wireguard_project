// SPDX-License-Identifier: GPL-2.0
//! Wireguard Rust experimental kernel module.
use kernel::prelude::*;
use kernel::{bindings, types::Opaque};

module! {
    type: WireguardRs,
    name: "wireguard_rs",
    authors: ["Angel"],
    description: "Rust wireguard_rs",
    license: "GPL",
}

struct WireguardRs {
    messageins: &'static str,
    messagerm: &'static str,
}

impl kernel::Module for WireguardRs {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        let messageins = "Hello World.";
        let messagerm = "Bye.";

        pr_info!("{}\n", messageins);

        Ok(WireguardRs { messageins, messagerm })
    } 
}

impl Drop for WireguardRs {
    fn drop(&mut self) {
        pr_info!("{}\n", self.messagerm);
    }
}


/// # Safety dev points to a valid, freshly allocated net_device
unsafe extern "C" fn wg_setup(_dev: *mut bindings::net_device) {
    pub const test: Opaque<u32> = Opaque::zeroed();
    pr_info!("wg_setup called\n");
}

