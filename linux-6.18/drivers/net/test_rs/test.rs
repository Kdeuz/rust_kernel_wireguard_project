// SPDX-License-Identifier: GPL-2.0
//! Test Rust kernel module.
use kernel::prelude::*;

module! {
    type: Test,
    name: "test",
    authors: ["Kdeuz"],
    description: "Rust test",
    license: "GPL",
}

struct Test {
    messageins: &'static str,
    messagerm: &'static str,
}

impl kernel::Module for Test {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        let messageins = "Hello World.";
        let messagerm = "Bye.";

        pr_info!("{}\n", messageins);

        Ok(Test {
            messageins,
            messagerm,
        })
    }
}

impl Drop for Test {
    fn drop(&mut self) {
        pr_info!("{}\n", self.messagerm);
    }
}
