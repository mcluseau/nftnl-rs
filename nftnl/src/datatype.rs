use nftnl_sys as sys;
use std::{
    ffi::{c_void, CStr},
    net::{Ipv4Addr, Ipv6Addr},
};

/// Trait for types that can be used as set/map keys or map values in nftables.
pub trait Data {
    const TYPE: u32;
    const LEN: u32;

    fn data(&self) -> Box<[u8]>;

    /// Per-field byte lengths for concatenated types.
    /// Returns non-empty for tuple impls (e.g. `(Ipv4Addr, u16)` -> `[4, 2]`).
    fn concat_bytes() -> Vec<u32> {
        vec![]
    }

    /// Writes this value's payload into a set element.
    /// Override for non-standard data (e.g. verdicts use VERDICT + CHAIN attributes).
    fn write_elem(&self, elem: *mut sys::nftnl_set_elem) {
        unsafe {
            let data = self.data();
            sys::nftnl_set_elem_set(
                elem,
                sys::NFTNL_SET_ELEM_DATA as u16,
                data.as_ptr() as *const c_void,
                data.len() as u32,
            );
        }
    }
}

impl Data for Ipv4Addr {
    const TYPE: u32 = 7;
    const LEN: u32 = 4;

    fn data(&self) -> Box<[u8]> {
        self.octets().to_vec().into_boxed_slice()
    }
}

impl Data for Ipv6Addr {
    const TYPE: u32 = 8;
    const LEN: u32 = 16;

    fn data(&self) -> Box<[u8]> {
        self.octets().to_vec().into_boxed_slice()
    }
}

impl Data for u16 {
    const TYPE: u32 = 13; // TYPE_INET_SERVICE
    const LEN: u32 = 2;

    fn data(&self) -> Box<[u8]> {
        self.to_be_bytes().to_vec().into_boxed_slice()
    }
}

impl Data for u32 {
    const TYPE: u32 = 4; // TYPE_INTEGER
    const LEN: u32 = 4;

    fn data(&self) -> Box<[u8]> {
        self.to_be_bytes().to_vec().into_boxed_slice()
    }
}

/// An ethernal MAC address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacAddr(pub [u8; 6]);

impl Data for MacAddr {
    const TYPE: u32 = 2; // TYPE_ETHERADDR
    const LEN: u32 = 6;

    fn data(&self) -> Box<[u8]> {
        self.0.to_vec().into_boxed_slice()
    }
}

impl Data for u8 {
    const TYPE: u32 = 4; // TYPE_INTEGER
    const LEN: u32 = 1;

    fn data(&self) -> Box<[u8]> {
        Box::new([*self])
    }
}

impl Data for &CStr {
    const TYPE: u32 = 0; // NFT_DATA_VALUE (variable-length [u8])
    const LEN: u32 = 0; // variable-length; actual length per element

    fn data(&self) -> Box<[u8]> {
        self.to_bytes().to_vec().into_boxed_slice()
    }
}

const fn netlink_padded_len_bytes(bytes: u32) -> u32 {
    bytes.div_ceil(4) * 4
}

impl<A: Data, B: Data> Data for (A, B) {
    const TYPE: u32 = (A::TYPE << 6) | B::TYPE;
    const LEN: u32 = netlink_padded_len_bytes(A::LEN) + netlink_padded_len_bytes(B::LEN);

    fn concat_bytes() -> Vec<u32> {
        vec![A::LEN, B::LEN]
    }

    fn data(&self) -> Box<[u8]> {
        let a_padded = netlink_padded_len_bytes(A::LEN) as usize;
        let b_padded = netlink_padded_len_bytes(B::LEN) as usize;
        let mut bytes = vec![0u8; a_padded + b_padded];
        let a_data = self.0.data();
        bytes[..A::LEN as usize].copy_from_slice(&a_data);
        let b_data = self.1.data();
        bytes[a_padded..a_padded + B::LEN as usize].copy_from_slice(&b_data);
        bytes.into_boxed_slice()
    }
}
