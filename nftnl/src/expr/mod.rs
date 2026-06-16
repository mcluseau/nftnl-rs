//! A module with all the nftables expressions that can be added to [`Rule`]s to build up how
//! they match against packets.
//!
//! [`Rule`]: struct.Rule.html

use std::ptr;

use super::rule::Rule;
use nftnl_sys::{self as sys, libc};

/// Trait for every safe wrapper of an nftables expression.
pub trait Expression {
    /// Allocates and returns the low level `nftnl_expr` representation of this expression.
    /// The caller to this method is responsible for freeing the expression.
    fn to_expr(&self, rule: &Rule) -> ptr::NonNull<sys::nftnl_expr>;
}

/// A netfilter data register. The expressions store and read data to and from these
/// when evaluating rule statements.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[repr(i32)]
pub enum Register {
    Verdict = libc::NFT_REG_VERDICT,
    Reg1 = libc::NFT_REG_1,
    Reg2 = libc::NFT_REG_2,
    Reg3 = libc::NFT_REG_3,
    Reg4 = libc::NFT_REG_4,
    Reg32_00 = libc::NFT_REG32_00,
    Reg32_01 = libc::NFT_REG32_01,
    Reg32_02 = libc::NFT_REG32_02,
    Reg32_03 = libc::NFT_REG32_03,
    Reg32_04 = libc::NFT_REG32_04,
    Reg32_05 = libc::NFT_REG32_05,
    Reg32_06 = libc::NFT_REG32_06,
    Reg32_07 = libc::NFT_REG32_07,
    Reg32_08 = libc::NFT_REG32_08,
    Reg32_09 = libc::NFT_REG32_09,
    Reg32_10 = libc::NFT_REG32_10,
    Reg32_11 = libc::NFT_REG32_11,
    Reg32_12 = libc::NFT_REG32_12,
    Reg32_13 = libc::NFT_REG32_13,
    Reg32_14 = libc::NFT_REG32_14,
    Reg32_15 = libc::NFT_REG32_15,
}

impl Register {
    pub fn to_raw(self) -> u32 {
        self as u32
    }
}

mod bitwise;
pub use self::bitwise::*;

mod cmp;
pub use self::cmp::*;

mod counter;
pub use self::counter::*;

pub mod ct;
pub use self::ct::*;

mod immediate;
pub use self::immediate::*;

mod lookup;
pub use self::lookup::*;

mod lookup_map;
pub use self::lookup_map::*;

mod masquerade;
pub use self::masquerade::*;

mod numgen;
pub use self::numgen::*;

mod meta;
pub use self::meta::*;

mod nat;
pub use self::nat::*;

mod payload;
pub use self::payload::*;

mod tproxy;
pub use self::tproxy::*;

mod verdict;
pub use self::verdict::*;

pub mod socket;
#[cfg_attr(not(socketexpr), allow(unused_imports))]
pub use self::socket::*;

#[macro_export(local_inner_macros)]
macro_rules! nft_expr {
    (bitwise mask $mask:expr,xor $xor:expr) => {
        nft_expr_bitwise!(mask $mask, xor $xor)
    };
    (socket $key:tt level $level:expr) => {
        nft_expr_socket!(socket $key level $level)
    };
    (cmp $op:tt $data:expr) => {
        nft_expr_cmp!($op $data)
    };
    (counter) => {
        $crate::expr::Counter
    };
    (ct $key:ident set) => {
        nft_expr_ct!($key set)
    };
    (ct $key:ident) => {
        nft_expr_ct!($key)
    };
    (verdict $verdict:ident) => {
        nft_expr_verdict!($verdict)
    };
    (verdict $verdict:ident $chain:expr) => {
        nft_expr_verdict!($verdict $chain)
    };
    (lookup $set:expr) => {
        nft_expr_lookup!($set)
    };
    (lookup_map $map:expr $( , $sreg:expr )? => $dreg:expr) => {
        nft_expr_lookup_map!($map $( , $sreg )? => $dreg)
    };
    (masquerade) => {
        $crate::expr::Masquerade
    };
    (numgen random mod $modulus:expr) => {
        nft_expr_numgen!(random mod $modulus)
    };
    (numgen random mod $modulus:expr, offset $offset:expr) => {
        nft_expr_numgen!(random mod $modulus, offset $offset)
    };
    (numgen inc mod $modulus:expr) => {
        nft_expr_numgen!(inc mod $modulus)
    };
    (numgen inc mod $modulus:expr, offset $offset:expr) => {
        nft_expr_numgen!(inc mod $modulus, offset $offset)
    };
    (meta $expr:ident set) => {
        nft_expr_meta!($expr set)
    };
    (meta $expr:ident) => {
        nft_expr_meta!($expr)
    };
    (payload $proto:ident $field:ident) => {
        nft_expr_payload!($proto $field)
    };
    (payload $proto:ident $field:ident => $dreg:expr) => {
        $crate::expr::PayloadReg::new(nft_expr_payload!($proto $field)).dreg($dreg)
    };
    (payload_raw $base:ident $offset:expr, $length:expr) => {
        nft_expr_payload!($base $offset, $length)
    };
    (tproxy port $port_register:expr) => {
        $crate::expr::TProxy {
            family: None,
            addr_register: None,
            port_register: Some($port_register),
        }
    };
    (tproxy addr $addr_register:expr) => {
        $crate::expr::TProxy {
            family: None,
            addr_register: Some($addr_register),
            port_register: None,
        }
    };
    (tproxy addr $addr_register:expr, port $port_register:expr) => {
        $crate::expr::TProxy {
            family: None,
            addr_register: Some($addr_register),
            port_register: Some($port_register),
        }
    };
    (tproxy $family:expr, addr $addr_register:expr) => {
        $crate::expr::TProxy {
            family: Some($family),
            addr_register: Some($addr_register),
            port_register: None,
        }
    };
    (tproxy $family:expr, port $port_register:expr) => {
        $crate::expr::TProxy {
            family: Some($family),
            addr_register: None,
            port_register: Some($port_register),
        }
    };
    (tproxy $family:expr, addr $addr_register:expr, port $port_register:expr) => {
        $crate::expr::TProxy {
            family: Some($family),
            addr_register: Some($addr_register),
            port_register: Some($port_register),
        }
    };
    (immediate $expr:ident $value:expr) => {
        nft_expr_immediate!($expr $value)
    };
}
