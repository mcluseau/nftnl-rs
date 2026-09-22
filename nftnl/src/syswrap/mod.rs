//! Thin, internal wrappers around the raw `nftnl_sys` FFI.
//!
//! These wrappers own the C objects (RAII), translate the `u32` attribute
//! constants into the `u16` the C API expects, and turn C return codes into
//! [`Error`]. They contain no nftables domain logic; the high-level types in
//! this crate (`set`, `table`, `chain`, `rule`, `expr`, ...) build on top.
//!
//! The C library does not set `errno` for the failures these setters report
//! (they only fail on allocation/validation), so a dedicated [`Error`] is used
//! instead of [`std::io::Error`].

// This layer mirrors the C API and is grown incrementally as more of it is
// needed; not every wrapper method is called yet.
#![allow(dead_code)]

use core::fmt;

mod nlmsg;
mod set;
mod set_elem;

pub(crate) use nlmsg::NlMsgHdr;
#[cfg(test)]
pub(crate) use nlmsg::SetElemListAttr;
pub(crate) use set::Set;
pub(crate) use set_elem::SetElem;

/// An error reported by a `libnftnl` setter.
///
/// `libnftnl` setters return a non-zero value on allocation or validation
/// failure and do not set `errno`, so no further detail is available.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Error(());

impl Error {
    pub(crate) const fn new() -> Self {
        Self(())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("libnftnl operation failed")
    }
}

impl std::error::Error for Error {}
