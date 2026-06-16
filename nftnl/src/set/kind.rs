use crate::datatype::Data;
use nftnl_sys::libc;

/// Describes the schema of a set: which flags it carries, what happens on `add`,
/// and (for maps) the type of the data value.
///
/// `Set` is generic over its [`SetKind`], so the "shape" of the set — plain
/// set, interval (range) set, map, or interval map — is part of its type. Each
/// kind also determines how a single `add` call is spelled.
pub trait SetKind {
    /// Whether the set stores keys as contiguous intervals (ranges).
    const INTERVAL: bool;
    /// Whether the set maps each key to a data value.
    const MAP: bool;

    /// Structural nf_tables flags intrinsic to this kind (`MAP`, `INTERVAL`).
    ///
    /// This never includes `CONSTANT` or `ANONYMOUS`; those are applied by the
    /// constructors (see [`crate::set::Set::new`] and
    /// [`crate::set::Set::new_named`]).
    fn set_flags() -> u32;

    /// The data value type, if this is a map kind.
    fn data_type() -> Option<u32> {
        None
    }

    /// The data value length, if this is a map kind.
    fn data_len() -> Option<u32> {
        None
    }
}

/// A plain set of single keys (anonymous, constant).
pub struct SimpleSet;

/// A set whose keys are contiguous ranges of values (constant).
pub struct IntervalSet;

/// A map: each key maps to a data value `D` (constant).
pub struct SimpleMap<D>(::std::marker::PhantomData<D>);

/// A map whose keys are contiguous ranges of values (constant).
pub struct IntervalMap<D>(::std::marker::PhantomData<D>);

impl SetKind for SimpleSet {
    const INTERVAL: bool = false;
    const MAP: bool = false;

    fn set_flags() -> u32 {
        0
    }
}

impl SetKind for IntervalSet {
    const INTERVAL: bool = true;
    const MAP: bool = false;

    fn set_flags() -> u32 {
        libc::NFT_SET_INTERVAL as u32
    }
}

impl<D: Data> SetKind for SimpleMap<D> {
    const INTERVAL: bool = false;
    const MAP: bool = true;

    fn set_flags() -> u32 {
        libc::NFT_SET_MAP as u32
    }

    fn data_type() -> Option<u32> {
        Some(D::TYPE)
    }

    fn data_len() -> Option<u32> {
        Some(D::LEN)
    }
}

impl<D: Data> SetKind for IntervalMap<D> {
    const INTERVAL: bool = true;
    const MAP: bool = true;

    fn set_flags() -> u32 {
        (libc::NFT_SET_INTERVAL | libc::NFT_SET_MAP) as u32
    }

    fn data_type() -> Option<u32> {
        Some(D::TYPE)
    }

    fn data_len() -> Option<u32> {
        Some(D::LEN)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn set_flags_are_structural_only() {
        assert_eq!(SimpleSet::set_flags(), 0);
        assert_eq!(IntervalSet::set_flags(), libc::NFT_SET_INTERVAL as u32);
        assert_eq!(
            <SimpleMap<u16>>::set_flags(),
            libc::NFT_SET_MAP as u32
        );
        assert_eq!(
            <IntervalMap<u16>>::set_flags(),
            (libc::NFT_SET_INTERVAL | libc::NFT_SET_MAP) as u32
        );
        for flags in [
            SimpleSet::set_flags(),
            IntervalSet::set_flags(),
            <SimpleMap<u16>>::set_flags(),
            <IntervalMap<u16>>::set_flags(),
        ] {
            assert_eq!(flags & libc::NFT_SET_CONSTANT as u32, 0);
            assert_eq!(flags & libc::NFT_SET_ANONYMOUS as u32, 0);
        }
    }

    #[test]
    fn map_kinds_expose_data_schema() {
        assert_eq!(SimpleSet::data_type(), None);
        assert_eq!(<SimpleMap<u16>>::data_type(), Some(13));
        assert_eq!(<SimpleMap<u16>>::data_len(), Some(2));
        assert_eq!(<IntervalMap<Ipv4Addr>>::data_len(), Some(4));
    }
}
