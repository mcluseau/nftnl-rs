use crate::datatype::{Data, increment_be};
use crate::{MsgType, ProtoFamily, table::Table};
use kind::SetKind;
use nftnl_sys::{self as sys, libc};
use std::{
    cell::Cell,
    ffi::{CStr, c_void},
    os::raw::c_char,
    ptr,
    rc::Rc,
};

const NFT_SET_CONCAT: u32 = 0x80;

pub mod kind;

/// A map: each key maps to a data value `D`.
pub type Map<'a, K, D> = Set<'a, K, kind::SimpleMap<D>>;
/// A set whose keys are contiguous ranges of values.
pub type IntervalSet<'a, K> = Set<'a, K, kind::IntervalSet>;
/// A map whose keys are contiguous ranges of values.
pub type IntervalMap<'a, K, D> = Set<'a, K, kind::IntervalMap<D>>;

#[macro_export]
macro_rules! nft_set {
    ($name:expr, $id:expr, $table:expr, $family:expr) => {
        $crate::set::Set::new($name, $id, $table, $family)
    };
    ($name:expr, $id:expr, $table:expr, $family:expr; [ ]) => {
        nft_set!($name, $id, $table, $family)
    };
    ($name:expr, $id:expr, $table:expr, $family:expr; [ $($value:expr,)* ]) => {{
        let mut set = nft_set!($name, $id, $table, $family);
        $(
            set.add($value);
        )*
        set
    }};
}

#[macro_export]
macro_rules! nft_map {
    ($name:expr, $id:expr, $table:expr, $family:expr) => {
        $crate::set::Map::<_, _>::new($name, $id, $table, $family)
    };
    ($name:expr, $id:expr, $table:expr, $family:expr; [ ]) => {
        nft_map!($name, $id, $table, $family)
    };
    ($name:expr, $id:expr, $table:expr, $family:expr; [ $($key:expr => $data:expr,)* ]) => {{
        let mut map = nft_map!($name, $id, $table, $family);
        $(
            map.add($key, $data);
        )*
        map
    }};
}

/// A collection of keys (or ranges of keys, or key/data pairs) stored in a table.
///
/// The `Kind` type parameter selects the shape of the set, defaulting to
/// [`kind::SimpleSet`]:
///
/// - [`kind::SimpleSet`]: a set of single keys (`add(&K)`).
/// - [`kind::IntervalSet`]: a set of contiguous ranges (`add(&K, &K)`).
/// - [`kind::SimpleMap`]: a map of keys to data (`add(&K, &D)`).
/// - [`kind::IntervalMap`]: a map of ranges of keys to data (`add(&K, &K, &D)`).
pub struct Set<'a, K, Kind: SetKind = kind::SimpleSet> {
    set: ptr::NonNull<sys::nftnl_set>,
    table: &'a Table,
    family: ProtoFamily,
    _marker: ::std::marker::PhantomData<(K, Kind)>,
}

impl<'a, K, Kind> Set<'a, K, Kind>
where
    K: Data,
    Kind: SetKind,
{
    /// Creates a named set of the given kind, with the default flags for that
    /// kind (`CONSTANT | ANONYMOUS` plus the kind's structural flags).
    pub fn new(name: &CStr, id: u32, table: &'a Table, family: ProtoFamily) -> Self {
        Self::new_with_flags(
            name,
            id,
            table,
            family,
            Kind::set_flags() | (libc::NFT_SET_ANONYMOUS | libc::NFT_SET_CONSTANT) as u32,
        )
    }

    /// Creates a named set that remains in the table independently of any rule,
    /// and may be updated later (no `ANONYMOUS` or `CONSTANT` flag).
    pub fn new_named(name: &CStr, id: u32, table: &'a Table, family: ProtoFamily) -> Self {
        Self::new_with_flags(name, id, table, family, Kind::set_flags())
    }

    fn new_with_flags(
        name: &CStr,
        id: u32,
        table: &'a Table,
        family: ProtoFamily,
        flags: u32,
    ) -> Self {
        let set = try_alloc!(unsafe { sys::nftnl_set_alloc() });

        unsafe {
            let set = set.as_ptr();
            sys::nftnl_set_set_u32(set, sys::NFTNL_SET_FAMILY as u16, family as u32);
            sys::nftnl_set_set_str(set, sys::NFTNL_SET_TABLE as u16, table.get_name().as_ptr());
            sys::nftnl_set_set_str(set, sys::NFTNL_SET_NAME as u16, name.as_ptr());
            sys::nftnl_set_set_u32(set, sys::NFTNL_SET_ID as u16, id);

            if flags != 0 {
                sys::nftnl_set_set_u32(set, sys::NFTNL_SET_FLAGS as u16, flags);
            }
            sys::nftnl_set_set_u32(set, sys::NFTNL_SET_KEY_TYPE as u16, K::TYPE);
            sys::nftnl_set_set_u32(set, sys::NFTNL_SET_KEY_LEN as u16, K::LEN);

            if let Some(data_type) = Kind::data_type() {
                sys::nftnl_set_set_u32(set, sys::NFTNL_SET_DATA_TYPE as u16, data_type);
            }
            if let Some(data_len) = Kind::data_len() {
                sys::nftnl_set_set_u32(set, sys::NFTNL_SET_DATA_LEN as u16, data_len);
            }
        }

        let mut s = Self {
            set,
            table,
            family,
            _marker: ::std::marker::PhantomData,
        };

        let key_bytes = K::concat_bytes();
        if !key_bytes.is_empty() {
            s.set_concat(&key_bytes);
        }

        s
    }

    fn set_concat(&mut self, field_lengths: &[u32]) {
        let mut desc = Vec::with_capacity(field_lengths.len());
        for &len in field_lengths {
            desc.push(len as u8);
        }

        unsafe {
            let set = self.set.as_ptr();
            let flags = sys::nftnl_set_get_u32(set, sys::NFTNL_SET_FLAGS as u16);
            sys::nftnl_set_set_u32(set, sys::NFTNL_SET_FLAGS as u16, flags | NFT_SET_CONCAT);

            sys::nftnl_set_set_data(
                set,
                sys::NFTNL_SET_DESC_CONCAT as u16,
                desc.as_ptr() as *const c_void,
                desc.len() as u32,
            );
        }
    }
}

impl<'a, K, Kind> Set<'a, K, Kind>
where
    Kind: SetKind,
{
    /// Returns the netlink messages for the elements previously added to this set.
    pub fn elems_iter(&'a self) -> SetElemsIter<'a, K, Kind> {
        SetElemsIter::new(self)
    }

    pub fn as_ptr(&self) -> ptr::NonNull<sys::nftnl_set> {
        self.set
    }

    pub fn get_family(&self) -> ProtoFamily {
        self.family
    }

    pub fn get_name(&self) -> &CStr {
        unsafe {
            let ptr = sys::nftnl_set_get_str(self.set.as_ptr(), sys::NFTNL_SET_NAME as u16);
            CStr::from_ptr(ptr)
        }
    }

    pub fn get_id(&self) -> u32 {
        unsafe { sys::nftnl_set_get_u32(self.set.as_ptr(), sys::NFTNL_SET_ID as u16) }
    }

    /// Returns a message that flushes all elements from this set.
    pub fn flush(&self) -> FlushSet<'_, K, Kind> {
        FlushSet { set: self }
    }

    fn add_element(&mut self, key_data: &[u8], write_data: impl FnOnce(*mut sys::nftnl_set_elem)) {
        unsafe {
            let elem = try_alloc!(sys::nftnl_set_elem_alloc());

            sys::nftnl_set_elem_set(
                elem.as_ptr(),
                sys::NFTNL_SET_ELEM_KEY as u16,
                key_data.as_ptr() as *const c_void,
                key_data.len() as u32,
            );

            write_data(elem.as_ptr());
            sys::nftnl_set_elem_add(self.set.as_ptr(), elem.as_ptr());
        }
    }

    fn add_end(&mut self, key_data: &[u8]) {
        unsafe {
            let elem = try_alloc!(sys::nftnl_set_elem_alloc());

            sys::nftnl_set_elem_set(
                elem.as_ptr(),
                sys::NFTNL_SET_ELEM_KEY as u16,
                key_data.as_ptr() as *const c_void,
                key_data.len() as u32,
            );

            sys::nftnl_set_elem_set_u32(
                elem.as_ptr(),
                sys::NFTNL_SET_ELEM_FLAGS as u16,
                libc::NFT_SET_ELEM_INTERVAL_END as u32,
            );

            sys::nftnl_set_elem_add(self.set.as_ptr(), elem.as_ptr());
        }
    }
}

// -- add: one impl per kind, each with its own arity -------------------------

impl<'a, K> Set<'a, K, kind::SimpleSet>
where
    K: Data,
{
    /// Adds a single key to the set.
    pub fn add(&mut self, key: &K) {
        let key_data = key.data();
        self.add_element(&key_data, |_| {});
    }
}

impl<'a, K> Set<'a, K, kind::IntervalSet>
where
    K: Data,
{
    /// Adds an inclusive range `[from, to]` to the set.
    pub fn add(&mut self, from: &K, to: &K) {
        let from = from.data();
        let to = to.data();
        self.add_element(&from, |_| {});
        if let Some(next) = increment_be(&to) {
            self.add_end(&next);
        }
    }

    /// Adds an exact match to the set.
    pub fn add_exact(&mut self, key: &K) {
        self.add(key, key)
    }
}

impl<'a, K, D> Set<'a, K, kind::SimpleMap<D>>
where
    K: Data,
    D: Data,
{
    /// Adds a key mapping to `data`.
    pub fn add(&mut self, key: &K, data: &D) {
        let key_data = key.data();
        self.add_element(&key_data, |elem| data.write_elem(elem));
    }
}

impl<'a, K, D> Set<'a, K, kind::IntervalMap<D>>
where
    K: Data,
    D: Data,
{
    /// Adds an inclusive range `[from, to]`, every key in it mapping to `data`.
    pub fn add(&mut self, from: &K, to: &K, data: &D) {
        let from = from.data();
        let to = to.data();
        self.add_element(&from, |elem| data.write_elem(elem));
        if let Some(next) = increment_be(&to) {
            self.add_end(&next);
        }
    }

    /// Adds an exact match mapping to `data`.
    pub fn add_exact(&mut self, key: &K, data: &D) {
        self.add(key, key, data)
    }
}

unsafe impl<K, Kind> crate::NlMsg for Set<'_, K, Kind>
where
    Kind: SetKind,
{
    unsafe fn write(&self, buf: *mut c_void, seq: u32, msg_type: MsgType) {
        let type_ = match msg_type {
            MsgType::Add => libc::NFT_MSG_NEWSET,
            MsgType::Del => libc::NFT_MSG_DELSET,
        };
        let header = unsafe {
            sys::nftnl_nlmsg_build_hdr(
                buf.cast::<c_char>(),
                type_ as u16,
                self.table.get_family() as u16,
                (libc::NLM_F_APPEND | libc::NLM_F_CREATE | libc::NLM_F_ACK) as u16,
                seq,
            )
        };
        unsafe { sys::nftnl_set_nlmsg_build_payload(header, self.set.as_ptr()) };
    }
}

impl<K, Kind> Drop for Set<'_, K, Kind>
where
    Kind: SetKind,
{
    fn drop(&mut self) {
        unsafe { sys::nftnl_set_free(self.set.as_ptr()) };
    }
}

// -- iterator ----------------------------------------------------------------

pub struct SetElemsIter<'a, K, Kind: SetKind> {
    set: &'a Set<'a, K, Kind>,
    iter: ptr::NonNull<sys::nftnl_set_elems_iter>,
    ret: Rc<Cell<i32>>,
}

impl<'a, K, Kind> SetElemsIter<'a, K, Kind>
where
    Kind: SetKind,
{
    fn new(set: &'a Set<'a, K, Kind>) -> Self {
        let iter = try_alloc!(unsafe { sys::nftnl_set_elems_iter_create(set.set.as_ptr()) });
        SetElemsIter {
            set,
            iter,
            ret: Rc::new(Cell::new(1)),
        }
    }
}

impl<'a, K, Kind> Iterator for SetElemsIter<'a, K, Kind>
where
    K: 'a,
    Kind: SetKind,
{
    type Item = SetElemsMsg<'a, K, Kind>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.ret.get() <= 0
            || unsafe { sys::nftnl_set_elems_iter_cur(self.iter.as_ptr()).is_null() }
        {
            trace!("SetElemsIter iterator ending");
            None
        } else {
            trace!("SetElemsIter returning new SetElemsMsg");
            Some(SetElemsMsg {
                set: self.set,
                iter: self.iter.as_ptr(),
                ret: self.ret.clone(),
            })
        }
    }
}

impl<K, Kind> Drop for SetElemsIter<'_, K, Kind>
where
    Kind: SetKind,
{
    fn drop(&mut self) {
        unsafe { sys::nftnl_set_elems_iter_destroy(self.iter.as_ptr()) };
    }
}

pub struct SetElemsMsg<'a, K, Kind: SetKind> {
    set: &'a Set<'a, K, Kind>,
    iter: *mut sys::nftnl_set_elems_iter,
    ret: Rc<Cell<i32>>,
}

unsafe impl<K, Kind> crate::NlMsg for SetElemsMsg<'_, K, Kind>
where
    Kind: SetKind,
{
    unsafe fn write(&self, buf: *mut c_void, seq: u32, msg_type: MsgType) {
        trace!("Writing SetElemsMsg to NlMsg");
        let (type_, flags) = match msg_type {
            MsgType::Add => (
                libc::NFT_MSG_NEWSETELEM,
                libc::NLM_F_CREATE | libc::NLM_F_EXCL | libc::NLM_F_ACK,
            ),
            MsgType::Del => (libc::NFT_MSG_DELSETELEM, libc::NLM_F_ACK),
        };
        let header = unsafe {
            sys::nftnl_nlmsg_build_hdr(
                buf.cast::<c_char>(),
                type_ as u16,
                self.set.get_family() as u16,
                flags as u16,
                seq,
            )
        };
        self.ret
            .set(unsafe { sys::nftnl_set_elems_nlmsg_build_payload_iter(header, self.iter) });
    }
}

// -- flush -------------------------------------------------------------------

/// A netlink message that flushes all elements from a set.
pub struct FlushSet<'a, K, Kind: SetKind> {
    set: &'a Set<'a, K, Kind>,
}

unsafe impl<K, Kind> crate::NlMsg for FlushSet<'_, K, Kind>
where
    Kind: SetKind,
{
    unsafe fn write(&self, buf: *mut c_void, seq: u32, _msg_type: MsgType) {
        trace!("Writing FlushSet to NlMsg");
        let header = unsafe {
            sys::nftnl_nlmsg_build_hdr(
                buf.cast::<c_char>(),
                libc::NFT_MSG_DELSETELEM as u16,
                self.set.get_family() as u16,
                libc::NLM_F_ACK as u16,
                seq,
            )
        };
        unsafe {
            sys::nftnl_set_elems_nlmsg_build_payload(header, self.set.set.as_ptr());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn simple_set_flags_are_anonymous_constant() {
        let table = Table::new(c"filter", ProtoFamily::Ipv4);
        let set = Set::<Ipv4Addr>::new(c"test", 1, &table, ProtoFamily::Ipv4);

        assert_eq!(
            flags(&set),
            Some((libc::NFT_SET_ANONYMOUS | libc::NFT_SET_CONSTANT) as u32)
        );
    }

    #[test]
    fn name_is_copied_and_not_retained() {
        use std::ffi::CString;

        let table = Table::new(c"filter", ProtoFamily::Ipv4);

        let (set, caller_ptr) = {
            // Build the Set from a short-lived name, then drop the CString.
            let name = CString::new("transient-name").unwrap();
            let caller_ptr = name.as_ptr();
            let set = Set::<Ipv4Addr>::new(name.as_c_str(), 1, &table, ProtoFamily::Ipv4);
            (set, caller_ptr)
        };

        // libnftnl must have copied the name; reading it back must not
        // dereference the now-dropped caller pointer.
        assert_eq!(set.get_name(), c"transient-name");
        // The stored copy must live at a different address than the dropped caller's.
        assert_ne!(set.get_name().as_ptr(), caller_ptr);
    }

    #[test]
    fn map_sets_map_flag() {
        let table = Table::new(c"filter", ProtoFamily::Ipv4);
        let map = Map::<Ipv4Addr, u16>::new(c"test", 1, &table, ProtoFamily::Ipv4);

        assert_eq!(
            flags(&map),
            Some((
                libc::NFT_SET_ANONYMOUS | libc::NFT_SET_CONSTANT | libc::NFT_SET_MAP
            ) as u32)
        );
    }

    #[test]
    fn interval_map_sets_interval_and_map_flags() {
        let table = Table::new(c"filter", ProtoFamily::Ipv4);
        let map = IntervalMap::<Ipv4Addr, u16>::new(c"test", 1, &table, ProtoFamily::Ipv4);

        assert_eq!(
            flags(&map),
            Some((
                libc::NFT_SET_ANONYMOUS
                    | libc::NFT_SET_CONSTANT
                    | libc::NFT_SET_INTERVAL
                    | libc::NFT_SET_MAP
            ) as u32)
        );
    }

    #[test]
    fn interval_set_sets_interval_flag() {
        let table = Table::new(c"filter", ProtoFamily::Ipv4);
        let set = IntervalSet::<Ipv4Addr>::new(c"test", 1, &table, ProtoFamily::Ipv4);

        assert_eq!(
            flags(&set),
            Some((
                libc::NFT_SET_ANONYMOUS | libc::NFT_SET_CONSTANT | libc::NFT_SET_INTERVAL
            ) as u32)
        );
    }

    #[test]
    fn new_named_is_mutable_and_keeps_structural_flags() {
        let table = Table::new(c"filter", ProtoFamily::Ipv4);

        // Plain set: no flags at all.
        let set = Set::<Ipv4Addr>::new_named(c"test", 1, &table, ProtoFamily::Ipv4);
        assert_eq!(flags(&set), None);

        // Interval set: keeps INTERVAL, no CONSTANT/ANONYMOUS.
        let set = IntervalSet::<Ipv4Addr>::new_named(c"test", 1, &table, ProtoFamily::Ipv4);
        let f = flags(&set).unwrap();
        assert_ne!(f & libc::NFT_SET_INTERVAL as u32, 0);
        assert_eq!(f & libc::NFT_SET_CONSTANT as u32, 0);

        // Map: keeps MAP, no CONSTANT/ANONYMOUS.
        let map = Map::<Ipv4Addr, u16>::new_named(c"test", 1, &table, ProtoFamily::Ipv4);
        let f = flags(&map).unwrap();
        assert_ne!(f & libc::NFT_SET_MAP as u32, 0);
        assert_eq!(f & libc::NFT_SET_CONSTANT as u32, 0);

        // Interval map: keeps INTERVAL|MAP, no CONSTANT/ANONYMOUS.
        let map = IntervalMap::<Ipv4Addr, u16>::new_named(c"test", 1, &table, ProtoFamily::Ipv4);
        let f = flags(&map).unwrap();
        assert_ne!(f & libc::NFT_SET_INTERVAL as u32, 0);
        assert_ne!(f & libc::NFT_SET_MAP as u32, 0);
        assert_eq!(f & libc::NFT_SET_CONSTANT as u32, 0);
    }

    #[test]
    fn simple_add_writes_single_key() {
        let table = Table::new(c"filter", ProtoFamily::Ipv4);
        let mut set = Set::<Ipv4Addr>::new(c"test", 1, &table, ProtoFamily::Ipv4);
        set.add(&Ipv4Addr::new(10, 0, 0, 5));

        let elems = collect_pelems(&set);
        assert_eq!(elems, vec![(vec![10, 0, 0, 5], None, None)]);
    }

    #[test]
    fn interval_add_writes_start_and_end() {
        let table = Table::new(c"filter", ProtoFamily::Ipv4);
        let mut set = IntervalSet::<Ipv4Addr>::new(c"test", 1, &table, ProtoFamily::Ipv4);
        set.add(&Ipv4Addr::new(10, 0, 0, 0), &Ipv4Addr::new(10, 0, 0, 15));

        let elems = collect_pelems(&set);
        assert_eq!(
            elems,
            vec![
                (vec![10, 0, 0, 0], None, None),
                (vec![10, 0, 0, 16], None, Some(libc::NFT_SET_ELEM_INTERVAL_END as u32)),
            ]
        );
    }

    #[test]
    fn interval_add_emits_only_start_on_max() {
        let table = Table::new(c"filter", ProtoFamily::Ipv4);
        let mut set = IntervalSet::<Ipv4Addr>::new(c"test", 1, &table, ProtoFamily::Ipv4);
        set.add(
            &Ipv4Addr::new(0, 0, 0, 0),
            &Ipv4Addr::new(255, 255, 255, 255),
        );

        let elems = collect_pelems(&set);
        assert_eq!(elems, vec![(vec![0, 0, 0, 0], None, None)]);
    }

    #[test]
    fn map_add_writes_key_with_data() {
        let table = Table::new(c"filter", ProtoFamily::Ipv4);
        let mut map = Map::<Ipv4Addr, u16>::new(c"test", 1, &table, ProtoFamily::Ipv4);
        map.add(&Ipv4Addr::new(10, 0, 0, 5), &8080u16);

        let elems = collect_pelems(&map);
        assert_eq!(
            elems,
            vec![(vec![10, 0, 0, 5], Some(8080u16.to_be_bytes().to_vec()), None)]
        );
    }

    #[test]
    fn interval_map_add_writes_start_with_data_and_end() {
        let table = Table::new(c"filter", ProtoFamily::Ipv4);
        let mut map = IntervalMap::<Ipv4Addr, u16>::new(c"test", 1, &table, ProtoFamily::Ipv4);
        map.add(
            &Ipv4Addr::new(10, 0, 0, 0),
            &Ipv4Addr::new(10, 0, 0, 15),
            &8080u16,
        );

        let elems = collect_pelems(&map);
        assert_eq!(
            elems,
            vec![
                (vec![10, 0, 0, 0], Some(8080u16.to_be_bytes().to_vec()), None),
                (vec![10, 0, 0, 16], None, Some(libc::NFT_SET_ELEM_INTERVAL_END as u32)),
            ]
        );
    }

    #[test]
    fn flush_writes_delsetelem_message() {
        use crate::NlMsg;

        let table = Table::new(c"filter", ProtoFamily::Ipv4);
        let set = Set::<Ipv4Addr>::new_named(c"test_set", 1, &table, ProtoFamily::Ipv4);
        let flush = set.flush();

        let mut buf = vec![0u8; crate::nft_nlmsg_maxsize() as usize];
        unsafe {
            flush.write(buf.as_mut_ptr().cast(), 1, MsgType::Del);
        }

        let header = buf.as_ptr().cast::<libc::nlmsghdr>();
        let nlmsg_type = unsafe { (*header).nlmsg_type };
        let expected_type =
            ((libc::NFNL_SUBSYS_NFTABLES as u16) << 8) | (libc::NFT_MSG_DELSETELEM as u16);
        assert_eq!(nlmsg_type, expected_type);
    }

    fn flags<K, Kind>(set: &Set<'_, K, Kind>) -> Option<u32>
    where
        Kind: SetKind,
    {
        unsafe {
            sys::nftnl_set_is_set(set.as_ptr().as_ptr(), sys::NFTNL_SET_FLAGS as u16)
                .then(|| sys::nftnl_set_get_u32(set.as_ptr().as_ptr(), sys::NFTNL_SET_FLAGS as u16))
        }
    }

    type PElem = (Vec<u8>, Option<Vec<u8>>, Option<u32>);

    fn collect_pelems<K, Kind>(set: &Set<'_, K, Kind>) -> Vec<PElem>
    where
        Kind: SetKind,
    {
        let mut out = Vec::new();
        unsafe {
            sys::nftnl_set_elem_foreach(
                set.as_ptr().as_ptr(),
                Some(collect_pelems_cb),
                (&mut out as *mut Vec<PElem>).cast(),
            );
        }
        out
    }

    unsafe extern "C" fn collect_pelems_cb(
        elem: *mut sys::nftnl_set_elem,
        data: *mut c_void,
    ) -> libc::c_int {
        unsafe {
            let out = &mut *(data as *mut Vec<PElem>);
            let mut len = 0u32;
            let key = sys::nftnl_set_elem_get(elem, sys::NFTNL_SET_ELEM_KEY as u16, &mut len);
            let key = std::slice::from_raw_parts(key.cast::<u8>(), len as usize).to_vec();

            let data_attr = {
                let mut dlen = 0u32;
                let d = sys::nftnl_set_elem_get(elem, sys::NFTNL_SET_ELEM_DATA as u16, &mut dlen);
                if d.is_null() {
                    None
                } else {
                    Some(std::slice::from_raw_parts(d.cast::<u8>(), dlen as usize).to_vec())
                }
            };

            let flag = sys::nftnl_set_elem_is_set(elem, sys::NFTNL_SET_ELEM_FLAGS as u16)
                .then(|| sys::nftnl_set_elem_get_u32(elem, sys::NFTNL_SET_ELEM_FLAGS as u16));
            out.push((key, data_attr, flag));
        }
        1
    }
}

