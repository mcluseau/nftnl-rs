use crate::datatype::{Data, increment_be};
use crate::syswrap::{NlMsgHdr, Set as SysSet, SetElem};
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
    set: SysSet,
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
        let mut set = SysSet::new();

        set.set_family(family as u32);
        set.set_table(table.get_name()).expect("setting set table");
        set.set_name(name).expect("setting set name");
        set.set_id(id);

        if flags != 0 {
            set.set_flags(flags);
        }
        set.set_key_type(K::TYPE);
        set.set_key_len(K::LEN);

        if let Some(data_type) = Kind::data_type() {
            set.set_data_type(data_type);
        }
        if let Some(data_len) = Kind::data_len() {
            set.set_data_len(data_len);
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

        self.set.set_flags(self.set.flags() | NFT_SET_CONCAT);
        self.set
            .set_desc_concat(&desc)
            .expect("setting set concat descriptor");
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
        // `syswrap::Set` is never null.
        ptr::NonNull::new(self.set.as_ptr()).expect("set pointer is non-null")
    }

    pub fn get_family(&self) -> ProtoFamily {
        self.family
    }

    pub fn get_name(&self) -> &CStr {
        self.set.name().expect("set has a name")
    }

    pub fn get_id(&self) -> u32 {
        self.set.id()
    }

    /// Returns a message that flushes all elements from this set.
    pub fn flush(&self) -> FlushSet<'_, K, Kind> {
        FlushSet { set: self }
    }

    fn add_element(&mut self, key_data: &[u8], write_data: impl FnOnce(&mut SetElem)) {
        let mut elem = SetElem::new();
        elem.set_key(key_data).expect("setting element key");
        write_data(&mut elem);
        self.set.elem_add(elem);
    }

    fn add_end(&mut self, key_data: &[u8]) {
        let mut elem = SetElem::new();
        elem.set_key(key_data).expect("setting element key");
        elem.set_flags(libc::NFT_SET_ELEM_INTERVAL_END as u32);
        self.set.elem_add(elem);
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
        self.add_element(&key_data, |elem| data.write_elem(elem.as_ptr()));
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
        self.add_element(&from, |elem| data.write_elem(elem.as_ptr()));
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
        let header = NlMsgHdr::<()>::build(
            buf.cast::<c_char>(),
            type_ as u16,
            self.table.get_family() as u16,
            (libc::NLM_F_APPEND | libc::NLM_F_CREATE | libc::NLM_F_ACK) as u16,
            seq,
        );
        self.set.nlmsg_build_payload(header.as_ptr());
    }
}

// -- iterator ----------------------------------------------------------------

/// Iterates the elements of a set, yielding one [`SetElemsMsg`] per netlink
/// message needed to carry all elements.
///
/// The packing is done here in Rust rather than through libnftnl's
/// `nftnl_set_elems_nlmsg_build_payload_iter` because that function rewinds only
/// a single element on 16-bit attribute overflow, which can tear an interval
/// (`start`, `INTERVAL_END`) pair across two messages. The kernel then rejects
/// the transaction. The loop below mirrors what `nft` does: an overflowing
/// interval pair is rewound as a unit, so both endpoints always travel together.
pub struct SetElemsIter<'a, K, Kind: SetKind> {
    set: &'a Set<'a, K, Kind>,
    elems: Rc<Vec<SetElem>>,
    next: Rc<Cell<usize>>,
    ret: Rc<Cell<i32>>,
}

impl<'a, K, Kind> SetElemsIter<'a, K, Kind>
where
    Kind: SetKind,
{
    fn new(set: &'a Set<'a, K, Kind>) -> Self {
        SetElemsIter {
            set,
            elems: Rc::new(set.set.elems()),
            next: Rc::new(Cell::new(0)),
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
        if self.ret.get() <= 0 || self.next.get() >= self.elems.len() {
            trace!("SetElemsIter iterator ending");
            None
        } else {
            trace!("SetElemsIter returning new SetElemsMsg");
            Some(SetElemsMsg {
                set: self.set,
                elems: self.elems.clone(),
                next: self.next.clone(),
                ret: self.ret.clone(),
            })
        }
    }
}

pub struct SetElemsMsg<'a, K, Kind: SetKind> {
    set: &'a Set<'a, K, Kind>,
    elems: Rc<Vec<SetElem>>,
    next: Rc<Cell<usize>>,
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
        let mut nlh = NlMsgHdr::build(
            buf.cast::<c_char>(),
            type_ as u16,
            self.set.get_family() as u16,
            flags as u16,
            seq,
        );

        let set = &self.set.set;
        if let Some(name) = set.name() {
            nlh.set_name(name);
        }
        if set.is_set(sys::NFTNL_SET_ID as u16) {
            nlh.set_id(set.id());
        }
        if let Some(table) = set.table() {
            nlh.set_table(table);
        }

        let mut idx = self.next.get();
        let len = self.elems.len();
        if idx >= len {
            self.ret.set(0);
            return;
        }

        let mut overflow = false;

        let mut elements = nlh.start_elements();

        // Length of the last element committed to this message, so an
        // interval-end overflow can also undo its interval-start sibling.
        let mut prev_len: Option<u16> = None;

        while idx < len {
            let elem = &self.elems[idx];
            let is_interval_end = elem.is_interval_end();

            let elem_len = elements.push(elem);

            if elements.len_so_far() > u16::MAX as usize {
                // The `NFTA_SET_ELEM_LIST_ELEMENTS` nest is a 16-bit length
                // attribute. Undo the element that did not fit.
                elements.shrink(elem_len as u32);
                if is_interval_end {
                    // Its interval-start sibling was already written into
                    // this same message; rewind that too so the pair is
                    // emitted together in the next message.
                    if let Some(plen) = prev_len {
                        elements.shrink(plen as u32);
                        idx -= 1;
                    }
                }
                overflow = true;
                break;
            }

            prev_len = (!is_interval_end).then_some(elem_len);
            idx += 1;
        }

        elements.end();

        self.next.set(idx);
        self.ret.set(overflow as i32);
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
        let header = NlMsgHdr::<()>::build(
            buf.cast::<c_char>(),
            libc::NFT_MSG_DELSETELEM as u16,
            self.set.get_family() as u16,
            libc::NLM_F_ACK as u16,
            seq,
        );
        self.set.set.elems_nlmsg_build_payload(header.as_ptr());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::syswrap::SetElemListAttr;
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

    /// Parses one NEWSETELEM message and asserts that every interval start is
    /// immediately followed by its `INTERVAL_END` sibling within the same
    /// message, and that no message ends on a dangling start.
    fn assert_interval_pairs_intact(msg: &[u8]) {
        const NLMSG_HDRLEN: usize = 16;
        // `nftnl_nlmsg_build_hdr` prepends an `nfgenmsg` (family, version, res_id).
        const NFGENMSG_LEN: usize = 4;
        const NLA_HDRLEN: usize = 4;
        const NLA_TYPE_MASK: u16 = 0x3fff;

        fn nla_type(attr: *const libc::nlattr) -> u16 {
            (unsafe { (*attr).nla_type }) & NLA_TYPE_MASK
        }
        fn nla_len(attr: *const libc::nlattr) -> usize {
            (unsafe { (*attr).nla_len }) as usize
        }
        fn attrs(buf: &[u8]) -> Vec<(*const libc::nlattr, usize)> {
            let mut out = Vec::new();
            let mut off = 0usize;
            while off + NLA_HDRLEN <= buf.len() {
                let attr = buf[off..].as_ptr().cast::<libc::nlattr>();
                let len = nla_len(attr);
                if len < NLA_HDRLEN || off + len > buf.len() {
                    break;
                }
                out.push((attr, off));
                off += (len + 3) & !3;
            }
            out
        }

        // Locate NFTA_SET_ELEM_LIST_ELEMENTS.
        let payload = &msg[NLMSG_HDRLEN + NFGENMSG_LEN..];
        let elements = attrs(payload)
            .into_iter()
            .find(|&(attr, _)| nla_type(attr) == SetElemListAttr::Elements as u16)
            .map(|(attr, off)| &payload[off + NLA_HDRLEN..off + nla_len(attr)])
            .expect("NFTA_SET_ELEM_LIST_ELEMENTS present");

        let mut pending_start = false;
        for (elem_attr, off) in attrs(elements) {
            let elem_body = &elements[off + NLA_HDRLEN..off + nla_len(elem_attr)];

            let is_end = attrs(elem_body)
                .into_iter()
                .find(|&(attr, _)| nla_type(attr) == 3)
                .map(|(attr, aoff)| {
                    u32::from_be_bytes(
                        elem_body[aoff + NLA_HDRLEN..aoff + nla_len(attr)]
                            .try_into()
                            .expect("flags attribute is 4 bytes"),
                    )
                })
                .map(|flags| flags & libc::NFT_SET_ELEM_INTERVAL_END as u32 != 0)
                .unwrap_or(false);

            if is_end {
                assert!(
                    pending_start,
                    "interval-end element without its start in the same message"
                );
                pending_start = false;
            } else {
                assert!(
                    !pending_start,
                    "interval-start not immediately followed by its end in the same message"
                );
                pending_start = true;
            }
        }
        assert!(
            !pending_start,
            "message ends with an interval-start whose end is in another message"
        );
    }

    #[test]
    fn interval_pairs_are_never_split_across_messages() {
        use crate::NlMsg;

        let table = Table::new(c"filter", ProtoFamily::Ipv4);
        let mut set = IntervalSet::<Ipv4Addr>::new(c"test", 1, &table, ProtoFamily::Ipv4);

        // Enough ranges that the 16-bit NFTA_SET_ELEM_LIST_ELEMENTS nest must be
        // split across several NEWSETELEM messages.
        for i in 0..4000u32 {
            let base = i << 8;
            set.add(&Ipv4Addr::from(base), &Ipv4Addr::from(base | 0x7f));
        }

        let mut messages = 0usize;
        for msg in set.elems_iter() {
            let mut buf = vec![0u8; crate::nft_nlmsg_maxsize() as usize];
            unsafe {
                msg.write(buf.as_mut_ptr().cast(), 1, MsgType::Add);
            }
            let nlh = unsafe { &*buf.as_ptr().cast::<libc::nlmsghdr>() };
            let len = nlh.nlmsg_len as usize;
            assert!(len >= 16 && len <= buf.len());
            assert_interval_pairs_intact(&buf[..len]);
            messages += 1;
        }

        assert!(
            messages >= 2,
            "expected the set to span multiple NEWSETELEM messages, got {messages}"
        );
    }
}

