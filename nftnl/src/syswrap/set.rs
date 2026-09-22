use super::{Error, SetElem};
use nftnl_sys::{self as sys, libc};
use std::ffi::CStr;
use std::ptr::NonNull;

/// Wrapper around `nftnl_set`.
///
/// Owns the underlying C object. Dropping it calls `nftnl_set_free`, which also
/// frees every element previously handed over with [`Set::elem_add`].
pub(crate) struct Set(NonNull<sys::nftnl_set>);

impl Set {
    /// Allocates a new, empty set.
    pub(crate) fn new() -> Self {
        Self(try_alloc!(unsafe { sys::nftnl_set_alloc() }))
    }

    pub(crate) fn as_ptr(&self) -> *mut sys::nftnl_set {
        self.0.as_ptr()
    }

    /// Returns whether `attr` has been set on this set.
    pub(crate) fn is_set(&self, attr: u16) -> bool {
        unsafe { sys::nftnl_set_is_set(self.0.as_ptr(), attr) }
    }

    /// Sets a `u32` attribute. Infallible in `libnftnl`.
    pub(crate) fn set_u32(&mut self, attr: u16, val: u32) {
        unsafe { sys::nftnl_set_set_u32(self.as_ptr(), attr, val) };
    }

    /// Sets a `u64` attribute. Infallible in `libnftnl`.
    pub(crate) fn set_u64(&mut self, attr: u16, val: u64) {
        unsafe { sys::nftnl_set_set_u64(self.as_ptr(), attr, val) };
    }

    /// Sets a string attribute (copied by `libnftnl`).
    pub(crate) fn set_str(&mut self, attr: u16, val: &CStr) -> Result<(), Error> {
        let rc = unsafe { sys::nftnl_set_set_str(self.as_ptr(), attr, val.as_ptr()) };
        if rc == 0 { Ok(()) } else { Err(Error::new()) }
    }

    /// Sets a raw binary attribute (copied by `libnftnl`).
    pub(crate) fn set_data(&mut self, attr: u16, data: &[u8]) -> Result<(), Error> {
        let rc = unsafe {
            sys::nftnl_set_set_data(self.as_ptr(), attr, data.as_ptr().cast(), data.len() as u32)
        };
        if rc == 0 { Ok(()) } else { Err(Error::new()) }
    }

    /// Returns a `u32` attribute. Only meaningful if [`Set::is_set`] is true.
    pub(crate) fn get_u32(&self, attr: u16) -> u32 {
        unsafe { sys::nftnl_set_get_u32(self.0.as_ptr(), attr) }
    }

    /// Returns a string attribute, or `None` if it is not set.
    pub(crate) fn get_str(&self, attr: u16) -> Option<&CStr> {
        let ptr = unsafe { sys::nftnl_set_get_str(self.0.as_ptr(), attr) };
        (!ptr.is_null()).then(|| unsafe { CStr::from_ptr(ptr) })
    }

    /// Serializes the set object into `nlh` (a `NFT_MSG_NEWSET`/`DELSET` message).
    pub(crate) fn nlmsg_build_payload(&self, nlh: *mut libc::nlmsghdr) {
        unsafe { sys::nftnl_set_nlmsg_build_payload(nlh, self.as_ptr()) };
    }

    /// Serializes all of the set's elements into `nlh` (`NFT_MSG_NEWSETELEM`).
    pub(crate) fn elems_nlmsg_build_payload(&self, nlh: *mut libc::nlmsghdr) {
        unsafe { sys::nftnl_set_elems_nlmsg_build_payload(nlh, self.as_ptr()) };
    }

    // -- typed attribute accessors ------------------------------------------

    /// Sets the protocol family.
    pub(crate) fn set_family(&mut self, family: u32) {
        self.set_u32(sys::NFTNL_SET_FAMILY as u16, family);
    }

    /// Sets the table this set belongs to.
    pub(crate) fn set_table(&mut self, table: &CStr) -> Result<(), Error> {
        self.set_str(sys::NFTNL_SET_TABLE as u16, table)
    }

    /// Sets the set name.
    pub(crate) fn set_name(&mut self, name: &CStr) -> Result<(), Error> {
        self.set_str(sys::NFTNL_SET_NAME as u16, name)
    }

    /// Sets the transaction-local set id.
    pub(crate) fn set_id(&mut self, id: u32) {
        self.set_u32(sys::NFTNL_SET_ID as u16, id);
    }

    /// Sets the set flags.
    pub(crate) fn set_flags(&mut self, flags: u32) {
        self.set_u32(sys::NFTNL_SET_FLAGS as u16, flags);
    }

    /// Sets the key type.
    pub(crate) fn set_key_type(&mut self, key_type: u32) {
        self.set_u32(sys::NFTNL_SET_KEY_TYPE as u16, key_type);
    }

    /// Sets the key length in bytes.
    pub(crate) fn set_key_len(&mut self, key_len: u32) {
        self.set_u32(sys::NFTNL_SET_KEY_LEN as u16, key_len);
    }

    /// Sets the map data type.
    pub(crate) fn set_data_type(&mut self, data_type: u32) {
        self.set_u32(sys::NFTNL_SET_DATA_TYPE as u16, data_type);
    }

    /// Sets the map data length in bytes.
    pub(crate) fn set_data_len(&mut self, data_len: u32) {
        self.set_u32(sys::NFTNL_SET_DATA_LEN as u16, data_len);
    }

    /// Sets the concatenation descriptor (per-field key lengths).
    pub(crate) fn set_desc_concat(&mut self, field_lengths: &[u8]) -> Result<(), Error> {
        self.set_data(sys::NFTNL_SET_DESC_CONCAT as u16, field_lengths)
    }

    /// Returns the set name, if set.
    pub(crate) fn name(&self) -> Option<&CStr> {
        self.get_str(sys::NFTNL_SET_NAME as u16)
    }

    /// Returns the table name, if set.
    pub(crate) fn table(&self) -> Option<&CStr> {
        self.get_str(sys::NFTNL_SET_TABLE as u16)
    }

    /// Returns the set id.
    pub(crate) fn id(&self) -> u32 {
        self.get_u32(sys::NFTNL_SET_ID as u16)
    }

    /// Returns the set flags.
    pub(crate) fn flags(&self) -> u32 {
        self.get_u32(sys::NFTNL_SET_FLAGS as u16)
    }

    /// Adds `elem` to this set, transferring ownership to the set.
    ///
    /// `libnftnl`'s `nftnl_set_free` frees every element in the set's element
    /// list, so the element must not be freed by the caller after this.
    pub(crate) fn elem_add(&mut self, elem: SetElem) {
        unsafe { sys::nftnl_set_elem_add(self.as_ptr(), elem.as_ptr()) };
        // Ownership moved into the set; `SetElem` has no `Drop`, so nothing to do.
    }

    /// Returns non-owning handles to all elements currently in the set.
    ///
    /// Iteration order is the set's internal element-list order. The returned
    /// handles borrow from this set and must not outlive it.
    pub(crate) fn elems(&self) -> Vec<SetElem> {
        let mut ptrs: Vec<NonNull<sys::nftnl_set_elem>> = Vec::new();
        unsafe {
            sys::nftnl_set_elem_foreach(
                self.as_ptr(),
                Some(collect_elem_cb),
                (&mut ptrs as *mut Vec<NonNull<sys::nftnl_set_elem>>).cast(),
            );
        }
        ptrs.into_iter().map(|ptr| unsafe { SetElem::from_ptr(ptr) }).collect()
    }
}

unsafe extern "C" fn collect_elem_cb(
    elem: *mut sys::nftnl_set_elem,
    data: *mut libc::c_void,
) -> libc::c_int {
    // SAFETY: `data` is the `Vec` pointer passed to `nftnl_set_elem_foreach`;
    // `elem` is owned by the set and valid while the set is alive.
    unsafe {
        let ptrs = &mut *(data as *mut Vec<NonNull<sys::nftnl_set_elem>>);
        if let Some(ptr) = NonNull::new(elem) {
            ptrs.push(ptr);
        }
    }
    0
}

impl Drop for Set {
    fn drop(&mut self) {
        unsafe { sys::nftnl_set_free(self.0.as_ptr()) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn u32_attributes_round_trip() {
        let mut set = Set::new();
        assert!(!set.is_set(sys::NFTNL_SET_ID as u16));

        set.set_u32(sys::NFTNL_SET_ID as u16, 42);
        assert!(set.is_set(sys::NFTNL_SET_ID as u16));
        assert_eq!(set.get_u32(sys::NFTNL_SET_ID as u16), 42);
    }

    #[test]
    fn typed_accessors_round_trip() {
        let mut set = Set::new();

        set.set_family(libc::NFPROTO_IPV4 as u32);
        set.set_id(42);
        set.set_flags(0b101);
        set.set_key_type(7);
        set.set_key_len(4);
        set.set_data_type(13);
        set.set_data_len(2);
        set.set_name(c"myset").unwrap();
        set.set_table(c"mytable").unwrap();
        set.set_desc_concat(&[4, 2]).unwrap();

        assert_eq!(set.id(), 42);
        assert_eq!(set.flags(), 0b101);
        assert_eq!(set.name().unwrap(), c"myset");
        assert_eq!(set.table().unwrap(), c"mytable");
    }

    #[test]
    fn str_attributes_are_copied() {
        let mut set = Set::new();
        let name = CString::new("transient").unwrap();
        let caller_ptr = name.as_ptr();

        set.set_str(sys::NFTNL_SET_NAME as u16, name.as_c_str())
            .unwrap();
        drop(name);

        let stored = set.get_str(sys::NFTNL_SET_NAME as u16).unwrap();
        assert_eq!(stored, c"transient");
        assert_ne!(stored.as_ptr(), caller_ptr);
    }

    #[test]
    fn get_str_returns_none_when_unset() {
        let set = Set::new();
        assert!(set.get_str(sys::NFTNL_SET_NAME as u16).is_none());
    }

    #[test]
    fn elems_round_trip_and_are_freed_with_the_set() {
        let mut set = Set::new();
        for key in [1u32, 2, 3] {
            let mut elem = SetElem::new();
            elem.set(sys::NFTNL_SET_ELEM_KEY as u16, &key.to_be_bytes())
                .unwrap();
            set.elem_add(elem);
        }
        assert_eq!(set.elems().len(), 3);
    }
}
