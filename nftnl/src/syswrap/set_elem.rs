use super::Error;
use nftnl_sys::{self as sys, libc};
use std::ffi::CStr;
use std::ptr::NonNull;

/// Wrapper around `nftnl_set_elem`.
///
/// An element created with [`SetElem::new`] is meant to be handed to
/// [`crate::syswrap::Set::elem_add`], which transfers ownership to the set.
/// `nftnl_set_free` frees all elements in its `element_list`, so this type
/// deliberately has no `Drop` impl: whoever owns the element is responsible for
/// adding it to a set (or freeing it via [`SetElem::free`]).
pub(crate) struct SetElem(NonNull<sys::nftnl_set_elem>);

impl SetElem {
    /// Allocates a new, empty set element.
    pub(crate) fn new() -> Self {
        Self(try_alloc!(unsafe { sys::nftnl_set_elem_alloc() }))
    }

    /// Wraps an existing element pointer without taking ownership.
    ///
    /// # Safety
    ///
    /// `ptr` must point to a live `nftnl_set_elem` that outlives the returned
    /// wrapper. Used to borrow elements stored in a set's element list.
    pub(crate) unsafe fn from_ptr(ptr: NonNull<sys::nftnl_set_elem>) -> Self {
        Self(ptr)
    }

    pub(crate) fn as_ptr(&self) -> *mut sys::nftnl_set_elem {
        self.0.as_ptr()
    }

    /// Sets a raw attribute. Overwrites any existing value for `attr`.
    pub(crate) fn set(&mut self, attr: u16, data: &[u8]) -> Result<(), Error> {
        let rc = unsafe {
            sys::nftnl_set_elem_set(self.as_ptr(), attr, data.as_ptr().cast(), data.len() as u32)
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(Error::new())
        }
    }

    /// Sets a `u32` attribute. Infallible in `libnftnl`.
    pub(crate) fn set_u32(&mut self, attr: u16, val: u32) {
        unsafe { sys::nftnl_set_elem_set_u32(self.as_ptr(), attr, val) };
    }

    /// Sets a string attribute.
    pub(crate) fn set_str(&mut self, attr: u16, val: &CStr) -> Result<(), Error> {
        let rc = unsafe { sys::nftnl_set_elem_set_str(self.as_ptr(), attr, val.as_ptr()) };
        if rc == 0 {
            Ok(())
        } else {
            Err(Error::new())
        }
    }

    /// Returns whether `attr` has been set on this element.
    pub(crate) fn is_set(&self, attr: u16) -> bool {
        unsafe { sys::nftnl_set_elem_is_set(self.0.as_ptr(), attr) }
    }

    // -- typed attribute accessors ------------------------------------------

    /// Sets the element key.
    pub(crate) fn set_key(&mut self, key: &[u8]) -> Result<(), Error> {
        self.set(sys::NFTNL_SET_ELEM_KEY as u16, key)
    }

    /// Sets the map data value.
    pub(crate) fn set_data(&mut self, data: &[u8]) -> Result<(), Error> {
        self.set(sys::NFTNL_SET_ELEM_DATA as u16, data)
    }

    /// Sets the element flags.
    pub(crate) fn set_flags(&mut self, flags: u32) {
        self.set_u32(sys::NFTNL_SET_ELEM_FLAGS as u16, flags);
    }

    /// Sets the verdict code (for verdict map values).
    pub(crate) fn set_verdict(&mut self, verdict: u32) {
        self.set_u32(sys::NFTNL_SET_ELEM_VERDICT as u16, verdict);
    }

    /// Sets the chain referenced by a `jump`/`goto` verdict.
    pub(crate) fn set_chain(&mut self, chain: &CStr) -> Result<(), Error> {
        self.set_str(sys::NFTNL_SET_ELEM_CHAIN as u16, chain)
    }

    /// Returns the element flags.
    pub(crate) fn flags(&self) -> u32 {
        self.get_u32(sys::NFTNL_SET_ELEM_FLAGS as u16)
    }

    /// Returns whether this element closes an interval (`NFT_SET_ELEM_INTERVAL_END`).
    pub(crate) fn is_interval_end(&self) -> bool {
        self.is_set(sys::NFTNL_SET_ELEM_FLAGS as u16)
            && (self.flags() & libc::NFT_SET_ELEM_INTERVAL_END as u32) != 0
    }

    /// Returns a `u32` attribute. Only meaningful if [`SetElem::is_set`] is true.
    pub(crate) fn get_u32(&self, attr: u16) -> u32 {
        unsafe { sys::nftnl_set_elem_get_u32(self.0.as_ptr(), attr) }
    }

    /// Frees this element.
    ///
    /// Must not be called for an element that was added to a set; the set frees
    /// its elements itself.
    pub(crate) fn free(self) {
        unsafe { sys::nftnl_set_elem_free(self.as_ptr()) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_accessors_round_trip() {
        let mut elem = SetElem::new();
        assert!(!elem.is_interval_end());

        elem.set_key(&[10, 0, 0, 0]).unwrap();
        elem.set_data(&[0x1f, 0x90]).unwrap();
        elem.set_flags(libc::NFT_SET_ELEM_INTERVAL_END as u32);

        assert!(elem.is_interval_end());
        assert!(elem.flags() & libc::NFT_SET_ELEM_INTERVAL_END as u32 != 0);
    }

    #[test]
    fn is_interval_end_false_without_flags() {
        let elem = SetElem::new();
        assert!(!elem.is_interval_end());
    }
}
