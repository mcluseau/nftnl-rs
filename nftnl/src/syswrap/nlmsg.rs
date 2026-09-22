use nftnl_sys::{self as sys, libc, mnl_sys};
use std::marker::PhantomData;
use std::ffi::CStr;
use std::ptr::NonNull;

use super::SetElem;

/// `enum nft_set_elem_list_attributes` from `linux/netfilter/nf_tables.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub(crate) enum SetElemListAttr {
    Unspec = 0,
    Table = 1,
    Set = 2,
    Elements = 3,
    SetId = 4,
}

impl From<SetElemListAttr> for u16 {
    fn from(attr: SetElemListAttr) -> Self {
        attr as u16
    }
}

pub(crate) trait Attr {}

impl Attr for () {}
impl Attr for SetElemListAttr {}

/// A netlink message header under construction in a caller-owned buffer.
///
/// Wraps `nftnl_nlmsg_build_hdr` (which composes the nf_tables subsystem id
/// into the message type and prepends the `nfgenmsg`) and the subset of
/// `libmnl` attribute helpers used to put the payload attributes.
///
/// This type borrows the buffer; it does not own it and has no `Drop`.
pub(crate) struct NlMsgHdr<A>(NonNull<libc::nlmsghdr>, PhantomData<A>);

impl<A: Attr> NlMsgHdr<A> {
    /// Starts an nf_tables message with the given raw `NFT_MSG_*` `msg_type`.
    pub(crate) fn build(
        buf: *mut libc::c_char,
        msg_type: u16,
        family: u16,
        flags: u16,
        seq: u32,
    ) -> Self {
        Self(non_null_hdr(unsafe {
            sys::nftnl_nlmsg_build_hdr(buf, msg_type, family, flags, seq)
        }), PhantomData)
    }

    pub(crate) fn as_ptr(&self) -> *mut libc::nlmsghdr {
        self.0.as_ptr()
    }

    /// Current total length of the message, in bytes.
    pub(crate) fn msg_len(&self) -> u32 {
        unsafe { self.0.as_ref().nlmsg_len }
    }

    /// Reduces the recorded message length by `by` bytes.
    ///
    /// Used to discard the most recently appended attribute(s), mirroring what
    /// `nft` does on attribute-nest overflow.
    pub(crate) fn shrink(&mut self, by: u32) {
        unsafe { self.0.as_mut().nlmsg_len -= by };
    }

    /// Appends a raw binary attribute.
    pub(crate) fn put(&mut self, attr: impl Into<u16>, data: &[u8]) {
        unsafe {
            mnl_sys::mnl_attr_put(self.as_ptr(), attr.into(), data.len(), data.as_ptr().cast())
        };
    }

    /// Appends a big-endian `u32` attribute.
    pub(crate) fn put_u32(&mut self, attr: impl Into<u16>, val: u32) {
        unsafe { mnl_sys::mnl_attr_put_u32(self.as_ptr(), attr.into(), val) };
    }

    /// Appends a NUL-terminated string attribute.
    pub(crate) fn put_strz(&mut self, attr: impl Into<u16>, val: &CStr) {
        unsafe { mnl_sys::mnl_attr_put_strz(self.as_ptr(), attr.into(), val.as_ptr()) };
    }

    /// Begins a nested attribute, returning a guard that must be released with
    /// [`Nested::end`].
    pub(crate) fn nest_start(&mut self, attr: impl Into<u16>) -> Nested<'_, A> {
        let ptr = unsafe { mnl_sys::mnl_attr_nest_start(self.as_ptr(), attr.into()) };
        Nested {
            container: self,
            start: NonNull::new(ptr).expect("mnl_attr_nest_start never returns null"),
        }
    }

    /// Sets the [`libc::NLM_F_ACK`] flag on this message.
    pub(crate) fn set_ack(&mut self) {
        unsafe { self.0.as_mut().nlmsg_flags |= libc::NLM_F_ACK as u16 };
    }
}

impl NlMsgHdr<SetElemListAttr> {
    /// Appends the set name to a `NEWSETELEM`/`DELSETELEM` message.
    pub(crate) fn set_name(&mut self, name: &CStr) {
        self.put_strz(SetElemListAttr::Set, name);
    }

    /// Appends the set id to a `NEWSETELEM`/`DELSETELEM` message.
    pub(crate) fn set_id(&mut self, id: u32) {
        self.put_u32(SetElemListAttr::SetId, id.to_be());
    }

    /// Appends the table name to a `NEWSETELEM`/`DELSETELEM` message.
    pub(crate) fn set_table(&mut self, table: &CStr) {
        self.put_strz(SetElemListAttr::Table, table);
    }

    /// Begins the set-element list nest of a `NEWSETELEM`/`DELSETELEM` message.
    pub(crate) fn start_elements(&mut self) -> NestedSetElem<'_> {
        NestedSetElem {
            nested: self.nest_start(SetElemListAttr::Elements),
            i: 0,
        }
    }
}

/// An open set-element list nest, as required by a `NEWSETELEM`/`DELSETELEM`
/// message. Created by [`NlMsgHdr::start_elements`].
pub(crate) struct NestedSetElem<'a> {
    nested: Nested<'a, SetElemListAttr>,
    /// 1-based index of the next element appended to this nest.
    i: libc::c_int,
}

impl NestedSetElem<'_> {
    /// Serializes `elem` into this nest and returns its length in bytes.
    pub(crate) fn push(&mut self, elem: &SetElem) -> u16 {
        self.i += 1;
        let ptr =
            unsafe { sys::nftnl_set_elem_nlmsg_build(self.nested.as_ptr(), elem.as_ptr(), self.i) };
        let ptr = NonNull::new(ptr.cast::<libc::nlattr>())
            .expect("nftnl_set_elem_nlmsg_build returns an attr");
        unsafe { mnl_sys::mnl_attr_get_len(ptr.as_ptr()) }
    }

    /// Length of the nest written so far, from the nest header to the current
    /// end of the message. Used to detect the 16-bit nest-length overflow.
    pub(crate) fn len_so_far(&self) -> usize {
        self.nested.len_so_far()
    }

    /// Reduces the recorded message length by `by` bytes, e.g. to discard an
    /// element that did not fit in this nest.
    pub(crate) fn shrink(&mut self, by: u32) {
        self.nested.shrink(by);
    }

    /// Closes this nest.
    pub(crate) fn end(self) {
        self.nested.end();
    }
}

/// An open nested attribute (`NLA_F_NESTED`), returned by
/// [`NlMsgHdr::nest_start`].
///
/// It borrows its container, so attributes can only be appended through it
/// while the nest is open, and the nest is only closed by consuming it with
/// [`Nested::end`]. Derefs to the container to reach the attribute putters.
pub(crate) struct Nested<'a, A> {
    container: &'a mut NlMsgHdr<A>,
    start: NonNull<libc::nlattr>,
}

impl<A: Attr> Nested<'_, A> {
    /// Length of the nest written so far, from the nest header to the current
    /// end of the message.
    pub(crate) fn len_so_far(&self) -> usize {
        let end = self.container.0.as_ptr() as usize + self.container.msg_len() as usize;
        end - self.start.as_ptr() as usize
    }

    /// Reduces the container's recorded message length by `by` bytes, e.g. to
    /// discard an attribute that did not fit in this nest.
    pub(crate) fn shrink(&mut self, by: u32) {
        self.container.shrink(by);
    }

    /// Closes this nest.
    pub(crate) fn end(self) {
        unsafe { mnl_sys::mnl_attr_nest_end(self.container.as_ptr(), self.start.as_ptr()) };
    }
}

impl<A: Attr> std::ops::Deref for Nested<'_, A> {
    type Target = NlMsgHdr<A>;

    fn deref(&self) -> &Self::Target {
        self.container
    }
}

impl<A: Attr> std::ops::DerefMut for Nested<'_, A> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.container
    }
}

fn non_null_hdr(ptr: *mut libc::nlmsghdr) -> NonNull<libc::nlmsghdr> {
    NonNull::new(ptr).expect("nftnl_nlmsg_build_hdr never returns null")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_attrs(buf: &[u8], offset: usize) -> Vec<(u16, usize, usize)> {
        // (type, header offset, total len)
        let mut out = Vec::new();
        let mut off = offset;
        while off + 4 <= buf.len() {
            let attr = unsafe { &*buf[off..].as_ptr().cast::<libc::nlattr>() };
            let len = attr.nla_len as usize;
            if len < 4 || off + len > buf.len() {
                break;
            }
            out.push((attr.nla_type & 0x3fff, off, len));
            off += (len + 3) & !3;
        }
        out
    }

    #[test]
    fn builds_header_with_nfgenmsg() {
        let mut buf = vec![0u8; 256];
        let hdr = NlMsgHdr::<()>::build(
            buf.as_mut_ptr().cast(),
            libc::NFT_MSG_NEWTABLE as u16,
            libc::NFPROTO_IPV4 as u16,
            (libc::NLM_F_ACK | libc::NLM_F_CREATE) as u16,
            7,
        );
        let nlh = unsafe { &*hdr.as_ptr() };
        // nf_tables subsystem id is composed in.
        assert_eq!(
            nlh.nlmsg_type,
            ((libc::NFNL_SUBSYS_NFTABLES as u16) << 8) | libc::NFT_MSG_NEWTABLE as u16
        );
        assert_eq!(nlh.nlmsg_seq, 7);
        assert_ne!(nlh.nlmsg_flags & libc::NLM_F_ACK as u16, 0);
        // header + nfgenmsg
        assert_eq!(nlh.nlmsg_len, (std::mem::size_of::<libc::nlmsghdr>() + 4) as u32);
    }

    #[test]
    fn puts_attributes_and_nests() {
        let mut buf = vec![0u8; 512];
        let mut hdr = NlMsgHdr::<()>::build(
            buf.as_mut_ptr().cast(),
            libc::NFT_MSG_NEWTABLE as u16,
            libc::NFPROTO_IPV4 as u16,
            0,
            1,
        );
        let base = std::mem::size_of::<libc::nlmsghdr>() + 4;

        hdr.put_u32(10u16, 42);
        let mut nest = hdr.nest_start(20u16);
        nest.put_u32(21u16, 7);
        nest.end();

        let len = hdr.msg_len() as usize;
        let attrs = parse_attrs(&buf[..len], base);
        assert_eq!(attrs.iter().map(|a| a.0).collect::<Vec<_>>(), vec![10, 20]);
        // nested attribute contains one child
        let (_, off, nlen) = attrs[1];
        let child_base = off + 4;
        let children = parse_attrs(&buf[..off + nlen], child_base);
        assert_eq!(children.len(), 1);
        assert_eq!(children[0].0, 21);
    }

    #[test]
    fn typed_set_list_attributes() {
        let mut buf = vec![0u8; 512];
        let mut hdr = NlMsgHdr::build(
            buf.as_mut_ptr().cast(),
            libc::NFT_MSG_NEWSETELEM as u16,
            libc::NFPROTO_IPV4 as u16,
            0,
            1,
        );
        let base = std::mem::size_of::<libc::nlmsghdr>() + 4;

        hdr.set_table(c"t");
        hdr.set_name(c"s");
        hdr.set_id(0x0102_0304);
        hdr.start_elements().end();

        let len = hdr.msg_len() as usize;
        let attrs = parse_attrs(&buf[..len], base);
        assert_eq!(
            attrs.iter().map(|a| a.0).collect::<Vec<_>>(),
            vec![
                u16::from(SetElemListAttr::Table),
                u16::from(SetElemListAttr::Set),
                u16::from(SetElemListAttr::SetId),
                u16::from(SetElemListAttr::Elements),
            ]
        );
        // set id is big-endian on the wire.
        let (_, off, nlen) = attrs[2];
        assert_eq!(
            &buf[off + 4..off + nlen],
            &0x0102_0304u32.to_be_bytes()
        );
    }

    #[test]
    fn shrink_discards_last_attribute() {
        let mut buf = vec![0u8; 512];
        let mut hdr = NlMsgHdr::<()>::build(
            buf.as_mut_ptr().cast(),
            libc::NFT_MSG_NEWTABLE as u16,
            libc::NFPROTO_IPV4 as u16,
            0,
            1,
        );
        let before = hdr.msg_len();
        hdr.put_u32(10u16, 1);
        let with_attr = hdr.msg_len();
        assert!(with_attr > before);
        hdr.shrink(with_attr - before);
        assert_eq!(hdr.msg_len(), before);
    }
}
