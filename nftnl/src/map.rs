use crate::{MsgType, ProtoFamily, datatype::Data, table::Table};
use nftnl_sys::{self as sys, libc};
use std::{
    cell::Cell,
    ffi::{CStr, c_void},
    os::raw::c_char,
    ptr,
    rc::Rc,
};

const NFT_SET_CONCAT: u32 = 0x80;

#[macro_export]
macro_rules! nft_map {
    ($name:expr, $id:expr, $table:expr, $family:expr) => {
        $crate::map::Map::new($name, $id, $table, $family)
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

pub struct Map<'a, K, D> {
    map: ptr::NonNull<sys::nftnl_set>,
    table: &'a Table,
    family: ProtoFamily,
    _marker: ::std::marker::PhantomData<(K, D)>,
}

impl<'a, K, D> Map<'a, K, D> {
    pub fn new(name: &CStr, id: u32, table: &'a Table, family: ProtoFamily) -> Self
    where
        K: Data,
        D: Data,
    {
        let map = try_alloc!(unsafe { sys::nftnl_set_alloc() });

        unsafe {
            let map = map.as_ptr();
            sys::nftnl_set_set_u32(map, sys::NFTNL_SET_FAMILY as u16, family as u32);
            sys::nftnl_set_set_str(map, sys::NFTNL_SET_TABLE as u16, table.get_name().as_ptr());
            sys::nftnl_set_set_str(map, sys::NFTNL_SET_NAME as u16, name.as_ptr());
            sys::nftnl_set_set_u32(map, sys::NFTNL_SET_ID as u16, id);

            sys::nftnl_set_set_u32(
                map,
                sys::NFTNL_SET_FLAGS as u16,
                (libc::NFT_SET_CONSTANT | libc::NFT_SET_MAP) as u32,
            );
            sys::nftnl_set_set_u32(map, sys::NFTNL_SET_KEY_TYPE as u16, K::TYPE);
            sys::nftnl_set_set_u32(map, sys::NFTNL_SET_KEY_LEN as u16, K::LEN);
            sys::nftnl_set_set_u32(map, sys::NFTNL_SET_DATA_TYPE as u16, D::TYPE);
            sys::nftnl_set_set_u32(map, sys::NFTNL_SET_DATA_LEN as u16, D::LEN);
        }

        let mut m = Map {
            map,
            table,
            family,
            _marker: ::std::marker::PhantomData,
        };

        let key_bytes = K::concat_bytes();
        if !key_bytes.is_empty() {
            m.set_concat(&key_bytes);
        }

        m
    }

    fn set_concat(&mut self, field_lengths: &[u32]) {
        let mut desc = Vec::with_capacity(field_lengths.len());
        for &len in field_lengths {
            desc.push(len as u8);
        }

        unsafe {
            let map = self.map.as_ptr();
            let flags = sys::nftnl_set_get_u32(map, sys::NFTNL_SET_FLAGS as u16) | NFT_SET_CONCAT;
            sys::nftnl_set_set_u32(map, sys::NFTNL_SET_FLAGS as u16, flags);

            sys::nftnl_set_set_data(
                map,
                sys::NFTNL_SET_DESC_CONCAT as u16,
                desc.as_ptr() as *const c_void,
                desc.len() as u32,
            );
        }
    }

    pub fn add(&mut self, key: &K, data: &D)
    where
        K: Data,
        D: Data,
    {
        unsafe {
            let elem = try_alloc!(sys::nftnl_set_elem_alloc());

            let key_data = key.data();
            let key_len = key_data.len() as u32;
            trace!("Adding key {key_data:?} with len {key_len}");
            sys::nftnl_set_elem_set(
                elem.as_ptr(),
                sys::NFTNL_SET_ELEM_KEY as u16,
                key_data.as_ptr() as *const c_void,
                key_len,
            );

            data.write_elem(elem.as_ptr());

            sys::nftnl_set_elem_add(self.map.as_ptr(), elem.as_ptr());
        }
    }

    pub fn elems_iter(&'a self) -> MapElemsIter<'a, K, D> {
        MapElemsIter::new(self)
    }

    pub fn as_ptr(&self) -> ptr::NonNull<sys::nftnl_set> {
        self.map
    }

    pub fn get_family(&self) -> ProtoFamily {
        self.family
    }

    pub fn get_name(&self) -> &CStr {
        unsafe {
            let ptr = sys::nftnl_set_get_str(self.map.as_ptr(), sys::NFTNL_SET_NAME as u16);
            CStr::from_ptr(ptr)
        }
    }

    pub fn get_id(&self) -> u32 {
        unsafe { sys::nftnl_set_get_u32(self.map.as_ptr(), sys::NFTNL_SET_ID as u16) }
    }
}

unsafe impl<K, D> crate::NlMsg for Map<'_, K, D> {
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
        unsafe { sys::nftnl_set_nlmsg_build_payload(header, self.map.as_ptr()) };
    }
}

impl<K, D> Drop for Map<'_, K, D> {
    fn drop(&mut self) {
        unsafe { sys::nftnl_set_free(self.map.as_ptr()) };
    }
}

pub struct MapElemsIter<'a, K, D> {
    map: &'a Map<'a, K, D>,
    iter: ptr::NonNull<sys::nftnl_set_elems_iter>,
    ret: Rc<Cell<i32>>,
}

impl<'a, K, D> MapElemsIter<'a, K, D> {
    fn new(map: &'a Map<'a, K, D>) -> Self {
        let iter = try_alloc!(unsafe { sys::nftnl_set_elems_iter_create(map.map.as_ptr()) });
        MapElemsIter {
            map,
            iter,
            ret: Rc::new(Cell::new(1)),
        }
    }
}

impl<'a, K: 'a, D: 'a> Iterator for MapElemsIter<'a, K, D> {
    type Item = MapElemsMsg<'a, K, D>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.ret.get() <= 0
            || unsafe { sys::nftnl_set_elems_iter_cur(self.iter.as_ptr()).is_null() }
        {
            trace!("MapElemsIter iterator ending");
            None
        } else {
            trace!("MapElemsIter returning new MapElemsMsg");
            Some(MapElemsMsg {
                map: self.map,
                iter: self.iter.as_ptr(),
                ret: self.ret.clone(),
            })
        }
    }
}

impl<K, D> Drop for MapElemsIter<'_, K, D> {
    fn drop(&mut self) {
        unsafe { sys::nftnl_set_elems_iter_destroy(self.iter.as_ptr()) };
    }
}

pub struct MapElemsMsg<'a, K, D> {
    map: &'a Map<'a, K, D>,
    iter: *mut sys::nftnl_set_elems_iter,
    ret: Rc<Cell<i32>>,
}

unsafe impl<K, D> crate::NlMsg for MapElemsMsg<'_, K, D> {
    unsafe fn write(&self, buf: *mut c_void, seq: u32, msg_type: MsgType) {
        trace!("Writing MapElemsMsg to NlMsg");
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
                self.map.get_family() as u16,
                flags as u16,
                seq,
            )
        };
        self.ret
            .set(unsafe { sys::nftnl_set_elems_nlmsg_build_payload_iter(header, self.iter) });
    }
}
