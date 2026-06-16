use super::{Expression, Register, Rule};
use crate::datatype::Data;
use crate::map::Map;
use nftnl_sys::{self as sys, libc};
use std::{ffi::CString, ptr};

#[macro_export]
macro_rules! nft_expr_lookup_map {
    ($map:expr $( , $sreg:expr )? => $dreg:expr) => {
        $crate::expr::LookupMap::new($map, $dreg) $( .set_sreg($sreg) )?
    };
}

/// Map lookup expression. Looks up a key in a map and writes the value to `dreg`.
pub struct LookupMap {
    set_name: CString,
    set_id: u32,
    sreg: u32,
    dreg: u32,
}

impl LookupMap {
    pub fn new<K, D: Data>(map: &Map<'_, K, D>, dreg: Register) -> Self {
        LookupMap {
            set_name: map.get_name().to_owned(),
            set_id: map.get_id(),
            sreg: libc::NFT_REG_1 as u32,
            dreg: dreg.to_raw(),
        }
    }

    pub fn set_sreg(mut self, reg: Register) -> Self {
        self.sreg = reg.to_raw();
        self
    }
}

impl Expression for LookupMap {
    fn to_expr(&self, _rule: &Rule) -> ptr::NonNull<sys::nftnl_expr> {
        unsafe {
            let expr = try_alloc!(sys::nftnl_expr_alloc(c"lookup".as_ptr()));

            sys::nftnl_expr_set_u32(expr.as_ptr(), sys::NFTNL_EXPR_LOOKUP_SREG as u16, self.sreg);
            sys::nftnl_expr_set_str(
                expr.as_ptr(),
                sys::NFTNL_EXPR_LOOKUP_SET as u16,
                self.set_name.as_ptr(),
            );
            sys::nftnl_expr_set_u32(
                expr.as_ptr(),
                sys::NFTNL_EXPR_LOOKUP_SET_ID as u16,
                self.set_id,
            );
            sys::nftnl_expr_set_u32(expr.as_ptr(), sys::NFTNL_EXPR_LOOKUP_DREG as u16, self.dreg);

            expr
        }
    }
}
