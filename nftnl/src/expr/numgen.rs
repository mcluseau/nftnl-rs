use super::{Expression, Register, Rule};
use nftnl_sys as sys;
use std::ptr;

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[repr(i32)]
pub enum NumgenMode {
    Incremental = 0,
    Random = 1,
}

pub struct Numgen {
    mode: NumgenMode,
    modulus: u32,
    register: Register,
    offset: u32,
}

impl Numgen {
    pub fn new(mode: NumgenMode, modulus: u32, register: Register) -> Self {
        Numgen {
            mode,
            modulus,
            register,
            offset: 0,
        }
    }

    pub fn set_offset(mut self, offset: u32) -> Self {
        self.offset = offset;
        self
    }
}

impl Expression for Numgen {
    fn to_expr(&self, _rule: &Rule) -> ptr::NonNull<sys::nftnl_expr> {
        unsafe {
            let expr = try_alloc!(sys::nftnl_expr_alloc(c"numgen".as_ptr()));

            sys::nftnl_expr_set_u32(
                expr.as_ptr(),
                sys::NFTNL_EXPR_NG_DREG as u16,
                self.register.to_raw(),
            );
            sys::nftnl_expr_set_u32(
                expr.as_ptr(),
                sys::NFTNL_EXPR_NG_MODULUS as u16,
                self.modulus,
            );
            sys::nftnl_expr_set_u32(
                expr.as_ptr(),
                sys::NFTNL_EXPR_NG_TYPE as u16,
                self.mode as u32,
            );
            if self.offset != 0 {
                sys::nftnl_expr_set_u32(
                    expr.as_ptr(),
                    sys::NFTNL_EXPR_NG_OFFSET as u16,
                    self.offset,
                );
            }

            expr
        }
    }
}

#[macro_export]
macro_rules! nft_expr_numgen {
    (random mod $modulus:expr) => {
        $crate::expr::Numgen::new(
            $crate::expr::NumgenMode::Random,
            $modulus,
            $crate::expr::Register::Reg1,
        )
    };
    (random mod $modulus:expr, offset $offset:expr) => {
        $crate::expr::Numgen::new(
            $crate::expr::NumgenMode::Random,
            $modulus,
            $crate::expr::Register::Reg1,
        )
        .set_offset($offset)
    };
    (inc mod $modulus:expr) => {
        $crate::expr::Numgen::new(
            $crate::expr::NumgenMode::Incremental,
            $modulus,
            $crate::expr::Register::Reg1,
        )
    };
    (inc mod $modulus:expr, offset $offset:expr) => {
        $crate::expr::Numgen::new(
            $crate::expr::NumgenMode::Incremental,
            $modulus,
            $crate::expr::Register::Reg1,
        )
        .set_offset($offset)
    };
}
