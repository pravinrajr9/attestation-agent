use std::cell::UnsafeCell;
use std::marker::PhantomData;
use std::mem;

pub struct Opaque(PhantomData<UnsafeCell<*mut ()>>);

pub unsafe trait ForeignType: Sized {
    /// The raw C type.
    type CType;

    /// The type representing a reference to this type.
    type Ref: ForeignTypeRef<CType = Self::CType>;

    /// Constructs an instance of this type from its raw type.
    unsafe fn from_ptr(ptr: *mut Self::CType) -> Self;

    /// Returns a raw pointer to the wrapped value.
    fn as_ptr(&self) -> *mut Self::CType;

    /// Consumes the wrapper and returns the raw pointer.
    #[inline]
    fn into_ptr(self) -> *mut Self::CType {
        let ptr = self.as_ptr();
        mem::forget(self);
        ptr
    }
}

/// A trait implemented by types which reference borrowed foreign types.
pub unsafe trait ForeignTypeRef: Sized {
    /// The raw C type.
    type CType;

    /// Constructs a shared instance of this type from its raw type.
    #[inline]
    unsafe fn from_ptr<'a>(ptr: *mut Self::CType) -> &'a Self {
        debug_assert!(!ptr.is_null());
        &*(ptr as *mut _)
    }

    /// Constructs a mutable reference of this type from its raw type.
    #[inline]
    unsafe fn from_ptr_mut<'a>(ptr: *mut Self::CType) -> &'a mut Self {
        debug_assert!(!ptr.is_null());
        &mut *(ptr as *mut _)
    }

    /// Returns a raw pointer to the wrapped value.
    #[inline]
    fn as_ptr(&self) -> *mut Self::CType {
        self as *const _ as *mut _
    }
}
