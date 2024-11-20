#![no_std]
#![feature(alloc_error_handler)]
#![feature(iterator_try_collect)]
use core::{
    alloc::{GlobalAlloc, Layout},
    ffi::{c_char, CStr},
};
use panic_halt as _;

struct PanicAllocator;

#[cfg(not(test))]
#[global_allocator]
static GLOBAL: PanicAllocator = PanicAllocator;

unsafe impl GlobalAlloc for PanicAllocator {
    unsafe fn alloc(&self, _layout: Layout) -> *mut u8 {
        panic!()
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {
        panic!()
    }
}

#[alloc_error_handler]
fn foo(_: core::alloc::Layout) -> ! {
    panic!()
}

#[repr(C)]
pub struct SubjectIdentity {
    identifier: *const c_char,
    issuer: *const c_char,
}

impl Default for SubjectIdentity {
    fn default() -> Self {
        Self {
            identifier: core::ptr::null(),
            issuer: core::ptr::null(),
        }
    }
}

#[no_mangle]
pub extern "C" fn verify_bt(
    rekor_pub_key: *const u8,
    rekor_pub_key_len: usize,
    root_cert: *const u8,
    root_cert_len: usize,
    bundle: *const u8,
    bundle_len: usize,
    blob: *const u8,
    blob_len: usize,
    subject_identities: *const SubjectIdentity,
    subject_identities_len: usize,
) -> bool {
    let rekor_pub_key = unsafe { core::slice::from_raw_parts(rekor_pub_key, rekor_pub_key_len) };
    let root_cert = unsafe { core::slice::from_raw_parts(root_cert, root_cert_len) };
    let bundle = unsafe { core::slice::from_raw_parts(bundle, bundle_len) };
    let blob = unsafe { core::slice::from_raw_parts(blob, blob_len) };
    let subject_identities =
        unsafe { core::slice::from_raw_parts(subject_identities, subject_identities_len) };
    let Ok(subject_identities) = subject_identities
        .iter()
        .map(|s| {
            let identifier = unsafe { CStr::from_ptr(s.identifier) };
            let issuer = unsafe { CStr::from_ptr(s.issuer) };
            Ok((
                identifier.to_str().map_err(|_| ())?,
                issuer.to_str().map_err(|_| ())?,
            ))
        })
        .collect::<Result<heapless::Vec<_, 10>, ()>>()
    else {
        return false;
    };

    bt2x_embedded::verify_bt(
        rekor_pub_key,
        root_cert,
        bundle,
        blob,
        subject_identities.as_slice(),
    )
    .is_ok()
}
