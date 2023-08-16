//! Solana Rust-based BPF memory operations

/// Memcpy
///
/// @param dst - Destination
/// @param src - Source
/// @param n - Number of bytes to copy
#[inline]
pub fn sor_memcpy(dst: &mut [u8], src: &[u8], n: usize) {
    #[cfg(target_arch = "bpf")]
    {
        extern "C" {
            fn sor_memcpy_(dst: *mut u8, src: *const u8, n: u64);
        }
        unsafe {
            sor_memcpy_(dst.as_mut_ptr(), src.as_ptr(), n as u64);
        }
    }

    #[cfg(not(target_arch = "bpf"))]
    crate::program_stubs::sor_memcpy(dst.as_mut_ptr(), src.as_ptr(), n);
}

/// Memmove
///
/// @param dst - Destination
/// @param src - Source
/// @param n - Number of bytes to copy
///
/// # Safety
#[inline]
pub unsafe fn sor_memmove(dst: *mut u8, src: *mut u8, n: usize) {
    #[cfg(target_arch = "bpf")]
    {
        extern "C" {
            fn sor_memmove_(dst: *mut u8, src: *const u8, n: u64);
        }
        sor_memmove_(dst, src, n as u64);
    }

    #[cfg(not(target_arch = "bpf"))]
    crate::program_stubs::sor_memmove(dst, src, n);
}

/// Memcmp
///
/// @param s1 - Slice to be compared
/// @param s2 - Slice to be compared
/// @param n - Number of bytes to compare
#[inline]
pub fn sor_memcmp(s1: &[u8], s2: &[u8], n: usize) -> i32 {
    let mut result = 0;

    #[cfg(target_arch = "bpf")]
    {
        extern "C" {
            fn sor_memcmp_(s1: *const u8, s2: *const u8, n: u64, result: *mut i32);
        }
        unsafe {
            sor_memcmp_(s1.as_ptr(), s2.as_ptr(), n as u64, &mut result as *mut i32);
        }
    }

    #[cfg(not(target_arch = "bpf"))]
    crate::program_stubs::sor_memcmp(s1.as_ptr(), s2.as_ptr(), n, &mut result as *mut i32);

    result
}

/// Memset
///
/// @param s1 - Slice to be compared
/// @param s2 - Slice to be compared
/// @param n - Number of bytes to compare
#[inline]
pub fn sor_memset(s: &mut [u8], c: u8, n: usize) {
    #[cfg(target_arch = "bpf")]
    {
        extern "C" {
            fn sor_memset_(s: *mut u8, c: u8, n: u64);
        }
        unsafe {
            sor_memset_(s.as_mut_ptr(), c, n as u64);
        }
    }

    #[cfg(not(target_arch = "bpf"))]
    crate::program_stubs::sor_memset(s.as_mut_ptr(), c, n);
}
