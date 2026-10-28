//! Safe access to user memory. Pages are translated through the process's page
//! tables and touched via the HHDM, so the kernel never dereferences a user
//! virtual address directly (unmapped/kernel/read-only pages yield EFAULT).

use x86_64::VirtAddr;

use super::errno::EFAULT;
use crate::mm::layout::{is_user_range, PAGE_SIZE};
use crate::mm::vmm;
use crate::task::Process;

fn for_each_chunk(
    p: &Process,
    addr: u64,
    len: usize,
    write: bool,
    mut f: impl FnMut(*mut u8, usize, usize),
) -> Result<(), i64> {
    if len == 0 {
        return Ok(());
    }
    if !is_user_range(addr, len as u64) {
        return Err(EFAULT);
    }
    let mut guard = p.space.lock();
    let space = guard.as_mut().ok_or(EFAULT)?;
    let mut done = 0usize;
    while done < len {
        let va = addr + done as u64;
        let page_off = (va & (PAGE_SIZE - 1)) as usize;
        let n = core::cmp::min(len - done, PAGE_SIZE as usize - page_off);
        let pa = space.translate_user(VirtAddr::new(va), write).ok_or(EFAULT)?;
        f(vmm::phys_to_virt(pa), n, done);
        done += n;
    }
    Ok(())
}

pub fn copy_from_user(p: &Process, dst: &mut [u8], src: u64) -> Result<(), i64> {
    let base = dst.as_mut_ptr();
    for_each_chunk(p, src, dst.len(), false, |kptr, n, off| {
        // SAFETY: `kptr..kptr+n` is HHDM-mapped RAM backing a present user page;
        // `off+n <= dst.len()` by construction.
        unsafe { core::ptr::copy_nonoverlapping(kptr, base.add(off), n) };
    })
}

pub fn copy_to_user(p: &Process, dst: u64, src: &[u8]) -> Result<(), i64> {
    let base = src.as_ptr();
    for_each_chunk(p, dst, src.len(), true, |kptr, n, off| {
        // SAFETY: as above; the page was verified writable by `translate_user`.
        unsafe { core::ptr::copy_nonoverlapping(base.add(off), kptr, n) };
    })
}
