//! Test-only allocation counters for import resource limits.
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

struct Allocator;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static OVERLAP: AtomicUsize = AtomicUsize::new(0);

fn allocated(bytes: usize) {
    let live = LIVE.fetch_add(bytes, Relaxed) + bytes;
    PEAK.fetch_max(live, Relaxed);
    OVERLAP.fetch_max(live, Relaxed);
}

unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let result = unsafe { System.alloc(layout) };
        if !result.is_null() {
            allocated(layout.size());
        }
        result
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Relaxed);
        unsafe { System.dealloc(pointer, layout) };
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let result = unsafe { System.realloc(pointer, layout, size) };
        if !result.is_null() {
            // Also report the upper bound if old and new blocks overlap in time.
            OVERLAP.fetch_max(LIVE.load(Relaxed).saturating_add(size), Relaxed);
            LIVE.fetch_sub(layout.size(), Relaxed);
            allocated(size);
        }
        result
    }
}

#[global_allocator]
static ALLOCATOR: Allocator = Allocator;

pub fn live() -> usize {
    LIVE.load(Relaxed)
}
pub fn reset() {
    PEAK.store(live(), Relaxed);
    OVERLAP.store(live(), Relaxed);
}
pub fn peak() -> usize {
    PEAK.load(Relaxed)
}
pub fn overlap() -> usize {
    OVERLAP.load(Relaxed)
}

pub fn verify() {
    let baseline = live();
    reset();
    let first = Layout::from_size_align(64, 8).unwrap();
    unsafe {
        let pointer = std::alloc::alloc(first);
        assert!(!pointer.is_null());
        assert_eq!(live(), baseline + 64);
        let pointer = std::alloc::realloc(pointer, first, 128);
        assert!(!pointer.is_null());
        assert_eq!(live(), baseline + 128);
        assert_eq!(peak(), baseline + 128);
        assert_eq!(overlap(), baseline + 192);
        std::alloc::dealloc(pointer, Layout::from_size_align(128, 8).unwrap());
    }
    assert_eq!(live(), baseline);
}
