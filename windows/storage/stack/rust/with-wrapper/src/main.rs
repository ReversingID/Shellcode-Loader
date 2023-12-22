/*
    Shellcode Loader
    Archive of Reversing.ID

    Storing payload in stack.

Compile:
    $ cargo build

Technique:
    - allocation: VirtualAlloc
    - writing:    
    - permission: 
    - execution:  unsafe call to function pointer

Note: 
	- use wrapper for allocation and running thread
*/

use std::ptr;
use std::slice;
use std::ffi::c_void;
use windows::Win32::System::Memory;
use windows::Win32::Foundation;
use windows::Win32::Foundation::WIN32_ERROR;
use windows::Win32::System::Threading;
use windows::Win32::System::WindowsProgramming;

pub struct DistributeMemory {
	len: usize,
	ptr: *mut u8,
}

impl Drop for DistributeMemory {
	fn drop(&mut self) {
		unsafe {
			Memory::VirtualFree(self.ptr as *mut c_void, 0, Memory::MEM_RELEASE);
		}
	}
}

impl DistributeMemory {
	fn new(len: usize) -> Result<DistributeMemory, WIN32_ERROR> {
		let mut memory = DistributeMemory {
			len,
			ptr: ptr::null_mut(),
		};
		
        // allocate memory buffer for payload as READ-WRITE (no executable)
		unsafe {
			memory.ptr = Memory::VirtualAlloc(
				ptr::null(),
				len,
				Memory::MEM_COMMIT | Memory::MEM_RESERVE,
				Memory::PAGE_EXECUTE_READWRITE,
			) as *mut u8;
		};
		
		if memory.ptr.is_null() {
			Err( unsafe{ Foundation::GetLastError()} )
		} else {
			Ok(memory)
		}
	}
	
	// copy to allocated buffer by turning pointer into mut slice
	pub fn as_slice_mut(&mut self) -> &mut[u8] {
		unsafe { slice::from_raw_parts_mut(self.ptr, self.len) }
	}
	
	pub fn as_ptr(&self) -> *mut u8 {
		self.ptr
	}
}

pub struct Thread {
	handle: Foundation::HANDLE,
	tid: u32,
}

impl Drop for Thread {
	fn drop(&mut self) {
		unsafe { Foundation::CloseHandle(self.handle) };
	}
}

impl Thread {
	pub unsafe fn run(start: *const u8) -> Result<Thread, WIN32_ERROR> {
		let mut th = Thread {
			handle: Foundation::HANDLE(0),
			tid: 0,
		};
		
		let ep: extern "system" fn(*mut c_void) -> u32 = { std::mem::transmute(start) };

        // execute shellcode as new thread
		th.handle = Threading::CreateThread(
			ptr::null_mut(),
			0,
			Some(ep),
			ptr::null_mut(),
			windows::Win32::System::Threading::THREAD_CREATION_FLAGS(0),
			&mut th.tid,
		).unwrap();
		
		if th.handle == Foundation::HANDLE(0) {
			Err(Foundation::GetLastError())
		} else {
			Ok(th)
		}
	}
	
	pub fn wait(&self) -> Result<(), WIN32_ERROR> {
		let status = unsafe { Threading::WaitForSingleObject(self.handle, WindowsProgramming::INFINITE) };
		if status == 0 {
			Ok(())
		} else {
			Err( unsafe{Foundation::GetLastError()} )
		}
	}
}

pub fn run(shellcode: Vec<u8>) -> Result<(), WIN32_ERROR> {
	let mut me = DistributeMemory::new(shellcode.len())?;
	let runtime = me.as_slice_mut();
	runtime[..shellcode.len()].copy_from_slice(shellcode.as_slice());
	let t = unsafe {
		Thread::run(me.as_ptr())
	}?;
	t.wait()
}

fn main() {
    static PAYLOAD: [u8; 4] = *b"\x90\x90\xCC\xC3";
	run(PAYLOAD.to_vec());
}