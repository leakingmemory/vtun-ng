/*
    VTun - Virtual Tunnel over TCP/IP network.

    Copyright (C) 1998-2016  Maxim Krasnyansky <max_mk@yahoo.com>
    Copyright (C) 2025 Jan-Espen Oversand <sigsegv@radiotube.org>

    VTun has been derived from VPPP package by Maxim Krasnyansky.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
 */

use std::ptr;

#[repr(C)]
pub struct LListElement {
    pub next: *mut LListElement,
    pub data: *mut libc::c_void
}

#[repr(C)]
pub struct LList {
    pub head: *mut LListElement,
    pub tail: *mut LListElement
}

impl LList {
    pub fn new() -> LList {
        LList {
            head: ptr::null_mut(),
            tail: ptr::null_mut()
        }
    }
}

impl Clone for LList {
    fn clone(&self) -> Self {
        let mut head: *mut LListElement = ptr::null_mut();
        let mut tail: *mut LListElement = ptr::null_mut();
        let mut walk = self.head;
        if walk != ptr::null_mut() {
            unsafe {
                head = libc::malloc(size_of::<LListElement>()) as *mut LListElement;
                libc::memset(head as *mut libc::c_void, 0, size_of::<LListElement>());
            }
            let head = unsafe { &mut *head };
            head.data = unsafe { &*walk }.data;
        }
        let mut item: *mut LListElement = head;
        while walk != self.tail {
            walk = unsafe { &*walk }.next;
            unsafe {
                (*item).next = libc::malloc(size_of::<LListElement>()) as *mut LListElement;
                libc::memset((*head).next as *mut libc::c_void, 0, size_of::<LListElement>());
                item = (*item).next;
            }
            let item = unsafe { &mut *item };
            item.data = unsafe { &*walk }.data;
        }
        if self.tail != ptr::null_mut() {
            tail = item;
        }
        Self {
            head,
            tail
        }
    }
}

impl Drop for LList {
    fn drop(&mut self) {
        let mut walk = self.head;
        if walk == ptr::null_mut() {
            return;
        }
        while walk != self.tail {
            walk = unsafe { &*walk }.next;
            unsafe {
                libc::free(walk as *mut libc::c_void);
            }
        }
        unsafe { libc::free(self.head as *mut libc::c_void); }
    }
}