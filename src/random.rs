// This file contains code from two files and has been copied from the Rust Project at commit
// ec38671075266e9cee0348701da2e133379e7c6c
// (https://github.com/rust-lang/rust/blob/ec38671075266e9cee0348701da2e133379e7c6c/library/std/src/sys/random/linux.rs, https://github.com/rust-lang/rust/blob/ec38671075266e9cee0348701da2e133379e7c6c/library/std/src/sys/random/apple.rs).
// This was done in order to not use any third party libraries and consume a feature which is
// alreayd in rust but only in nightly and avoid having to be forced to use a nightly version of
// rust.
//
// It falls under the following Copyright.
//
//  Taken from https://github.com/rust-lang/rust/blob/ec38671075266e9cee0348701da2e133379e7c6c/COPYRIGHT
//
//  Short version for non-lawyers:
//
//  The Rust Project is dual-licensed under Apache 2.0 and MIT
//  terms.
//
//  It is Copyright (c) The Rust Project Contributors.
//
//  Longer version:
//
//  Copyrights in the Rust project are retained by their contributors. No
//  copyright assignment is required to contribute to the Rust project.
//
//  Some files include explicit copyright notices and/or license notices.
//  For full authorship information, see the version control history or
//  <https://thanks.rust-lang.org>
//
//  Except as otherwise noted, Rust is licensed under the Apache License, Version
//  2.0 <LICENSE-APACHE> or <http://www.apache.org/licenses/LICENSE-2.0> or the MIT
//  license <LICENSE-MIT> or <http://opensource.org/licenses/MIT>, at your option.

#[cfg(target_os = "linux")]
pub mod linux {
    // Copied content starts after this line.
    //! Random data generation with the Linux kernel.
    //!
    //! The first interface random data interface to be introduced on Linux were
    //! the `/dev/random` and `/dev/urandom` special files. As paths can become
    //! unreachable when inside a chroot and when the file descriptors are exhausted,
    //! this was not enough to provide userspace with a reliable source of randomness,
    //! so when the OpenBSD 5.6 introduced the `getentropy` syscall, Linux 3.17 got
    //! its very own `getrandom`  syscall to match.[^1] Unfortunately, even if our
    //! minimum supported version were high enough, we still couldn't rely on the
    //! syscall being available, as it is blocked in `seccomp` by default.
    //!
    //! The question is therefore which of the random sources to use. Historically,
    //! the kernel contained two pools: the blocking and non-blocking pool. The
    //! blocking pool used entropy estimation to limit the amount of available
    //! bytes, while the non-blocking pool, once initialized using the blocking
    //! pool, uses a CPRNG to return an unlimited number of random bytes. With a
    //! strong enough CPRNG however, the entropy estimation didn't contribute that
    //! much towards security while being an excellent vector for DoS attacks. Thus,
    //! the blocking pool was removed in kernel version 5.6.[^2] That patch did not
    //! magically increase the quality of the non-blocking pool, however, so we can
    //! safely consider it strong enough even in older kernel versions and use it
    //! unconditionally.
    //!
    //! One additional consideration to make is that the non-blocking pool is not
    //! always initialized during early boot. We want the best quality of randomness
    //! for the output of `DefaultRandomSource` so we simply wait until it is
    //! initialized. When `HashMap` keys however, this represents a potential source
    //! of deadlocks, as the additional entropy may only be generated once the
    //! program makes forward progress. In that case, we just use the best random
    //! data the system has available at the time.
    //!
    //! So in conclusion, we always want the output of the non-blocking pool, but
    //! may need to wait until it is initialized. The default behavior of `getrandom`
    //! is to wait until the non-blocking pool is initialized and then draw from there,
    //! so if `getrandom` is available, we use its default to generate the bytes. For
    //! `HashMap`, however, we need to specify the `GRND_INSECURE` flags, but that
    //! is only available starting with kernel version 5.6. Thus, if we detect that
    //! the flag is unsupported, we try `GRND_NONBLOCK` instead, which will only
    //! succeed if the pool is initialized. If it isn't, we fall back to the file
    //! access method.
    //!
    //! The behavior of `/dev/urandom` is inverse to that of `getrandom`: it always
    //! yields data, even when the pool is not initialized. For generating `HashMap`
    //! keys, this is not important, so we can use it directly. For secure data
    //! however, we need to wait until initialization, which we can do by `poll`ing
    //! `/dev/random`.
    //!
    //! TLDR: our fallback strategies are:
    //!
    //! Secure data                                 | `HashMap` keys
    //! --------------------------------------------|------------------
    //! getrandom(0)                                | getrandom(GRND_INSECURE)
    //! poll("/dev/random") && read("/dev/urandom") | getrandom(GRND_NONBLOCK)
    //!                                             | read("/dev/urandom")
    //!
    //! [^1]: <https://lwn.net/Articles/606141/>
    //! [^2]: <https://lwn.net/Articles/808575/>
    //!
    // FIXME(in 2040 or so): once the minimum kernel version is 5.6, remove the
    // `GRND_NONBLOCK` fallback and use `/dev/random` instead of `/dev/urandom`
    // when secure data is required.

    use crate::fs::File;
    use crate::io::Read;
    use crate::os::fd::AsRawFd;
    use crate::sync::OnceLock;
    use crate::sync::atomic::Ordering::{Acquire, Relaxed, Release};
    use crate::sync::atomic::{Atomic, AtomicBool};
    use crate::sys::pal::os::errno;
    use crate::sys::pal::weak::syscall;

    fn getrandom(mut bytes: &mut [u8], insecure: bool) {
        // A weak symbol allows interposition, e.g. for perf measurements that want to
        // disable randomness for consistency. Otherwise, we'll try a raw syscall.
        // (`getrandom` was added in glibc 2.25, musl 1.1.20, android API level 28)
        syscall!(
            fn getrandom(
                buffer: *mut libc::c_void,
                length: libc::size_t,
                flags: libc::c_uint,
            ) -> libc::ssize_t;
        );

        static GETRANDOM_AVAILABLE: Atomic<bool> = AtomicBool::new(true);
        static GRND_INSECURE_AVAILABLE: Atomic<bool> = AtomicBool::new(true);
        static URANDOM_READY: Atomic<bool> = AtomicBool::new(false);
        static DEVICE: OnceLock<File> = OnceLock::new();

        if GETRANDOM_AVAILABLE.load(Relaxed) {
            loop {
                if bytes.is_empty() {
                    return;
                }

                let flags = if insecure {
                    if GRND_INSECURE_AVAILABLE.load(Relaxed) {
                        libc::GRND_INSECURE
                    } else {
                        libc::GRND_NONBLOCK
                    }
                } else {
                    0
                };

                let ret = unsafe { getrandom(bytes.as_mut_ptr().cast(), bytes.len(), flags) };
                if ret != -1 {
                    bytes = &mut bytes[ret as usize..];
                } else {
                    match errno() {
                        libc::EINTR => continue,
                        // `GRND_INSECURE` is not available, try
                        // `GRND_NONBLOCK`.
                        libc::EINVAL if flags == libc::GRND_INSECURE => {
                            GRND_INSECURE_AVAILABLE.store(false, Relaxed);
                            continue;
                        }
                        // The pool is not initialized yet, fall back to
                        // /dev/urandom for now.
                        libc::EAGAIN if flags == libc::GRND_NONBLOCK => break,
                        // `getrandom` is unavailable or blocked by seccomp.
                        // Don't try it again and fall back to /dev/urandom.
                        libc::ENOSYS | libc::EPERM => {
                            GETRANDOM_AVAILABLE.store(false, Relaxed);
                            break;
                        }
                        _ => panic!("failed to generate random data"),
                    }
                }
            }
        }

        // When we want cryptographic strength, we need to wait for the CPRNG-pool
        // to become initialized. Do this by polling `/dev/random` until it is ready.
        if !insecure {
            if !URANDOM_READY.load(Acquire) {
                let random = File::open("/dev/random").expect("failed to open /dev/random");
                let mut fd = libc::pollfd {
                    fd: random.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };

                while !URANDOM_READY.load(Acquire) {
                    let ret = unsafe { libc::poll(&mut fd, 1, -1) };
                    match ret {
                        1 => {
                            assert_eq!(fd.revents, libc::POLLIN);
                            URANDOM_READY.store(true, Release);
                            break;
                        }
                        -1 if errno() == libc::EINTR => continue,
                        _ => panic!("poll(\"/dev/random\") failed"),
                    }
                }
            }
        }

        DEVICE
            .get_or_try_init(|| File::open("/dev/urandom"))
            .and_then(|mut dev| dev.read_exact(bytes))
            .expect("failed to generate random data");
    }

    pub fn fill_bytes(bytes: &mut [u8]) {
        getrandom(bytes, false);
    }

    pub fn hashmap_random_keys() -> (u64, u64) {
        let mut bytes = [0; 16];
        getrandom(&mut bytes, true);
        let k1 = u64::from_ne_bytes(bytes[..8].try_into().unwrap());
        let k2 = u64::from_ne_bytes(bytes[8..].try_into().unwrap());
        (k1, k2)
    }
}

#[cfg(target_vendor = "apple")]
pub mod apple {
    // Copied content starts after this line.
    //! Random data on Apple platforms.
    //!
    //! `CCRandomGenerateBytes` calls into `CCRandomCopyBytes` with `kCCRandomDefault`.
    //! `CCRandomCopyBytes` manages a CSPRNG which is seeded from the kernel's CSPRNG.
    //! We use `CCRandomGenerateBytes` instead of `SecCopyBytes` because it is accessible via
    //! `libSystem` (libc) while the other needs to link to `Security.framework`.
    //!
    //! Note that technically, `arc4random_buf` is available as well, but that calls
    //! into the same system service anyway, and `CCRandomGenerateBytes` has been
    //! proven to be App Store-compatible.

    pub fn fill_bytes(bytes: &mut [u8]) {
        let ret = unsafe { libc::CCRandomGenerateBytes(bytes.as_mut_ptr().cast(), bytes.len()) };
        assert_eq!(ret, libc::kCCSuccess, "failed to generate random data");
    }
}
