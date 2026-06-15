use std::io;

/// Returns the platform-specific integer for EMSGSIZE (Message too long)
const fn emsgsize_code() -> i32 {
    #[cfg(target_os = "linux")]
    {
        90
    }

    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd"
    ))]
    {
        40
    }

    #[cfg(target_os = "windows")]
    {
        10040
    } // Windows Sockets WSAEMSGSIZE

    // Fallback for other Unix-like OSes if they match Linux layout
    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "windows"
    )))]
    {
        90
    }
}

pub fn errmsgsize() -> io::Error {
    io::Error::from_raw_os_error(emsgsize_code())
}
