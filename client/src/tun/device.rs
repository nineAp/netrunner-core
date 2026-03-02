use bytes::{Bytes, BytesMut};
use smoltcp::phy::{ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken, TxToken};
use std::io::{Read, Write};
use std::os::fd::RawFd;
use std::os::unix::io::AsRawFd;

pub struct TunDevice<T: Read + Write + AsRawFd> {
    pub io: T, // Сюда мы запихнем или File (Android) или Tun-либу
    mtu: usize,
    read_buffer: BytesMut,
}

impl<T: Read + Write + AsRawFd> TunDevice<T> {
    pub fn new(io: T, mtu: usize) -> Self {
        let fd = io.as_raw_fd();
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFL);
            if flags == -1 {
                panic!("Не удалось получить флаги файла");
            }
            libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
        Self {
            io,
            mtu,
            read_buffer: BytesMut::with_capacity(mtu),
        }
    }
}

impl<T: Read + Write + AsRawFd> Device for TunDevice<T> {
    type RxToken<'a>
        = TunRxToken
    where
        Self: 'a;
    type TxToken<'a>
        = TunTxToken<'a, T>
    where
        Self: 'a;

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps.checksum = ChecksumCapabilities::ignored();
        caps
    }

    fn receive(
        &mut self,
        _timestamp: smoltcp::time::Instant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let mut tmp_buf = [0u8; 2048];
        match self.io.read(&mut tmp_buf) {
            Ok(n) if n > 0 => {
                let rx_data = Bytes::copy_from_slice(&tmp_buf[..n]);

                let rx = TunRxToken { buffer: rx_data };
                let tx = TunTxToken { io: &mut self.io };
                Some((rx, tx))
            }
            _ => None,
        }
    }

    fn transmit(&mut self, _timestamp: smoltcp::time::Instant) -> Option<Self::TxToken<'_>> {
        Some(TunTxToken { io: &mut self.io })
    }
}

pub struct TunRxToken {
    buffer: Bytes,
}

impl RxToken for TunRxToken {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&mut self.buffer)
    }
}

pub struct TunTxToken<'a, T: Write> {
    io: &'a mut T,
}

impl<'a, T: Write> TxToken for TunTxToken<'a, T> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        // ПРЯМАЯ ЗАПИСЬ БЕЗ ДОБАВЛЕНИЯ PI-ЗАГОЛОВКА
        let mut buffer = vec![0u8; len];
        let result = f(&mut buffer);
        let _ = self.io.write_all(&buffer);
        result
    }
}

impl<T: Read + Write + AsRawFd> AsRawFd for TunDevice<T> {
    fn as_raw_fd(&self) -> RawFd {
        self.io.as_raw_fd()
    }
}
