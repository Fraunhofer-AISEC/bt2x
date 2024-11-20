pub use embedded_storage::nor_flash::NorFlash;
/// File-system-backed "flash" implementation for testing purposes.
#[cfg(any(feature = "mock_flash", test))]
pub mod mock_flash {
    use alloc::vec;
    pub use embedded_storage::nor_flash::{
        ErrorType, NorFlash, NorFlashError, NorFlashErrorKind, ReadNorFlash,
    };
    use std::os::unix::fs::FileExt;

    #[derive(Debug)]
    pub struct FsWriter(pub std::path::PathBuf);

    impl ReadNorFlash for FsWriter {
        const READ_SIZE: usize = 0;

        fn read(&mut self, offset: u32, bytes: &mut [u8]) -> Result<(), Self::Error> {
            let f = std::fs::OpenOptions::new()
                .read(true)
                .open(&self.0)
                .map_err(|_| FsWriterError(NorFlashErrorKind::Other))?;
            f.read_exact_at(bytes, offset as u64)
                .map_err(|_| FsWriterError(NorFlashErrorKind::Other))?;
            Ok(())
        }

        fn capacity(&self) -> usize {
            0x4096 * 1024 * 1024
        }
    }

    #[derive(Debug)]
    pub struct FsWriterError(NorFlashErrorKind);

    impl NorFlashError for FsWriterError {
        fn kind(&self) -> NorFlashErrorKind {
            self.0
        }
    }

    impl ErrorType for FsWriter {
        type Error = FsWriterError;
    }

    impl NorFlash for FsWriter {
        const ERASE_SIZE: usize = 0;
        const WRITE_SIZE: usize = 0;

        fn erase(&mut self, from: u32, to: u32) -> Result<(), Self::Error> {
            let data = vec![1; (to - from) as usize];
            let f = std::fs::OpenOptions::new()
                .read(true)
                .open(&self.0)
                .map_err(|_| FsWriterError(NorFlashErrorKind::Other))?;
            f.write_at(&data, from as u64)
                .map_err(|_| FsWriterError(NorFlashErrorKind::Other))?;
            Ok(())
        }

        fn write(&mut self, offset: u32, bytes: &[u8]) -> Result<(), Self::Error> {
            let f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                //.truncate(true)
                .open(&self.0)
                .expect("failed to open file");
            f.write_at(bytes, offset as u64).expect("failed to write");
            Ok(())
        }
    }
}

#[cfg(test)]
pub(crate) mod test {}
