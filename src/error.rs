#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    #[cfg(target_family = "windows")]
    Win32(windows::core::Error),
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Error::Io(error)
    }
}

#[cfg(target_family = "windows")]
impl From<windows::core::Error> for Error {
    fn from(error: windows::core::Error) -> Self {
        Error::Win32(error)
    }
}
