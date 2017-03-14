/// Implement a straightforward conversion of error type
macro_rules! impl_from_error {
    ($f: ty, $e: expr) => {
        impl From<$f> for Error {
            fn from(f: $f) -> Error { $e(f) }
        }
    }
}

/// Implement a simple Deref from `From` to `To` where `From` is a newtype struct containing `To`
macro_rules! impl_deref {
    ($f:ty, $t:ty) => {
        impl Deref for $f {
            type Target = $t;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }
    }
}
