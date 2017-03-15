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

/// Extract some value from an expression via pattern matching. This is the cousin to `assert_matches!`.
macro_rules! match_extract {
    ($e: expr, $p: pat, $f: expr) => (match $e {
        $p => Ok($f),
        _ => {
            Err(format!("{}: Expected pattern {} \ndid not match", stringify!($e), stringify!($p)).to_string())
        }
    })
}
