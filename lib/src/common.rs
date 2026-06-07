#[inline]
pub const fn err_as_eof<T>(message: &str) -> impl Fn(T) -> std::io::Error
where
    T: std::error::Error,
{
    move |e| std::io::Error::new(std::io::ErrorKind::UnexpectedEof, format!("{message}: {e}"))
}
