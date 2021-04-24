/// 错误类型
///
/// [极光错误类型说明](https://docs.jiguang.cn/jverification/server/rest_api/code_description/)
#[derive(Debug)]
pub struct Error {
    /// 错误码
    pub code: u32,
    /// 错误信息说明
    pub message: String,
}

impl Error {
    pub fn new(code: u32, message: String) -> Self {
        Self { code, message }
    }
}
