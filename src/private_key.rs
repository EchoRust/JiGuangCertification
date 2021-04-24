use crate::error::Error;
use std::{fs::File, io::Read, path::Path};

/// # 极光私钥
/// 一键登录的手机号码将用RSA公钥加密后返回，开发者需使用对应私钥解密，请妥善保存密钥对。
///
/// RSA加密公钥位数1024位，密钥格式PKCS#8.
///
/// [密钥生成工具](http://www.metools.info/code/c80.html)
pub struct PrivateKey {
    /// 私钥
    pub key: Vec<u8>,
}

impl PrivateKey {
    /// 从字符串中加载私钥
    ///
    /// # Example
    ///
    /// ```no_run
    /// use jiguang_certification::PrivateKey;
    ///
    /// let s = r#"
    /// -----BEGIN PRIVATE KEY-----
    /// MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBALx3lux8fiSk8+2f
    /// au7sdQtaAu7GGEIr5juBy6nXq4K+73rN8HPMxEpmg6SnGMFzDL+UlUH9JoRuW7D4
    /// qi7mHmtiOhLXbTSNpPPM/It9gHXYDMV1bD4Z6l3gafttaoim1JGfCqlXQAjzVm1u
    /// -----END PRIVATE KEY-----
    /// "#;
    ///
    /// let private = PrivateKey::from_str(s).unwrap();
    /// ```
    pub fn from_str(key: &str) -> Result<Self, Error> {
        let key = key.lines().filter(|line| !line.starts_with("-")).fold(
            String::new(),
            |mut data, line| {
                data.push_str(line);
                data
            },
        );

        let key = match base64::decode(&key) {
            Ok(key) => key,
            Err(_) => return Err(Error::new(10, String::from("base64解码出现错误"))),
        };

        Ok(Self { key })
    }

    /// 从文件中加载私钥
    ///
    /// # Example
    ///
    /// ```no_run
    /// use jiguang_certification::PrivateKey;
    ///
    /// let private = PrivateKey::from_file("./key.key").unwrap();
    /// ```
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let mut file = match File::open(path) {
            Ok(file) => file,
            Err(_) => {
                return Err(Error::new(
                    11,
                    String::from("文件打开失败，请检查文件是否存在或者是否有访问权限"),
                ))
            }
        };
        let mut s = String::new();
        file.read_to_string(&mut s).unwrap();

        Self::from_str(s.as_str())
    }
}
