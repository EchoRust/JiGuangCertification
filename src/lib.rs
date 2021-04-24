//! # 极光认证登录SDK
//!
//! 极光认证整合了三大运营商的网关认证能力，为开发者提供了一键登录和号码认证功能，优化用户注册/登录、号码验证的体验，提高安全性。
//! 本SDK非官方SDK。
//!
//! ## 应用场景
//! * 注册
//! * 登录
//! * 二次验证
//!
//! # Example
//! 提交loginToken，验证后返回手机号码
//! ```rust, no_run
//! use jiguang_certification::JiGuang;
//! use jiguang_certification::PrivateKey;
//!
//! let jiguang = JiGuang::new("12345", "qwerty");
//!
//! let s = r#"
//! -----BEGIN PRIVATE KEY-----
//! MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBALx3lux8fiSk8+2f
//! au7sdQtaAu7GGEIr5juBy6nXq4K+73rN8HPMxEpmg6SnGMFzDL+UlUH9JoRuW7D4
//! qi7mHmtiOhLXbTSNpPPM/It9gHXYDMV1bD4Z6l3gafttaoim1JGfCqlXQAjzVm1u
//! -----END PRIVATE KEY-----
//! "#;
//!
//! let private_key = PrivateKey::from_str(s).unwrap();
//!
//! let phone = jiguang.login_token_verify("login_token", &private_key).await.unwrap();
//!
//! println!("{}", phone);
//! ```
//!
//! 提交手机号码和token，验证是否一致
//! ```rust, no_run
//! use jiguang_certification::JiGuang;
//! use jiguang_certification::VerifyType;
//!
//! let jiguang = JiGuang::new("12345", "qwerty");
//!
//! let result = jiguang.verify("token", "phone", VerifyType::APP).await.unwrap();
//!
//! assert!(result);
//! ```
//!
//! ## 快速开始
//!
//! ### 如果您初次使用极光开发者的产品
//! 1. 进入极光官网注册开发者账号
//! 2. 进入管理控制台，创建应用程序，得到 AppKey（SDK与服务器端通过AppKey互相识别）
//! 3. 完成开发者认证
//! 4. 选择要开通极光认证的应用程序，在应用设置中点击左侧的［极光认证］按钮。在应用介绍中填写［应用分类］ 、［应用简介］。Android应用需要填写［应用包名］和［应用签名］，iOS应用需要填写［Bundle ID］，填写完成后点击［提交审核］，如果应用程序同时具有Android和iOS版本，需要在此页面分别提交申请
//! 5. 若开发者需要使用一键登录功能，待步骤4完成后，请在［一键登录设置］中选择要开通一键登录的平台，并填写RSA加密公钥，点击［提交审核］按钮
//! 6. 待审核通过后，可通过本SDK运行应用程序
//!
//! ### 如果您已经是极光开发者
//! 1. 完成开发者认证
//! 2. 选择要开通极光认证的应用程序，在应用设置中点击左侧的［极光认证］按钮。在应用介绍中填写［应用分类］ 、［应用简介］。Android应用需要填写［应用包名］和［应用签名］，iOS应用需要填写［Bundle ID］，填写完成后点击［提交审核］，如果应用程序同时具有Android和iOS版本，需要在此页面分别提交申请
//! 3. 若开发者需要使用一键登录功能，待步骤4完成后，请在［一键登录设置］中选择要开通一键登录的平台，并填写RSA加密公钥，点击［提交审核］按钮
//! 4. 待审核通过后，可通过本SDK运行应用程序
//!
//!
//!
//!

mod error;
mod private_key;

use serde::Deserialize;
use std::collections::HashMap;

pub use error::Error;
pub use private_key::PrivateKey;

/// 验证手机号码和token是否一致的请求类型
pub enum VerifyType {
    /// Android，iOS客户端请求类型
    APP,
    /// Web客户端请求类型
    WEB,
}

/// 极光认证返回类型
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct JiGuangLoginToken {
    // 流水号，请求出错时可能为空
    _id: Option<u128>,
    // 极光返回码
    code: u32,
    // 极光返回码说明
    _content: String,
    // 开发者自定义的id，若请求时为空返回为空
    _ex_id: Option<String>,
    // 加密后的手机号码，需用配置在极光的公钥对应的私钥解密
    phone: Option<String>,
}

/// 极光构造器
#[derive(Debug, PartialEq)]
pub struct JiGuang<'r> {
    app_key: &'r str,
    master_secret: &'r str,
}

impl<'r> JiGuang<'r> {
    /// 初始化极光
    ///
    /// 使用极光控制台获取的AppKey和MasterSecret初始化
    ///
    /// # Example
    ///
    /// ```rust
    /// use jiguang_certification::JiGuang;
    ///
    /// let jiguang = JiGuang::new("12345", "qwerty");
    ///
    /// assert_eq!(jiguang, JiGuang { app_key: "12345", master_secret: "qwerty"});
    /// ```
    pub fn new(app_key: &'r str, master_secret: &'r str) -> Self {
        Self {
            app_key,
            master_secret,
        }
    }

    /// 提交loginToken，验证后返回手机号码
    /// * loginToken: 认证SDK获取到的loginToken
    /// * private_key: 验证手机号码和token是否一致的请求类型
    ///
    /// # Example
    /// ```rust, no_run
    /// use jiguang_certification::JiGuang;
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
    /// let private_key = PrivateKey::from_str(s).unwrap();
    ///
    /// let jiguang = JiGuang::new("12345", "qwerty");
    ///
    /// let phone = jiguang.login_token_verify("login_token", &private_key).await.unwrap();
    ///
    /// println!("{}", phone);
    /// ```
    pub async fn login_token_verify(
        &self,
        login_token: &str,
        private_key: &PrivateKey,
    ) -> Result<String, Error> {
        let key = match rsa::RSAPrivateKey::from_pkcs8(&private_key.key) {
            Ok(key) => key,
            Err(e) => return Err(Error::new(1, format!("{:?}", e))),
        };

        let client = reqwest::Client::new();
        let mut map = HashMap::new();
        map.insert("loginToken", login_token);

        let jiguang_error = JiGuang::get_jiguang_err();

        let jiguang_token = match client
            .post("https://api.verification.jpush.cn/v1/web/loginTokenVerify")
            .basic_auth(self.app_key, Some(self.master_secret))
            .json(&map)
            .send()
            .await
        {
            Ok(resp) => match resp.json::<JiGuangLoginToken>().await {
                Ok(token) => match token.code {
                    8000 => token,
                    error_code if jiguang_error.contains_key(&error_code) => {
                        return Err(Error::new(
                            error_code,
                            format!("{}", jiguang_error.get(&error_code).unwrap()),
                        ))
                    }
                    _ => return Err(Error::new(4, String::from(""))),
                },
                Err(e) => return Err(Error::new(3, format!("{:?}", e))),
            },
            Err(e) => return Err(Error::new(2, format!("{:?}", e))),
        };

        let phone = match key.decrypt(
            rsa::PaddingScheme::new_pkcs1v15_encrypt(),
            &base64::decode(jiguang_token.phone.unwrap()).unwrap(),
        ) {
            Ok(phone) => phone,
            Err(e) => return Err(Error::new(5, format!("{:?}", e))),
        };

        Ok(String::from_utf8(phone).unwrap())
    }

    /// 验证token和手机号码是否一致
    /// * token: 运营商下发的token
    /// * phone: 待认证的手机号码
    /// * verify_type: 验证手机号码和token是否一致的请求类型
    ///
    /// # Example
    /// ```rust, no_run
    /// use jiguang_certification::JiGuang;
    /// use jiguang_certification::VerifyType;
    ///
    /// let jiguang = JiGuang::new("12345", "qwerty");
    ///
    /// let result = jiguang.verify("token", "phone", VerifyType::APP).await.unwrap();
    ///
    /// assert!(result);
    /// ```
    pub async fn verify(
        &self,
        token: &str,
        phone: &str,
        verify_type: VerifyType,
    ) -> Result<bool, Error> {
        let client = reqwest::Client::new();
        let mut map = HashMap::new();
        map.insert("token", token);
        map.insert("phone", phone);

        let jiguang_error = JiGuang::get_jiguang_err();

        match client
            .post(match verify_type {
                VerifyType::APP => "https://api.verification.jpush.cn/v1/web/verify",
                VerifyType::WEB => "https://api.verification.jpush.cn/v1/web/h5/verify",
            })
            .basic_auth(self.app_key, Some(self.master_secret))
            .json(&map)
            .send()
            .await
        {
            Ok(resp) => match resp.json::<JiGuangLoginToken>().await {
                Ok(token) => match token.code {
                    9000 => return Ok(true),
                    error_code if jiguang_error.contains_key(&error_code) => {
                        return Err(Error::new(
                            error_code,
                            format!("{}", jiguang_error.get(&error_code).unwrap()),
                        ))
                    }
                    _ => return Err(Error::new(4, String::from(""))),
                },
                Err(e) => return Err(Error::new(3, format!("{:?}", e))),
            },
            Err(e) => return Err(Error::new(2, format!("{:?}", e))),
        }
    }

    // 获取极光错误信息
    fn get_jiguang_err() -> HashMap<u32, &'static str> {
        let mut jiguang_error: HashMap<u32, &'static str> = HashMap::new();
        jiguang_error.insert(8001, "JiGuang: get phone fail; 获取一键登录的手机号码失败");
        jiguang_error.insert(9001, "JiGuang: verify not consistent; 手机号验证不一致");
        jiguang_error.insert(9002, "JiGuang: unknown result; 结果未知");
        jiguang_error.insert(
            9003,
            "JiGuang: token expired or not exist; token失效或不存在",
        );
        jiguang_error.insert(9004, "JiGuang: config not found; 获取配置失败");
        jiguang_error.insert(
            9005,
            "verify interval is less than the minimum limit; 同一号码连续两次提交认证间隔过短",
        );
        jiguang_error.insert(
            9006,
            "JiGuang: frequency of verifying single number is beyond the maximum limit; 同一号码自然日内认证次数超过限制");
        jiguang_error.insert(
            9007,
            "beyond daily frequency limit; appKey自然日认证消耗超过限制",
        );
        jiguang_error.insert(9010, "JiGuang: miss auth; 缺少鉴权信息");
        jiguang_error.insert(9011, "JiGuang: auth failed; 鉴权失败");
        jiguang_error.insert(9012, "JiGuang: parameter invalid; 参数错误");
        jiguang_error.insert(
            9013,
            "request method not supported; 请求方式错误，请用POST请求",
        );
        jiguang_error.insert(9014, "JiGuang: appkey is blocked; 功能被禁用");
        jiguang_error.insert(
            9015,
            "http media type not supported; 请检查Content type类型",
        );
        jiguang_error.insert(9018, "JiGuang: appKey no money; 账户余额不足");
        jiguang_error.insert(
            9020,
            "decrypt token failed; 解密token失败，请检查appkey是否正确",
        );
        jiguang_error.insert(
            9021,
            "JiGuang: token invalid; token非法，请确认token获取正确",
        );
        jiguang_error.insert(
            9022,
            "encrypt mobile failed; 加密号码失败，请检查RSA公钥是否正确",
        );
        jiguang_error.insert(9031, "JiGuang: not validate user; 未开通认证服务");
        jiguang_error.insert(9099, "JiGuang: bad server; 服务器未知错误");
        jiguang_error.insert(9200, "JiGuang: success; 一键登录开通成功");
        jiguang_error.insert(9202, "JiGuang: appKey not exists; appKey不存在");
        jiguang_error.insert(9203, "JiGuang: signOnce opened already; 一键登录已开通");
        jiguang_error.insert(9301, "JiGuang: signOnce opened failed; 一键登录开通失败");

        jiguang_error
    }
}

#[cfg(test)]
mod tests {
    use super::{JiGuang, VerifyType};
    use crate::PrivateKey;

    #[test]
    fn it_works() {
        let jiguang = JiGuang::new("12345", "qwerty");

        assert_eq!(
            jiguang,
            JiGuang {
                app_key: "12345",
                master_secret: "qwerty"
            }
        );
    }

    #[tokio::test]
    async fn login_token() {
        let s = r#"
-----BEGIN PRIVATE KEY-----
MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBALx3lux8fiSk8+2f
au7sdQtaAu7GGEIr5juBy6nXq4K+73rN8HPMxEpmg6SnGMFzDL+UlUH9JoRuW7D4
qi7mHmtiOhLXbTSNpPPM/It9gHXYDMV1bD4Z6l3gafttaoim1JGfCqlXQAjzVm1u
-----END PRIVATE KEY-----"#;
        let private_key = PrivateKey::from_str(s).unwrap();

        let phone = JiGuang::new("12345", "qwerty")
            .login_token_verify("login_token", &private_key)
            .await
            .unwrap();

        assert_eq!(phone.as_str(), "xxxxxxxx");
    }

    #[tokio::test]
    async fn verify() {
        let res = JiGuang::new("12345", "qwerty")
            .verify("token", "xxxxxxxx", VerifyType::APP)
            .await
            .unwrap();

        assert!(res);
    }
}
