# 极光认证Rust SDK

[![Crates.io][crates-badge]][crates-url]
[![MIT licensed][mit-badge]][mit-url]

[crates-badge]: https://img.shields.io/badge/crates-0.1-blue
[crates-url]: https://crates.io/crates/jiguang-certification
[mit-badge]: https://img.shields.io/badge/license-MIT-blue.svg
[mit-url]: https://opensource.org/licenses/MIT

极光认证整合了三大运营商的网关认证能力，为开发者提供了一键登录和号码认证功能，优化用户注册/登录、号码验证的体验，提高安全性。

本SDK非官方SDK。

## 应用场景
* 注册
* 登录
* 二次验证

## 添加依赖

```yaml
[dependencies]
jiguang_certification = "0.1"
```

# Example
提交loginToken，验证后返回手机号码
```rust, no_run
use jiguang_certification::JiGuang;
use jiguang_certification::PrivateKey;

let jiguang = JiGuang::new("12345", "qwerty");

let s = r#"
-----BEGIN PRIVATE KEY-----
MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBALx3lux8fiSk8+2f
au7sdQtaAu7GGEIr5juBy6nXq4K+73rN8HPMxEpmg6SnGMFzDL+UlUH9JoRuW7D4
qi7mHmtiOhLXbTSNpPPM/It9gHXYDMV1bD4Z6l3gafttaoim1JGfCqlXQAjzVm1u
-----END PRIVATE KEY-----
"#;

let private_key = PrivateKey::from_str(s).unwrap();

let phone = jiguang.login_token_verify("login_token", &private_key).await.unwrap();

println!("{}", phone);
```

提交手机号码和token，验证是否一致
```rust, no_run
use jiguang_certification::JiGuang;
use jiguang_certification::VerifyType;

let jiguang = JiGuang::new("12345", "qwerty");

let result = jiguang.verify("token", "phone", VerifyType::APP).await.unwrap();

assert!(result);
```

## 版权声明

[MIT](https://opensource.org/licenses/MIT)

Copyright (c) 2021-present, Yang (Echo) Li