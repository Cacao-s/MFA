//! `otpauth://` URI parsing and generation.
//!
//! Follows the de-facto Key Uri Format that Google Authenticator established,
//! and is deliberately forgiving about what real-world issuers emit: mixed
//! case, `SHA-256`, padded Base32, a label with no issuer prefix.

use core::fmt;

use percent_encoding::{percent_decode_str, utf8_percent_encode, AsciiSet, CONTROLS};

use crate::error::{Error, Result};
use crate::secret::Secret;
use crate::totp::{Algorithm, TotpParams, DEFAULT_DIGITS, DEFAULT_PERIOD};

/// Characters we percent-encode inside one label component or one query value.
/// `:` is in the set because a raw colon separates issuer from account.
const COMPONENT: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'&')
    .add(b'+')
    .add(b'/')
    .add(b':')
    .add(b'<')
    .add(b'=')
    .add(b'>')
    .add(b'?')
    .add(b'@')
    .add(b'\\')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}');

/// One account as described by an `otpauth://` URI.
///
/// This is also the shape a migration import and a manual entry produce, so
/// everything that can add an account converges on one type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtpauthUri {
    /// The service, e.g. `GitHub`. `None` when the URI carried a bare label.
    pub issuer: Option<String>,
    /// The account at that service, e.g. `alice@example.com`.
    pub account: String,
    pub secret: Secret,
    pub params: TotpParams,
}

impl OtpauthUri {
    /// Parses an `otpauth://totp/...` URI.
    pub fn parse(uri: &str) -> Result<Self> {
        let rest = strip_scheme(uri, "otpauth").ok_or(Error::NotOtpauthUri)?;

        // `authority[/path][?query]`
        let (location, query) = match rest.split_once('?') {
            Some((location, query)) => (location, query),
            None => (rest, ""),
        };
        let (otp_type, path) = match location.split_once('/') {
            Some((otp_type, path)) => (otp_type, path),
            None => (location, ""),
        };

        if !otp_type.eq_ignore_ascii_case("totp") {
            return Err(Error::UnsupportedOtpType(otp_type.to_ascii_lowercase()));
        }

        let (label_issuer, account) = parse_label(path)?;

        let mut secret = None;
        let mut param_issuer = None;
        let mut algorithm = Algorithm::default();
        let mut digits = DEFAULT_DIGITS;
        let mut period = DEFAULT_PERIOD;

        for (key, value) in query_pairs(query) {
            let key = key?;
            let value = value?;
            match key.to_ascii_lowercase().as_str() {
                "secret" => secret = Some(Secret::from_base32(&value)?),
                "issuer" if !value.is_empty() => param_issuer = Some(value),
                "algorithm" if !value.is_empty() => algorithm = value.parse()?,
                "digits" if !value.is_empty() => {
                    digits = value
                        .parse()
                        .map_err(|_| Error::InvalidParameter(value.clone(), "digits"))?;
                }
                "period" if !value.is_empty() => {
                    period = value
                        .parse()
                        .map_err(|_| Error::InvalidParameter(value.clone(), "period"))?;
                }
                // `counter`, `image` and anything else an issuer invented are
                // not ours to interpret.
                _ => {}
            }
        }

        Ok(Self {
            // The `issuer` parameter wins: the label prefix is the legacy
            // channel and is the one that gets truncated or mangled.
            issuer: param_issuer.or(label_issuer),
            account,
            secret: secret.ok_or(Error::MissingSecret)?,
            params: TotpParams::new(algorithm, digits, period)?,
        })
    }

    /// Renders the URI back out, for re-export or for showing a QR code.
    pub fn to_uri_string(&self) -> String {
        let account = encode(&self.account);
        let label = match &self.issuer {
            Some(issuer) => format!("{}:{}", encode(issuer), account),
            None => account,
        };

        let mut uri = format!(
            "otpauth://totp/{label}?secret={secret}",
            secret = self.secret.to_base32()
        );
        if let Some(issuer) = &self.issuer {
            uri.push_str("&issuer=");
            uri.push_str(&encode(issuer));
        }
        uri.push_str("&algorithm=");
        uri.push_str(self.params.algorithm.as_str());
        uri.push_str("&digits=");
        uri.push_str(&self.params.digits.to_string());
        uri.push_str("&period=");
        uri.push_str(&self.params.period.to_string());
        uri
    }

    /// What the account list shows: `Issuer (account)`, or just one of them.
    pub fn display_name(&self) -> String {
        match (&self.issuer, self.account.is_empty()) {
            (Some(issuer), false) => format!("{issuer} ({})", self.account),
            (Some(issuer), true) => issuer.clone(),
            (None, _) => self.account.clone(),
        }
    }
}

impl fmt::Display for OtpauthUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_uri_string())
    }
}

/// Returns everything after `scheme://`, case-insensitively.
pub(crate) fn strip_scheme<'a>(uri: &'a str, scheme: &str) -> Option<&'a str> {
    let prefix_len = scheme.len() + 3;
    let (prefix, rest) = uri.split_at_checked(prefix_len)?;
    let (name, separator) = prefix.split_at(scheme.len());
    (name.eq_ignore_ascii_case(scheme) && separator == "://").then_some(rest)
}

/// Splits a percent-encoded label into its optional issuer and its account.
fn parse_label(path: &str) -> Result<(Option<String>, String)> {
    let label = decode(path)?;
    let label = label.trim();
    if label.is_empty() {
        return Err(Error::MissingLabel);
    }

    match label.split_once(':') {
        Some((issuer, account)) => {
            let issuer = issuer.trim();
            let account = account.trim().to_owned();
            if issuer.is_empty() {
                Ok((None, account))
            } else {
                Ok((Some(issuer.to_owned()), account))
            }
        }
        None => Ok((None, label.to_owned())),
    }
}

/// Iterates `key=value` pairs, percent-decoding both sides.
fn query_pairs(query: &str) -> impl Iterator<Item = (Result<String>, Result<String>)> + '_ {
    query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| match pair.split_once('=') {
            Some((key, value)) => (decode(key), decode(value)),
            None => (decode(pair), Ok(String::new())),
        })
}

fn decode(text: &str) -> Result<String> {
    percent_decode_str(text)
        .decode_utf8()
        .map(|decoded| decoded.into_owned())
        .map_err(|_| Error::InvalidPercentEncoding)
}

fn encode(text: &str) -> String {
    utf8_percent_encode(text, COMPONENT).to_string()
}
