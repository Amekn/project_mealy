use crate::ProviderCredentialReference;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, net::IpAddr};
use thiserror::Error;
use url::Url;

const MAXIMUM_ALLOWED_DOMAINS: usize = 128;
const MAXIMUM_ALLOWED_ORIGINS: usize = 64;

/// Non-secret, explicitly activated authority for bounded web search and fetch tools.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WebAccessConfig {
    /// Whether any web adapter may be initialized.
    #[serde(default)]
    pub enabled: bool,
    /// Allows public HTTPS destinations after DNS/IP enforcement.
    #[serde(default)]
    pub allow_public_internet: bool,
    /// Exact lowercase DNS suffix grants used when broad public access is disabled.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_domains: Vec<String>,
    /// Exact canonical origins; literal-loopback HTTP is permitted only through this list.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_origins: Vec<String>,
    /// Optional bounded search service.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub search: Option<WebSearchConfig>,
}

/// Configured search API normalized behind web.search.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum WebSearchConfig {
    /// Brave Search web endpoint using a brokered subscription token.
    Brave {
        /// Full API endpoint, normally the Brave web-search endpoint.
        base_url: String,
        /// Opaque startup-resolved credential reference.
        credential: ProviderCredentialReference,
    },
}

/// Invalid web authority configuration.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum WebAccessConfigError {
    /// A transport, authority, domain, origin, search, or credential constraint failed.
    #[error("web access configuration is invalid")]
    Invalid,
}

impl WebAccessConfig {
    /// Validates canonical, bounded, and usable authority.
    ///
    /// # Errors
    ///
    /// Returns Invalid for any malformed or ambiguous authority.
    pub fn validate(&self) -> Result<(), WebAccessConfigError> {
        if !self.enabled {
            return if !self.allow_public_internet
                && self.allowed_domains.is_empty()
                && self.allowed_origins.is_empty()
                && self.search.is_none()
            {
                Ok(())
            } else {
                Err(WebAccessConfigError::Invalid)
            };
        }
        if self.allowed_domains.len() > MAXIMUM_ALLOWED_DOMAINS
            || self.allowed_origins.len() > MAXIMUM_ALLOWED_ORIGINS
            || (!self.allow_public_internet
                && self.allowed_domains.is_empty()
                && self.allowed_origins.is_empty()
                && self.search.is_none())
        {
            return Err(WebAccessConfigError::Invalid);
        }
        let mut domains = BTreeSet::new();
        if self
            .allowed_domains
            .iter()
            .any(|domain| !valid_domain(domain) || !domains.insert(domain.as_str()))
        {
            return Err(WebAccessConfigError::Invalid);
        }
        let mut origins = BTreeSet::new();
        if self.allowed_origins.iter().any(|origin| {
            canonical_allowed_origin(origin).as_deref() != Some(origin.as_str())
                || !origins.insert(origin.as_str())
        }) {
            return Err(WebAccessConfigError::Invalid);
        }
        if self
            .search
            .as_ref()
            .is_some_and(|search| search.validate().is_err())
        {
            return Err(WebAccessConfigError::Invalid);
        }
        Ok(())
    }

    /// Exact opaque destination claims copied into each newly promoted task.
    #[must_use]
    pub fn capability_network_destinations(&self) -> BTreeSet<String> {
        if !self.enabled {
            return BTreeSet::new();
        }
        let mut destinations = BTreeSet::new();
        if self.allow_public_internet {
            destinations.insert("public:https".to_owned());
        }
        destinations.extend(
            self.allowed_domains
                .iter()
                .map(|domain| format!("domain:{domain}")),
        );
        destinations.extend(
            self.allowed_origins
                .iter()
                .map(|origin| format!("origin:{origin}")),
        );
        if let Some(search) = &self.search {
            destinations.insert(format!("search:{}", search.base_url()));
        }
        destinations
    }

    /// Opaque credential claims copied into each newly promoted task.
    #[must_use]
    pub fn capability_secret_references(&self) -> BTreeSet<String> {
        self.search
            .as_ref()
            .map(WebSearchConfig::credential)
            .map(|credential| BTreeSet::from([credential.capability_reference()]))
            .unwrap_or_default()
    }
}

impl WebSearchConfig {
    /// Validates endpoint transport and the opaque credential reference.
    ///
    /// # Errors
    ///
    /// Returns Invalid when either boundary is malformed.
    pub fn validate(&self) -> Result<(), WebAccessConfigError> {
        match self {
            Self::Brave {
                base_url,
                credential,
            } => {
                if validated_endpoint(base_url).is_some() && credential.validate().is_ok() {
                    Ok(())
                } else {
                    Err(WebAccessConfigError::Invalid)
                }
            }
        }
    }

    /// Full validated search endpoint.
    #[must_use]
    pub fn base_url(&self) -> &str {
        match self {
            Self::Brave { base_url, .. } => base_url,
        }
    }

    /// Opaque search credential reference.
    #[must_use]
    pub const fn credential(&self) -> &ProviderCredentialReference {
        match self {
            Self::Brave { credential, .. } => credential,
        }
    }
}

/// Returns whether one canonical URL is within the persisted destination claims.
#[must_use]
pub fn web_url_authorized_by_capabilities(value: &str, destinations: &BTreeSet<String>) -> bool {
    let Ok(url) = Url::parse(value) else {
        return false;
    };
    if !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.host_str().is_none()
    {
        return false;
    }
    let origin = url.origin().ascii_serialization();
    if destinations.contains(&format!("origin:{origin}")) {
        return url.scheme() == "https"
            || url.scheme() == "http"
                && url
                    .host_str()
                    .and_then(|host| host.parse::<IpAddr>().ok())
                    .is_some_and(|address| address.is_loopback());
    }
    if url.scheme() != "https" || url.port().is_some() {
        return false;
    }
    let Some(host) = url.host_str().map(str::to_ascii_lowercase) else {
        return false;
    };
    destinations.contains("public:https")
        || destinations.iter().any(|destination| {
            destination
                .strip_prefix("domain:")
                .is_some_and(|domain| host == domain || host.ends_with(&format!(".{domain}")))
        })
}

fn canonical_allowed_origin(value: &str) -> Option<String> {
    if value.is_empty() || value.len() > 2_048 || value.trim() != value {
        return None;
    }
    let url = Url::parse(value).ok()?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return None;
    }
    let origin = url.origin().ascii_serialization();
    let local = url
        .host_str()
        .and_then(|host| host.parse::<IpAddr>().ok())
        .is_some_and(|address| address.is_loopback());
    if url.scheme() == "https" || url.scheme() == "http" && local {
        Some(origin)
    } else {
        None
    }
}

fn validated_endpoint(value: &str) -> Option<bool> {
    if value.is_empty() || value.len() > 2_048 || value.trim() != value {
        return None;
    }
    let url = Url::parse(value).ok()?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.host_str().is_none()
    {
        return None;
    }
    let local = url
        .host_str()
        .and_then(|host| host.parse::<IpAddr>().ok())
        .is_some_and(|address| address.is_loopback());
    (url.scheme() == "https" || url.scheme() == "http" && local).then_some(local)
}

fn valid_domain(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value == value.to_ascii_lowercase()
        && !value.starts_with('.')
        && !value.ends_with('.')
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::{WebAccessConfig, WebSearchConfig, web_url_authorized_by_capabilities};
    use crate::{ProviderCredentialReference, WebAccessConfigError};

    #[test]
    fn authority_is_canonical_explicit_and_transport_safe() {
        let config = WebAccessConfig {
            enabled: true,
            allow_public_internet: false,
            allowed_domains: vec!["example.com".to_owned()],
            allowed_origins: vec!["http://127.0.0.1:8080".to_owned()],
            search: Some(WebSearchConfig::Brave {
                base_url: "https://api.search.brave.com/res/v1/web/search".to_owned(),
                credential: ProviderCredentialReference::Broker {
                    secret_id: "brave-search".to_owned(),
                },
            }),
        };
        assert!(config.validate().is_ok());
        let destinations = config.capability_network_destinations();
        assert!(web_url_authorized_by_capabilities(
            "https://docs.example.com/guide",
            &destinations
        ));
        assert!(web_url_authorized_by_capabilities(
            "http://127.0.0.1:8080/test",
            &destinations
        ));
        assert!(!web_url_authorized_by_capabilities(
            "http://127.0.0.1:8081/test",
            &destinations
        ));
        assert!(!web_url_authorized_by_capabilities(
            "https://notexample.com/",
            &destinations
        ));

        let latent = WebAccessConfig {
            enabled: false,
            allowed_domains: vec!["example.com".to_owned()],
            ..WebAccessConfig::default()
        };
        assert_eq!(latent.validate(), Err(WebAccessConfigError::Invalid));
    }
}
