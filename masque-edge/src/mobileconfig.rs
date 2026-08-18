use uuid::Uuid;

pub struct ProfileOptions {
    pub name: String,
    pub http3_url: String,
    pub http2_url: Option<String>,
    pub bearer_token: String,
    pub match_domains: Vec<String>,
}

pub fn render(options: &ProfileOptions) -> String {
    let profile_uuid = Uuid::new_v4();
    let relay_uuid = Uuid::new_v4();
    let name = xml_escape(&options.name);
    let http3_url = xml_escape(&options.http3_url);
    let token = xml_escape(&format!("Bearer {}", options.bearer_token));
    let http2 = options.http2_url.as_ref().map(|url| {
        format!(
            "\n                    <key>HTTP2RelayURL</key>\n                    <string>{}</string>",
            xml_escape(url)
        )
    }).unwrap_or_default();
    let match_domains = if options.match_domains.is_empty() {
        String::new()
    } else {
        let domains = options
            .match_domains
            .iter()
            .map(|domain| format!("\n                <string>{}</string>", xml_escape(domain)))
            .collect::<String>();
        format!("\n            <key>MatchDomains</key>\n            <array>{domains}\n            </array>")
    };

    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>PayloadDisplayName</key>
            <string>{name}</string>
            <key>PayloadIdentifier</key>
            <string>com.netrunner.relay.{relay_uuid}</string>
            <key>PayloadType</key>
            <string>com.apple.relay.managed</string>
            <key>PayloadUUID</key>
            <string>{relay_uuid}</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>Relays</key>
            <array>
                <dict>
                    <key>HTTP3RelayURL</key>
                    <string>{http3_url}</string>{http2}
                    <key>AdditionalHTTPHeaderFields</key>
                    <dict>
                        <key>Authorization</key>
                        <string>{token}</string>
                    </dict>
                </dict>
            </array>{match_domains}
        </dict>
    </array>
    <key>PayloadDisplayName</key>
    <string>{name}</string>
    <key>PayloadIdentifier</key>
    <string>com.netrunner.profile.{profile_uuid}</string>
    <key>PayloadOrganization</key>
    <string>Netrunner</string>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>{profile_uuid}</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
</dict>
</plist>
"#
    )
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_device_profile_omits_match_domains() {
        let profile = render(&ProfileOptions {
            name: "Netrunner & Test".into(),
            http3_url: "https://relay.example/udp/{target_host}/{target_port}/".into(),
            http2_url: None,
            bearer_token: "a<b".into(),
            match_domains: vec![],
        });
        assert!(profile.contains("com.apple.relay.managed"));
        assert!(profile.contains("Netrunner &amp; Test"));
        assert!(profile.contains("Bearer a&lt;b"));
        assert!(!profile.contains("<key>MatchDomains</key>"));
    }

    #[test]
    fn split_profile_contains_domains_and_h2_fallback() {
        let profile = render(&ProfileOptions {
            name: "Relay".into(),
            http3_url: "https://relay.example/udp/{target_host}/{target_port}/".into(),
            http2_url: Some("https://relay.example/udp/{target_host}/{target_port}/".into()),
            bearer_token: "secret".into(),
            match_domains: vec!["example.com".into()],
        });
        assert!(profile.contains("<key>HTTP2RelayURL</key>"));
        assert!(profile.contains("<key>MatchDomains</key>"));
        assert!(profile.contains("<string>example.com</string>"));
    }
}
