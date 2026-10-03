//! URL parsing and response rewriting for the browser search gateway.

use lol_html::{
    element,
    html_content::{ContentType, Element},
    HandlerResult, HtmlRewriter, Settings,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use url::{Host, Url};

pub(crate) struct Target {
    pub(crate) url: Url,
    pub(crate) connect_addr: String,
    pub(crate) host_header: String,
    pub(crate) pool_key: String,
    pub(crate) tls: bool,
}

pub(crate) fn gateway_url(url: &Url, proxy_domain: &str) -> String {
    let mut authority = match url.host() {
        Some(Host::Ipv6(address)) => format!("[{address}]"),
        Some(host) => host.to_string(),
        None => String::new(),
    };
    if let Some(port) = url.port() {
        authority.push(':');
        authority.push_str(&port.to_string());
    }
    let host: String = url::form_urlencoded::byte_serialize(authority.as_bytes()).collect();
    let query = url
        .query()
        .map(|query| format!("?{query}"))
        .unwrap_or_default();
    let fragment = url
        .fragment()
        .map(|fragment| format!("#{fragment}"))
        .unwrap_or_default();
    format!(
        "https://{proxy_domain}/browse/{}/{host}{}{query}{fragment}",
        url.scheme(),
        url.path()
    )
}

pub(crate) fn search_redirect(query: &str) -> Option<Url> {
    let target = url::form_urlencoded::parse(query.as_bytes())
        .find_map(|(key, value)| (key == "uddg").then(|| value.into_owned()))?;
    let url = Url::parse(&target).ok()?;
    is_http_url(&url).then_some(url)
}

pub(crate) async fn parse_target(path_and_query: &str) -> Result<Target, String> {
    resolve_target(target_url_from_gateway(path_and_query)?).await
}

pub(crate) async fn parse_referer_target(
    referer: &str,
    request_uri: &str,
    proxy_domain: &str,
) -> Result<Target, String> {
    let referer = Url::parse(referer).map_err(|error| format!("invalid referrer: {error}"))?;
    if !referer
        .host_str()
        .is_some_and(|host| host.eq_ignore_ascii_case(proxy_domain))
    {
        return Err("missing same-origin browse referrer".into());
    }
    let gateway_path = match referer.query() {
        Some(query) => format!("{}?{query}", referer.path()),
        None => referer.path().to_string(),
    };
    let source = target_url_from_gateway(&gateway_path)?;
    let target = source
        .join(request_uri)
        .map_err(|error| format!("invalid relative browse URL: {error}"))?;
    resolve_target(target).await
}

fn target_url_from_gateway(path_and_query: &str) -> Result<Url, String> {
    let (path, query) = path_and_query
        .split_once('?')
        .map_or((path_and_query, None), |(path, query)| (path, Some(query)));
    let tail = path
        .strip_prefix("/browse/")
        .ok_or_else(|| "missing browse target".to_string())?;
    let mut parts = tail.splitn(3, '/');
    let scheme = parts.next().unwrap_or_default();
    let encoded_host = parts.next().unwrap_or_default();
    let target_path = parts.next().unwrap_or_default();
    let host = url::form_urlencoded::parse(format!("host={encoded_host}").as_bytes())
        .next()
        .map(|(_, host)| host.into_owned())
        .ok_or_else(|| "missing browse hostname".to_string())?;
    if scheme != "http" && scheme != "https" {
        return Err("only public HTTP(S) URLs are allowed".into());
    }
    let query = query.map(|query| format!("?{query}")).unwrap_or_default();
    let target_url = format!("{scheme}://{host}/{target_path}{query}");
    Url::parse(&target_url).map_err(|error| format!("invalid browse URL: {error}"))
}

async fn resolve_target(url: Url) -> Result<Target, String> {
    if !is_http_url(&url) || !url.username().is_empty() || url.password().is_some() {
        return Err("only public HTTP(S) URLs without credentials are allowed".into());
    }

    let tls = url.scheme() == "https";
    let port = url
        .port_or_known_default()
        .ok_or_else(|| "URL has no supported port".to_string())?;
    if (tls && port != 443) || (!tls && port != 80) {
        return Err("only ports 80 and 443 are allowed".into());
    }

    let host = match url
        .host()
        .ok_or_else(|| "URL has no hostname".to_string())?
    {
        Host::Domain(domain) => domain.to_ascii_lowercase(),
        Host::Ipv4(address) => address.to_string(),
        Host::Ipv6(address) => format!("[{address}]"),
    };
    let socket_addrs = if let Ok(ip) = host.trim_matches(['[', ']']).parse::<IpAddr>() {
        vec![SocketAddr::new(ip, port)]
    } else {
        tokio::net::lookup_host((host.as_str(), port))
            .await
            .map_err(|error| format!("resolving {host}: {error}"))?
            .collect()
    };
    let public_addr = socket_addrs
        .into_iter()
        .find(|address| is_public_ip(address.ip()))
        .ok_or_else(|| "hostname did not resolve to a public IP address".to_string())?;
    let connect_addr = match public_addr {
        SocketAddr::V4(address) => address.to_string(),
        SocketAddr::V6(address) => format!("[{}]:{}", address.ip(), address.port()),
    };
    let default_port = if tls { 443 } else { 80 };
    let host_header = if port == default_port {
        host.clone()
    } else {
        format!("{host}:{port}")
    };
    let pool_key = format!("{}://{}:{}", url.scheme(), host, port);

    Ok(Target {
        url,
        connect_addr,
        host_header,
        pool_key,
        tls,
    })
}

pub(crate) fn rewrite_html(
    html: &[u8],
    base_url: &Url,
    proxy_domain: &str,
    relay_domain: &str,
) -> Result<Vec<u8>, String> {
    let mut output = Vec::with_capacity(html.len());
    let bootstrap = BROWSER_FETCH_BOOTSTRAP.replace(
        "__BROWSER_PROXY_ORIGIN__",
        &format!("https://{proxy_domain}"),
    );
    let mut rewriter = HtmlRewriter::new(
        Settings {
            element_content_handlers: vec![
                element!("head", |el| {
                    el.prepend(&bootstrap, ContentType::Html);
                    Ok(())
                }),
                element!("base", |el| {
                    el.remove();
                    Ok(())
                }),
                element!("a[href], area[href]", |el| rewrite_attr(el, "href", base_url, proxy_domain, relay_domain)),
                element!("link[href], script[src], img[src], source[src], video[src], audio[src], iframe[src], frame[src], embed[src], input[src], track[src], object[data]", |el| {
                    let name = if el.get_attribute("src").is_some() { "src" } else { "data" };
                    rewrite_attr(el, name, base_url, proxy_domain, relay_domain)
                }),
                element!("img[srcset], source[srcset]", |el| {
                    if let Some(value) = el.get_attribute("srcset") {
                        let rewritten = rewrite_srcset(&value, base_url, proxy_domain, relay_domain);
                        el.set_attribute("srcset", &rewritten)?;
                    }
                    Ok(())
                }),
                element!("[style]", |el| {
                    if let Some(value) = el.get_attribute("style") {
                        if let Some(rewritten) = rewrite_css(value.as_bytes(), base_url, proxy_domain) {
                            let rewritten = String::from_utf8_lossy(&rewritten);
                            el.set_attribute("style", &rewritten)?;
                        }
                    }
                    Ok(())
                }),
                element!("form[action]", |el| rewrite_attr(el, "action", base_url, proxy_domain, relay_domain)),
                element!("button[formaction], input[formaction]", |el| rewrite_attr(el, "formaction", base_url, proxy_domain, relay_domain)),
            ],
            ..Settings::default()
        },
        |chunk: &[u8]| output.extend_from_slice(chunk),
    );
    rewriter
        .write(html)
        .map_err(|error| format!("rewriting HTML: {error}"))?;
    rewriter
        .end()
        .map_err(|error| format!("finishing HTML rewrite: {error}"))?;
    Ok(output)
}

const BROWSER_FETCH_BOOTSTRAP: &str = r#"<script>
(()=>{const relay="__BROWSER_PROXY_ORIGIN__";const route=value=>{try{const raw=value instanceof Request?value.url:value;const u=new URL(raw,location.href);if((u.protocol!=="http:"&&u.protocol!=="https:")||u.origin===location.origin)return value;const path=`${relay}/browse/${u.protocol.slice(0,-1)}/${encodeURIComponent(u.host)}${u.pathname}${u.search}${u.hash}`;return value instanceof Request?new Request(path,value):path}catch{return value}};const fetch0=window.fetch.bind(window);window.fetch=(input,init)=>fetch0(route(input),init);const open0=XMLHttpRequest.prototype.open;XMLHttpRequest.prototype.open=function(method,url,...rest){return open0.call(this,method,route(url),...rest)};if(navigator.sendBeacon){const beacon0=navigator.sendBeacon.bind(navigator);navigator.sendBeacon=(url,data)=>beacon0(route(url),data)}})();
</script>"#;

pub(crate) fn rewrite_css(css: &[u8], base_url: &Url, proxy_domain: &str) -> Option<Vec<u8>> {
    let css = std::str::from_utf8(css).ok()?;
    let lower = css.to_ascii_lowercase();
    let mut output = String::with_capacity(css.len());
    let mut cursor = 0;
    while let Some(relative_start) = lower[cursor..].find("url(") {
        let start = cursor + relative_start;
        let value_start = start + 4;
        let Some(relative_end) = css[value_start..].find(')') else {
            break;
        };
        let end = value_start + relative_end;
        output.push_str(&css[cursor..value_start]);
        let raw = css[value_start..end].trim();
        let value = raw.trim_matches(['\'', '"']).trim();
        if let Some(url) = base_url.join(value).ok().filter(is_http_url) {
            output.push('"');
            output.push_str(&gateway_url(&url, proxy_domain));
            output.push('"');
        } else {
            output.push_str(raw);
        }
        output.push(')');
        cursor = end + 1;
    }
    output.push_str(&css[cursor..]);
    Some(output.into_bytes())
}

fn rewrite_attr(
    element: &mut Element,
    attr: &str,
    base_url: &Url,
    proxy_domain: &str,
    relay_domain: &str,
) -> HandlerResult {
    let Some(value) = element.get_attribute(attr) else {
        return Ok(());
    };
    if let Some(rewritten) = rewrite_url(&value, base_url, proxy_domain, relay_domain) {
        element.set_attribute(attr, &rewritten)?;
    }
    Ok(())
}

fn rewrite_url(
    value: &str,
    base_url: &Url,
    proxy_domain: &str,
    relay_domain: &str,
) -> Option<String> {
    let value = value.trim();
    if value.is_empty()
        || value.starts_with('#')
        || value.starts_with("data:")
        || value.starts_with("javascript:")
        || value.starts_with("mailto:")
        || value.starts_with("tel:")
        || value.starts_with("blob:")
    {
        return None;
    }
    let target = base_url.join(value).ok()?;
    if !is_http_url(&target) {
        return None;
    }
    if target.host_str().is_some_and(|host| {
        host.eq_ignore_ascii_case("duckduckgo.com")
            || host.to_ascii_lowercase().ends_with(".duckduckgo.com")
    }) && target.path().starts_with("/l/")
    {
        let query = target
            .query()
            .map(|query| format!("?{query}"))
            .unwrap_or_default();
        return Some(format!("https://{relay_domain}{}{query}", target.path()));
    }
    Some(gateway_url(&target, proxy_domain))
}

fn rewrite_srcset(value: &str, base_url: &Url, proxy_domain: &str, relay_domain: &str) -> String {
    value
        .split(',')
        .map(|candidate| {
            let candidate = candidate.trim();
            let split = candidate
                .find(char::is_whitespace)
                .unwrap_or(candidate.len());
            let (url, descriptor) = candidate.split_at(split);
            match rewrite_url(url, base_url, proxy_domain, relay_domain) {
                Some(url) if descriptor.is_empty() => url,
                Some(url) => format!("{url}{descriptor}"),
                None => candidate.to_string(),
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn is_http_url(url: &Url) -> bool {
    matches!(url.scheme(), "http" | "https") && url.host().is_some()
}

fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_public_ipv4(ip),
        IpAddr::V6(ip) => is_public_ipv6(ip),
    }
}

fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !ip.is_private()
        && !ip.is_loopback()
        && !ip.is_link_local()
        && !ip.is_multicast()
        && !ip.is_broadcast()
        && !ip.is_unspecified()
        && a != 0
        && !(a == 100 && (64..=127).contains(&b))
        && !(a == 192 && b == 0 && c == 0)
        && !(a == 192 && b == 0 && c == 2)
        && !(a == 192 && b == 88 && c == 99)
        && !(a == 198 && (b == 18 || b == 19))
        && !(a == 198 && b == 51 && c == 100)
        && !(a == 203 && b == 0 && c == 113)
        && a < 240
}

fn is_public_ipv6(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    (segments[0] & 0xe000) == 0x2000
        && !ip.is_loopback()
        && !ip.is_unspecified()
        && !ip.is_multicast()
        && !(segments[0] == 0x2001 && segments[1] == 0x0db8)
        && !(segments[0] == 0x2001 && segments[1] <= 0x01ff)
        && segments[0] != 0x2002
}
