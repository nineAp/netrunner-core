use http::Request;

#[derive(Clone, Debug)]
pub struct BearerAuth {
    token: Option<String>,
}

impl BearerAuth {
    pub fn new(token: Option<String>) -> Self {
        Self { token }
    }

    pub fn authorize(&self, request: &Request<()>) -> bool {
        let Some(expected) = self.token.as_deref() else {
            return true;
        };
        let Some(value) = request.headers().get(http::header::AUTHORIZATION) else {
            return false;
        };
        let Ok(value) = value.to_str() else {
            return false;
        };
        let Some(actual) = value.strip_prefix("Bearer ") else {
            return false;
        };
        constant_time_eq(actual.as_bytes(), expected.as_bytes())
    }
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }

    let mut difference = 0_u8;
    for (&left, &right) in left.iter().zip(right) {
        difference |= left ^ right;
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_exact_bearer_token() {
        let request = Request::builder()
            .header("authorization", "Bearer secret")
            .body(())
            .unwrap();
        assert!(BearerAuth::new(Some("secret".into())).authorize(&request));
    }

    #[test]
    fn rejects_missing_or_different_token() {
        let missing = Request::new(());
        let different = Request::builder()
            .header("authorization", "Bearer nope")
            .body(())
            .unwrap();
        let auth = BearerAuth::new(Some("secret".into()));
        assert!(!auth.authorize(&missing));
        assert!(!auth.authorize(&different));
    }
}
