pub use goauth::scopes::Scope;
/// A module for managing a Google API access token
use {
    goauth::{
        auth::{JwtClaims, Token},
        credentials::Credentials,
    },
    log::*,
    smpl_jwt::Jwt,
    std::{
        sync::{
            atomic::{AtomicBool, Ordering},
            {Arc, RwLock},
        },
        time::Instant,
    },
};

fn load_credentials(filepath: Option<String>) -> Result<Credentials, String> {
    let path = match filepath {
        Some(f) => f,
        None => std::env::var("GOOGLE_APPLICATION_CREDENTIALS").map_err(|_| {
            "GOOGLE_APPLICATION_CREDENTIALS environment variable not found".to_string()
        })?,
    };
    Credentials::from_file(&path)
        .map_err(|err| format!("Failed to read GCP credentials from {}: {}", path, err))
}

#[derive(Clone)]
pub struct AccessToken {
    credentials: Credentials,
    scope: Scope,
    refresh_active: Arc<AtomicBool>,
    token: Arc<RwLock<(Token, Instant)>>,
}

impl AccessToken {
    pub async fn new(scope: Scope, credential_filepath: Option<String>) -> Result<Self, String> {
        let credentials = load_credentials(credential_filepath)?;
        if let Err(err) = credentials.rsa_key() {
            Err(format!("Invalid rsa key: {}", err))
        } else {
            let token = Arc::new(RwLock::new(Self::get_token(&credentials, &scope).await?));
            let access_token = Self {
                credentials,
                scope,
                token,
                refresh_active: Arc::new(AtomicBool::new(false)),
            };
            Ok(access_token)
        }
    }

    /// The project that this token grants access to
    pub fn project(&self) -> String {
        self.credentials.project()
    }

    async fn get_token(
        credentials: &Credentials,
        scope: &Scope,
    ) -> Result<(Token, Instant), String> {
        info!("Requesting token for {:?} scope", scope);
        let claims = JwtClaims::new(
            credentials.iss(),
            scope,
            credentials.token_uri(),
            None,
            None,
        );
        let jwt = Jwt::new(claims, credentials.rsa_key().unwrap(), None);

        let token = goauth::get_token(&jwt, credentials)
            .await
            .map_err(|err| format!("Failed to refresh access token: {}", err))?;

        info!("Token expires in {} seconds", token.expires_in());
        Ok((token, Instant::now()))
    }

    /// Call this function regularly to ensure the access token does not expire
    pub async fn refresh(&self) {
        // Check if it's time to try a token refresh
        {
            let token_r = self.token.read().unwrap();
            if token_r.1.elapsed().as_secs() < token_r.0.expires_in() as u64 / 2 {
                return;
            }

            #[allow(deprecated)]
            if self
                .refresh_active
                .compare_and_swap(false, true, Ordering::Relaxed)
            {
                // Refresh already pending
                return;
            }
        }

        info!("Refreshing token");
        let new_token = Self::get_token(&self.credentials, &self.scope).await;
        {
            let mut token_w = self.token.write().unwrap();
            match new_token {
                Ok(new_token) => *token_w = new_token,
                Err(err) => warn!("{}", err),
            }
            self.refresh_active.store(false, Ordering::Relaxed);
        }
    }

    /// Return an access token suitable for use in an HTTP authorization header
    pub fn get(&self) -> String {
        let token_r = self.token.read().unwrap();
        format!("{} {}", token_r.0.token_type(), token_r.0.access_token())
    }
}
