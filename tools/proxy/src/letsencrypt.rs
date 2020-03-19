//https://github.com/ctm/actix-web-lets-encrypt/blob/master/src/lib.rs

use actix::prelude::*;
use actix_web::{HttpRequest, Result};
use actix_files::NamedFile;
use std::path::PathBuf;
use acme_lib::{Account, Certificate, Directory, DirectoryUrl};
use acme_lib::persist::FilePersist;
use acme_lib::create_p384_key;
use std::time::Duration;
use openssl::ssl::{SslAcceptor, SslAcceptorBuilder, SslMethod, SslFiletype};

pub struct LetsEncrypt {
    // Should be possible to atleast include subdomains to register
    domain: String,
    alts: Vec<String>,
    renew_within_days: i64,
    check_every: Duration,
    base_path: PathBuf
}
const SECS_IN_MINUTE: u64 = 60;
const SECS_IN_HOUR: u64 = SECS_IN_MINUTE * 60;

/// Domain and alt-names currently in the certificate,
/// used while checking for whether to create
#[derive(Hash)]
pub struct CertificateState {
    domain: String,
    alts: Vec<String>
}
impl CertificateState {
    pub fn get_hashed(&self) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        self.hash(&mut hasher);
        format!("{}", hasher.finish())
    }
}

impl LetsEncrypt {
    pub fn new(domain: String, alts: Vec<String>) -> Self {
        let base_path = PathBuf::from("/ssl");
        LetsEncrypt {
            domain,
            alts,
            renew_within_days: 30,
            check_every: Duration::new(12 * SECS_IN_HOUR, 0),
            base_path,
        }
    }

    pub fn certificate(&self) -> Result<Option<Certificate>, String> {
        let account = self.account()?;
        let account_debug = account.api_account();
        println!("Is status valid: {}", account_debug.is_status_valid());
        println!("Is status deactivated: {}", account_debug.is_status_deactivated());
        println!("Is status revoked: {}", account_debug.is_status_revoked());
        println!("Is terms agreed: {}", account_debug.termsOfServiceAgreed());
        println!("{:?}", account_debug);
        match account.certificate(&self.domain) {
            Ok(certificate_opt) => Ok(certificate_opt),
            Err(_) => return Err(format!("Failed to get certificate"))
        }
    }

    // Factored to prevent errors from different paths
    fn certificate_state_path(&self) -> PathBuf {
        self.base_path.join("certificate_state")
    }

    // Factored to prevent errors from different implementations
    fn current_certificate_state(&self) -> CertificateState {
        CertificateState {
            domain: self.domain.clone(),
            alts: self.alts.clone()
        }
    }

    /// Returns hash derived from domain and alts in certificate
    pub fn certificate_state_matches(&self) -> Result<bool, String> {
        let path = self.certificate_state_path();
        // This should probably be temp, and return Err instead
        if !path.exists() {
            return Ok(false);
        }
        let hashed_saved = match std::fs::read_to_string(path) {
            Ok(hashed) => hashed,
            Err(_) => return Err("Could not read certificate state file".into())
        };
        Ok(hashed_saved == self.current_certificate_state().get_hashed())
    }
    
    /// Save certificate state
    pub fn certificate_state_save(&self) -> Result<(), String> {
        let path = self.certificate_state_path();
        match std::fs::write(path, self.current_certificate_state().get_hashed()) {
            Ok(_) => Ok(()),
            Err(e) => Err(format!("Failed to write certificate state: {:?}", e))
        }
    }

    pub fn days_left(&self) -> Result<Option<i64>, String> {
        match self.certificate()? {
            Some(certificate) => {
                match self.certificate_state_matches() {
                    Ok(false) => {
                        // There could be a revoke somewhere in here
                        // Preferably after a new certificate is created,
                        // if before, order may fail and take time, if after
                        // ensure we're not revoking current certificate
                        println!("Certificate state does not match");
                        Ok(None)
                    }
                    Ok(true) => {
                        println!("Certificate state matches");
                        let days_left = certificate.valid_days_left();
                        if days_left > 0 {
                            Ok(Some(days_left))
                        } else {
                            Ok(None)
                        }
                    }
                    Err(e) => Err(e)
                }
            }
            None => Ok(None)
        }
    }

    fn needs_building(&self) -> Result<bool, String> {
        match self.days_left()? {
            Some(days_left) => Ok(days_left < self.renew_within_days),
            None => Ok(true)
        }
    }

    pub fn account(&self) -> Result<Account<FilePersist>, String> {
        let staging = false;
        let directory = match if staging {
            let staging_dir = self.base_path.join("staging");
            match std::fs::create_dir_all(&staging_dir) {
                Ok(_) => (),
                Err(e) => return Err(format!("Could not create staging directory: {:?}", e))
            }
            Directory::from_url(FilePersist::new(&staging_dir), DirectoryUrl::LetsEncryptStaging)
        } else {
            let account_dir = self.base_path.clone();
            match std::fs::create_dir_all(&account_dir) {
                Ok(_) => (),
                Err(_) => return Err("Could not create base directory".into())
            }
            Directory::from_url(FilePersist::new(&account_dir), DirectoryUrl::LetsEncrypt)
        } {
            Ok(directory) => directory,
            Err(_) => return Err("Failed to create directory".into())
        };
        // Todo: From config
        let account = match directory.account("brygga-dev@gmail.com") {
            Ok(account) => account,
            Err(e) => return Err(format!("Could not register account: {:?}", e))
        };
        Ok(account)
    }

    fn build_cert(&self) -> Result<(), String> {
        let account = self.account()?;
        let alt_str: Vec<&str> = self.alts.iter().map(|alt| alt.as_str()).collect();
        println!("Making order for: {} and {:?}", self.domain, alt_str);
        let mut ord_new = match account.new_order(&self.domain, &alt_str) {
            Ok(ord_new) => ord_new,
            Err(e) => return Err(format!("Could not create new order: {:?}", e))
        };
        // Ensure .well-known/acme-challenge exists
        let challenge_dir = self.base_path.join("nonce/.well-known/acme-challenge");
        match std::fs::create_dir_all(&challenge_dir) {
            Ok(_) => (),
            Err(e) => return Err(format!("Could not create challenge directory: {:?}", e))
        }
        let ord_csr = loop {
            if let Some(ord_csr) = ord_new.confirm_validations() {
                break ord_csr;
            }
            let auths = match ord_new.authorizations() {
                Ok(auths) => auths,
                Err(e) => return Err(format!("Failed getting authorizations: {:?}", e))
            };
            if auths.len() < 1 {
                return Err("Zero auths returned".into());
            }
            for auth in auths {
                let chall = auth.http_challenge();
                if chall.need_validate() {
                    let token = chall.http_token();
                    let proof = chall.http_proof();
                    let mut token_file = match std::fs::File::create(challenge_dir.join(token)) {
                        Ok(token_file) => token_file,
                        Err(e) => return Err(format!("Failed to create token file: {:?}", e))
                    };
                    use std::io::Write;
                    match token_file.write_all(proof.as_bytes()) {
                        Ok(_) => (),
                        Err(e) => return Err(format!("Failed to write proof: {:?}", e))
                    }
                    match chall.validate(2500) {
                        Ok(_) => (),
                        Err(e) => return Err(format!("Failed to validate: {:?}", e))
                    }
                }
            }
            match ord_new.refresh() {
                Ok(_) => (),
                Err(e) => return Err(format!("Failed to refresh order: {:?}", e))
            }
        };
        let (pkey_pri, pkey_pub) = create_p384_key();
        let ord_cert = match ord_csr.finalize_pkey(pkey_pri, pkey_pub, 2500) {
            Ok(ord_cert) => ord_cert,
            Err(e) => return Err(format!("Failed finalize pkey: {:?}", e))
        };
        let _cert = match ord_cert.download_and_save_cert() {
            Ok(cert) => cert,
            Err(e) => return Err(format!("Failed download and save cert: {:?}", e))
        };
        self.certificate_state_save()?;
        Ok(())
    }

    /// Check whether building is needed, and do build if so,
    /// return whether build was done
    pub fn checked_build(&self) -> bool {
        println!("Checking certificate");
        match self.needs_building() {
            Ok(needs_building) => {
                if needs_building {
                    match self.build_cert() {
                        Ok(_) => {
                            println!("Certificates built!");
                            true
                        }
                        Err(e) => {
                            eprintln!("Failed certificates build!: {}", e);
                            false
                        }
                    }
                } else {
                    false
                }
            },
            Err(e) => {
                eprintln!("Failed needs_building check!: {}", e);
                false
            }
        }
    }

    pub fn ssl_builder(&self, certificate: Certificate) -> Result<SslAcceptorBuilder, String> {
        use std::io::Write;

        let cert_path = self.base_path.join(format!("cert_file_{}", self.domain));
        let mut cert_file = match std::fs::File::create(&cert_path) {
            Ok(cert_file) => cert_file,
            Err(_) => return Err("Could not open cert file".into())
        };
        match cert_file.write_all(certificate.certificate().as_bytes()) {
            Ok(_) => (),
            Err(_) => return Err("Could not write cert file".into())
        }

        let pkey_path = self.base_path.join(format!("pkey_file_{}", self.domain));
        let mut pkey_file = match std::fs::File::create(&pkey_path) {
            Ok(cert_file) => cert_file,
            Err(_) => return Err("Could not open cert file".into())
        };
        match pkey_file.write_all(certificate.private_key().as_bytes()) {
            Ok(_) => (),
            Err(_) => return Err("Could not write cert file".into())
        }

        let mut builder = match SslAcceptor::mozilla_intermediate(SslMethod::tls()) {
            Ok(builder) => builder,
            Err(_) => return Err("Could not make ssl_acceptor".into())
        };
        match builder.set_private_key_file(&pkey_path, SslFiletype::PEM) {
            Ok(_) => (),
            Err(_) => return Err("Could not set private key file".into())
        }
        match builder.set_certificate_chain_file(&cert_path) {
            Ok(_) => (),
            Err(_) => return Err("Could not set cert file".into())
        }
        return Ok(builder);

        let pkey = match openssl::pkey::PKey::private_key_from_der(&certificate.private_key_der()) {
            Ok(pkey) => pkey,
            Err(_) => return Err("Failed to get private key".into())
        };
        let cert = match openssl::x509::X509::from_der(&certificate.certificate_der()) {
            Ok(cert) => cert,
            Err(_) => return Err("Failed to get certificate".into())
        };
        match builder.set_private_key(&pkey) {
            Ok(_) => (),
            Err(_) => return Err("Failed to set private key".into())
        }
        match builder.set_certificate(&cert) {
            Ok(_) => (),
            Err(_) => return Err("Failed to set certificate".into())
        }
        Ok(builder)
    }
}

impl Actor for LetsEncrypt {
    type Context = Context<LetsEncrypt>;

    fn started(&mut self, ctx: &mut Self::Context) {
        if self.checked_build() {
            // Relying on docker restart policy to restart the container
            actix::System::current().stop();
        } else {
            ctx.run_interval(self.check_every, move |act, _ctx| {
                if act.checked_build() {
                    actix::System::current().stop();
                }
            });
        }
    }
}

pub fn nonce_request(req: HttpRequest) -> Result<NamedFile> {
    let token = req.match_info().query("token");
    let token_root = PathBuf::from("/ssl/nonce/.well-known/acme-challenge");
    let path = token_root.join(token);
    Ok(NamedFile::open(path)?)
}