use crate::er::{self, Result};
use crate::project::ProjectConfig;
use crate::utils::{self, CliEnv};
use failure::format_err;
use std::path::{Path, PathBuf};
use crate::server::{SyncSet, SyncBase, SyncSentCache, SshConn};

use crate::jitsi_env_file;
use std::fs;

/// Creates config folders in project, .env file used with docker
pub fn setup_project(env: &CliEnv, project: &mut ProjectConfig) -> Result<()> {
    let jitsi_config_dir = project.dir_and(env, ".jitsi-meet-cfg");

    fs::create_dir_all(&jitsi_config_dir)?;
    for config_sub in &["web/letsencrypt", "transcripts", "prosody", "jicofo", "jvb"] {
        fs::create_dir_all(jitsi_config_dir.join(config_sub))?;
    }
    // .env file
    let tz = "Europe/Oslo".to_string();
    let local_config = jitsi_env_file::JitsiEnvConfig {
        config_dir: jitsi_config_dir.to_string_lossy().to_string(),
        tz: tz.clone(),
        public_url: "localhost".to_string(),
        letsencrypt: None,
        http_port: 7000,
        https_port: 7443
    };
    let local_content = jitsi_env_file::write_env_file(local_config)?;
    let mut env_file = fs::File::create(project.dir_and(env, ".env"))?;
    use std::io::Write;
    env_file.write_all(local_content.as_bytes())?;
    Ok(())
}

pub fn setup_project_prod(env: &CliEnv, project: &mut ProjectConfig) -> Result<()> {
    let server = project.require_server(env)?;
    let conn = SshConn::connect_server(env, &server)?;
    // todo: This crashes with code/viddler/server (oops)
    let server_project_dir = server.home_dir_and(&format!("projects/{}", project.name));
    let jitsi_config_dir = server_project_dir.join(".jitsi-meet-cfg");
    for config_sub in &["web/letsencrypt", "transcripts", "prosody", "jicofo", "jvb"] {
        // not quite optimal but
        conn.exec(format!("mkdir -p {}", jitsi_config_dir.join(config_sub).to_string_lossy()))?;
    }
    let tz = "Europe/Oslo".to_string();
    use std::io::Write;
    // .env
    let (letsencrypt, public_url) = if let Some(domain) = &project.domain {
        let letsencrypt = Some(jitsi_env_file::JitsiEnvConfigLetsEncrypt {
            domain: domain.to_owned(),
            email: "viddler.no@gmail.com".to_string()
        });
        (letsencrypt, format!("https://{}", domain))
    } else {
        (None, format!("http://{}", server.url))
    };
    let prod_config = jitsi_env_file::JitsiEnvConfig {
        config_dir: jitsi_config_dir.to_string_lossy().to_string(),
        tz,
        public_url,
        letsencrypt,
        http_port: 80,
        https_port: 443
    };
    let prod_content = jitsi_env_file::write_env_file(prod_config)?;
    let env_local = project.dir_and(env, ".env.prod");
    let mut env_file = fs::File::create(&env_local)?;
    env_file.write_all(prod_content.as_bytes())?;
    // Transfer file to prod with name '.env'
    SyncSet::from_file(
        SyncBase::local(env_local),
        SyncBase::remote(server_project_dir.join(".env"), &conn.sftp()?),
        false,
        SyncSentCache::None
    )?.sync_plain()?;
    Ok(())
}
