use crate::docker;
use crate::er::{self, Result};
use crate::project::ProjectConfig;
use crate::project_path::ProjectItemPaths;
use crate::server::{self, SshConn, SyncBase, SyncSet};
use crate::server::{ServerConfig, SyncSentCache};
use crate::utils::{self, CliEnv};
use failure::format_err;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

/*
/// While wp-specific, dev setup might be a different category
pub fn gen_vscode_debug_config(env: &CliEnv, project: &ProjectConfig) -> Result<()> {
    // Using hjson here to preserve comments in json file
    // edit: unfortunately doesn't preserve comments, at least
    // parses it
    use serde_hjson::{Map, Value};
    // Collect mapping for plugins and themes
    let mut mappings = Map::new();
    // Have now moved to mount whole plugins and themes dirs
    /*
    let site_local = get_local_site_data(env, project)?;
    for (_name, plugin) in site_local.plugins {
        mappings.insert(
            plugin.paths.server_path.string(),
            Value::String(format!(
                "${{workspaceRoot}}/{}",
                plugin.paths.from_project.cow()
            )),
        );
    }
    for (_name, theme) in site_local.themes {
        mappings.insert(
            theme.paths.server_path.string(),
            Value::String(format!(
                "${{workspaceRoot}}/{}",
                theme.paths.from_project.cow()
            )),
        );
    }
    */
    mappings.insert(
        "/var/www/html/wp-content/plugins".to_string(),
        Value::String("${workspaceRoot}/plugins".to_string()),
    );
    mappings.insert(
        "/var/www/html/wp-content/themes".to_string(),
        Value::String("${workspaceRoot}/themes".to_string()),
    );
    // Lastly, add fallback to wp root for all other files
    mappings.insert(
        "/var/www/html".to_string(),
        Value::String("${workspaceRoot}/wp".to_string()),
    );
    // Assemble entry
    let our_debug_key = "Wop";
    use std::iter::FromIterator;
    let config_entry = Value::Object(Map::from_iter(vec![
        ("name".to_string(), Value::String(our_debug_key.to_string())),
        ("request".to_string(), Value::String("launch".to_string())),
        ("type".to_string(), Value::String("php".to_string())),
        ("pathMappings".to_string(), Value::Object(mappings)),
        ("port".to_string(), Value::I64(9001)),
    ]));
    let mut conf_path = project.dir(env);
    conf_path.push(".vscode");
    conf_path.push("launch.json");
    let json_value = if conf_path.is_file() {
        // Existing json file, replace wop entry
        let conf_str = std::fs::read_to_string(&conf_path)?;
        // Deserializing to generic json value to ease
        // dealing with potientially unknown values
        let mut json_val = serde_hjson::from_str::<serde_hjson::Value>(&conf_str)
            .map_err(|e| er::error(format!("Json decode error: {:?}", e)))?;
        // If there is existing entry, replace, otherwise append
        // Ugh, next time investigate api. There are many methods for stuff like this.
        match &mut json_val {
            Value::Object(ref mut map) => {
                match map.get_mut("configurations") {
                    Some(ref mut configurations) => match configurations {
                        Value::Array(ref mut arr) => {
                            // Check for name = "Wop"
                            let index = arr.iter().position(|entry| match entry {
                                Value::Object(map) => match map.get("name") {
                                    Some(Value::String(name_val)) => name_val == our_debug_key,
                                    _ => false,
                                },
                                _ => false,
                            });
                            match index {
                                Some(index) => {
                                    // Replace
                                    arr[index] = config_entry;
                                }
                                None => {
                                    // Push
                                    arr.push(config_entry);
                                }
                            }
                        }
                        _ => {
                            return er::err("Expected configurations array in .vscode/launch.json")
                        }
                    },
                    None => return er::err("Expected configurations key in .vscode/launch.json"),
                }
            }
            _ => return er::err("Expected object in .vscode/launch.json"),
        }
        json_val
    } else {
        // New json file
        Value::Object(Map::from_iter(vec![
            ("version".to_string(), Value::String("0.2.0".to_string())),
            (
                "configurations".to_string(),
                Value::Array(vec![config_entry]),
            ),
        ]))
    };
    let json_str = serde_json::to_string_pretty(&to_json_val(json_value))
        .map_err(|e| er::error(format!("Serialize error: {:?}", e)))?;
    utils::ensure_parent_dir(&conf_path)?;
    std::fs::write(conf_path, json_str).map_err(|e| er::Io::e(e).into())
}

// Ugh. Got type error with hjson
fn to_json_val(v: serde_hjson::Value) -> serde_json::Value {
    match v {
        serde_hjson::Value::Array(v) => {
            serde_json::Value::Array(v.into_iter().map(|e| to_json_val(e)).collect())
        }
        serde_hjson::Value::Bool(v) => serde_json::Value::Bool(v),
        serde_hjson::Value::F64(v) => serde_json::Value::Number(serde_json::Number::from(
            serde_json::de::ParserNumber::F64(v),
        )),
        serde_hjson::Value::I64(v) => serde_json::Value::Number(serde_json::Number::from(
            serde_json::de::ParserNumber::I64(v),
        )),
        serde_hjson::Value::Null => serde_json::Value::Null,
        serde_hjson::Value::Object(m) => {
            serde_json::Value::Object(m.into_iter().map(|(k, v)| (k, to_json_val(v))).collect())
        }
        serde_hjson::Value::String(s) => serde_json::Value::String(s),
        serde_hjson::Value::U64(v) => serde_json::Value::Number(serde_json::Number::from(
            serde_json::de::ParserNumber::U64(v),
        )),
    }
}*/

/// Docker file to create a prod like environment locally
pub fn create_docker_local_prod_yml(env: &CliEnv, project: &mut ProjectConfig) -> Result<()> {
    use crate::docker::{ComposeService, ComposeYml};
    // Set environment variable for external url
    let mut proxy_env = IndexMap::new();
    proxy_env.insert("EXTERNAL".to_string(), "http://localhost".to_string());
    let proxy = ComposeService {
        volumes: Vec::new(),
        environment: proxy_env,
    };
    let mut services = IndexMap::new();
    services.insert("proxy".to_string(), proxy);
    let yml = ComposeYml {
        version: "3.3".into(),
        services,
    };
    yml.save_if_diff(&project.dir_and(env, "docker/prod-local.yml"))?;
    Ok(())
}

pub fn create_docker_prod_yml(env: &CliEnv, project: &mut ProjectConfig) -> Result<()> {
    use crate::docker::{ComposeService, ComposeYml};
    // Set environment variable for external url
    let server = project.require_server(env)?;
    let mut proxy_env = IndexMap::new();
    let elastic_ip = match server.elastic_ip {
        Some(elastic_ip) => elastic_ip,
        None => {
            // I guess this isn't totally wrong, but allowing domain now
            eprintln!("Elastic ip is required for prod.yml");
            return Err(format_err!("Elastic ip is required for prod.yml"));
        }
    };
    match &project.domain {
        Some(domain) => {
            // Todo: It would make more sense to pass the domain by itself,
            // this would require some changes in proxy
            proxy_env.insert("EXTERNAL".to_string(), format!("https://{}", domain));
        }
        None => {
            proxy_env.insert(
                "EXTERNAL".to_string(),
                format!("http://{}", elastic_ip.public_ip),
            );
        }
    }
    let proxy = ComposeService {
        volumes: Vec::new(),
        environment: proxy_env,
    };
    let mut services = IndexMap::new();
    services.insert("proxy".to_string(), proxy);
    let yml = ComposeYml {
        version: "3.3".into(),
        services,
    };
    yml.save_if_diff(&project.dir_and(env, "docker/prod.yml"))?;
    Ok(())
}

/// Create backup compose file for project
pub fn create_backup_yml(env: &CliEnv, project: &ProjectConfig) -> Result<()> {
    use crate::docker::{ComposeService, ComposeYml};
    use crate::git;
    let mut services = IndexMap::new();
    let mut backup_env = IndexMap::new();
    let git_config = crate::git::get_config(env, &project.git_user)?;
    backup_env.insert(
        "GIT_REPO".to_string(),
        git::make_origin_url(&git_config, &project.git_backup_repo)?,
    );
    backup_env.insert("GIT_USER".to_string(), git_config.user);
    backup_env.insert("GIT_EMAIL".to_string(), git_config.email);
    services.insert(
        "backup".to_string(),
        ComposeService {
            volumes: Vec::new(),
            environment: backup_env,
        },
    );
    let yml = ComposeYml {
        version: "3.3".into(),
        services,
    };
    yml.save_if_diff(&project.dir_and(env, "docker/backup.yml"))?;
    Ok(())
}

/// Create mount entries for directories in
/// plugins/ and themes/ folders
pub fn create_wp_mounts_docker_yml(env: &CliEnv, project: &ProjectConfig) -> Result<()> {
    use crate::docker::{ComposeService, ComposeYml};
    // Iterate plugins and themes and collect mounts
    let mut mounts = Vec::new();
    let local_site = get_local_site_data(env, project)?;
    // Mounting full plugins, themes folder instead of specifics
    // like done below
    mounts.push((
        local_site.project_dir.join("plugins"),
        PathBuf::from("/var/www/html/wp-content/plugins"),
    ));
    mounts.push((
        local_site.project_dir.join("themes"),
        PathBuf::from("/var/www/html/wp-content/themes"),
    ));

    // Plugin mounts
    /*
    for (_name, plugin) in local_site.plugins {
        mounts.push((
            plugin.paths.full_path.string(),
            plugin.paths.server_path.string(),
        ));
    }*/
    // Theme mounts
    /*for (_name, theme) in local_site.themes {
        mounts.push((
            theme.paths.full_path.string(),
            theme.paths.server_path.string(),
        ));
    }*/
    let mut services = IndexMap::new();
    // Add mounts to wordpress-container and wp-cli
    let mut volumes = mounts
        .into_iter()
        .map(|(source, dst)| format!("{}:{}", source.to_string_lossy(), dst.to_string_lossy()))
        .collect::<Vec<_>>();

    // Add mounts relevent to static files to proxy service
    /*
    services.insert(
        "proxy".into(),
        ComposeService {
            volumes: volumes.clone(),
        },
    );*/
    // And mount wp root onto project for easy interaction
    // in development
    let mut local_wp = project.dir(env);
    local_wp.push("wp");
    volumes.push(format!("{}:/var/www/html", local_wp.to_string_lossy()));

    // todo: Investigate global volume drivers to
    // see if we can mount onto them with particular drivers
    services.insert(
        "wordpress-container".into(),
        ComposeService {
            volumes: volumes.clone(),
            environment: IndexMap::new(),
        },
    );
    services.insert(
        "wp-cli".into(),
        ComposeService {
            volumes,
            environment: IndexMap::new(),
        },
    );
    let yml = ComposeYml {
        version: "3.3".into(),
        services,
    };
    yml.save_if_diff(&project.dir_and(env, "docker/mounts.yml"))?;
    Ok(())
}

/// Returns a connection to either dev server,
/// or tunneled from prod server
pub fn wp_cli_conn(env: &CliEnv, project: &mut ProjectConfig, on_server: bool) -> Result<SshConn> {
    let conn = if on_server {
        let server_config = if on_server {
            // Todo: Could allow to choose, or return error
            // Adding a new is more involved as it would need provision
            // and currently more steps to set up
            match project.get_server(&env, true)? {
                Some(server_config) => Some(server_config),
                None => return Err(format_err!("Could not resolve server")),
            }
        } else {
            None
        };
        match server_config {
            Some(server_config) => server::SshConn::connect_container_ssh(
                env,
                2345,
                "www-data",
                "www-data",
                Some(&server_config),
            )?,
            None => return Err(format_err!("No server config")),
        }
    } else {
        server::SshConn::connect_container_ssh(env, 2345, "www-data", "www-data", None)?
    };
    Ok(conn)
}

/// Wp_cli invokation cli command entry point
pub fn wp_cli(
    env: &CliEnv,
    current_process: utils::CurrentProcess,
    project: &mut ProjectConfig,
    args: Vec<String>,
    on_server: bool,
) -> Result<utils::CurrentProcess> {
    let cmd = format!("wp {}", args.join(" "));
    println!("{}", console::style(&cmd).green());
    let conn = wp_cli_conn(env, project, on_server)?;
    let output = conn.exec_capture(cmd, Some("/var/www/html"))?;
    println!("{}", output);
    Ok(current_process)
}

pub fn wp_clean(
    env: &CliEnv,
    project: &ProjectConfig,
    current_process: utils::CurrentProcess,
) -> Result<utils::CurrentProcess> {
    // Running docker-compose down including
    // volumes
    docker::dev_cmd(
        &env,
        current_process,
        project,
        vec!["down".to_string(), "--volumes".to_string()],
    )
}

/// Run wp installation process
pub fn wp_install(
    env: &CliEnv,
    project: &mut ProjectConfig,
    current_process: utils::CurrentProcess,
    on_server: bool,
) -> Result<utils::CurrentProcess> {
    // Collect needed install info,
    // then run wp-cli command
    let title = env.get_input("Title", Some("Site name".into()))?;
    let admin_user = env.get_input("Admin user", Some("admin".into()))?;
    // todo: Some security
    // Maybe some easy way to login, command or otherwise
    let admin_pass = env.get_input("Admin pass", Some("pass".into()))?;
    let admin_email = env.get_input("Admin email", Some("wp@example.com".into()))?;

    let args = vec![
        "core".to_string(),
        "install".to_string(),
        "--url=wordpress-container".to_string(),
        format!("--title=\"{}\"", title),
        format!("--admin_user={}", admin_user),
        // Would be preferable to use the option to read from file
        format!("--admin_password={}", admin_pass),
        format!("--admin_email={}", admin_email),
        "--skip-email".to_string(),
    ];

    // Download is not necessary currently
    // as it is done in the docker entrypoint script

    //wp_cli(env, project.clone(), "core", Some(vec!["download".into()]))?;
    let current_process = wp_cli(env, current_process, project, args, on_server)?;
    sync_local(env, project, on_server)?;
    Ok(current_process)
}

pub struct WpCliCmd {
    args: utils::StringVec,
}
impl WpCliCmd {
    pub fn new<C: Into<String>>(init: C) -> Self {
        let mut args = utils::StringVec::new();
        args.push(init);
        WpCliCmd { args }
    }

    pub fn exec(&self, cli_conn: &SshConn) -> Result<()> {
        match cli_conn.exec(format!("cd /var/www/html && wp {}", self.args.join(" "))) {
            Ok(exit_code) => {
                if exit_code == 0 {
                    Ok(())
                } else {
                    Err(format_err!("Non-zero exit code: {}", exit_code))
                }
            }
            Err(e) => Err(e),
        }
    }
}

pub fn install_plugin(cli_conn: &SshConn, plugin: &str, activate: bool) -> Result<()> {
    let mut cmd = WpCliCmd::new("plugin install");
    cmd.args.push(plugin);
    if activate {
        cmd.args.push("--activate");
    }
    cmd.exec(cli_conn)
}

pub fn activate_plugin(cli_conn: &SshConn, plugin: &str) -> Result<()> {
    let mut cmd = WpCliCmd::new("plugin activate");
    cmd.args.push(plugin);
    cmd.exec(cli_conn)
}

pub fn activate_theme(cli_conn: &SshConn, theme: &str) -> Result<()> {
    let mut cmd = WpCliCmd::new("theme activate");
    cmd.args.push(theme);
    cmd.exec(cli_conn)
}

// todo: it would be nice with "plugin" architecture for subsystems
/// Copy project files to container
pub fn sync_files_to_prod(
    env: &CliEnv,
    project: &ProjectConfig,
    server: &ServerConfig,
    cli_conn: &SshConn,
    site_local: &WpLocalSiteData,
) -> Result<()> {
    println!("Sync files to prod");
    let sftp = cli_conn.sftp()?;
    // Make sync set
    // todo: This barely works, but it would be
    // be nice to combine sync_sets for example
    let mut sync_set = SyncSet::new(
        SyncBase::local(site_local.project_dir.clone()),
        SyncBase::remote(PathBuf::from("/var/www/html/wp-content"), &sftp),
        SyncSentCache::load(env, format!("{}-{}", server.name, project.name))?,
    );
    println!("Sync set made");
    for (_name, plugin) in &site_local.plugins {
        println!("Plugin: {}", _name);
        sync_set.resolve_local(&plugin.paths.full_path.0, false)?;
    }
    for (_name, theme) in &site_local.themes {
        sync_set.resolve_local(&theme.paths.full_path.0, false)?;
    }
    sync_set.sync_zipped(cli_conn, &sftp)?;
    // Copy to docker volume
    // In this case, plugins and themes folders should be present,
    // but note that `cp` does not create parent folders
    // Specifying `-` for either source or destination will
    // accept a tar file from stdin, or export one to stdout
    // Using a tar file is a trick to handling file owner.
    println!("Sync files to prod done");
    Ok(())
}

/// Transfers uploads and database to prod
/// Plugins and themes are done elsewhere and they need
/// to be compatible.
pub fn sync_content_to_prod(env: &CliEnv, project: &mut ProjectConfig) -> Result<()> {
    let dev_cli_conn = wp_cli_conn(env, project, false)?;
    let server_cli_conn = wp_cli_conn(env, project, true)?;
    // Use sent cache when sending stuff to server
    sync_content(
        dev_cli_conn,
        server_cli_conn,
        // todo: Could we type the cache_key better?
        SyncSentCache::load(
            env,
            format!("{}-{}", project.require_server(env)?.name, project.name),
        )?,
    )?;
    println!("Done content-to-prod");
    Ok(())
}

pub fn sync_content_to_local(env: &CliEnv, project: &mut ProjectConfig) -> Result<()> {
    let dev_cli_conn = wp_cli_conn(env, project, false)?;
    let server_cli_conn = wp_cli_conn(env, project, true)?;
    sync_content(server_cli_conn, dev_cli_conn, SyncSentCache::None)?;
    println!("Done content-to-local");
    Ok(())
}

/// Expects wp-cli-connections
pub fn sync_content(from_conn: SshConn, to_conn: SshConn, sync_cache: SyncSentCache) -> Result<()> {
    let from_sftp = from_conn.sftp()?;
    let to_sftp = to_conn.sftp()?;
    // Uploads folder
    let uploads_dir: std::path::PathBuf = "/var/www/html/wp-content/uploads".into();
    let mut sync_set = SyncSet::from_file(
        SyncBase::remote(&uploads_dir, &from_sftp),
        SyncBase::remote(&uploads_dir, &to_sftp),
        false,
        sync_cache,
    )?;
    println!("Is blocking1: {:?}", to_conn.session.is_blocking());
    sync_set.sync_plain()?;
    // Run mysqldump to export db to a file
    // todo: better would be to pipe stdout to server, also
    // if we get project users we could use home directory
    // or other appropriate
    // todo:! file path is pretty bad. put there to quick fix permissions
    let mysqldump_file = PathBuf::from("/var/www/html/mysqldump.sql");
    from_conn.exec(mysql_export_cmd(&mysqldump_file))?;
    SyncSet::from_file(
        SyncBase::remote(&mysqldump_file, &from_sftp),
        SyncBase::remote(&mysqldump_file, &to_sftp),
        true,
        sync_set.sent_cache,
    )?
    .sync_plain()?;
    // Should sftps be dropped before commands?
    // Could split db and content folders if it helps use cases as content transfer can get heavy
    to_conn.exec(mysql_import_cmd(&mysqldump_file, false))?;
    to_conn.exec(format!("rm -rf {}", mysqldump_file.to_string_lossy()))?;
    Ok(())
}

/// Helper to create command to export database to a given path
fn mysql_export_cmd(mysqldump_file: &Path) -> String {
    let mut cmd = utils::StringVec::new();
    cmd.push("/usr/bin/env mysqldump");
    cmd.push("-uwordpress");
    cmd.push("-pwordpress");
    cmd.push("--host=db");
    cmd.push(format!(
        "--result-file={}",
        mysqldump_file.to_string_lossy()
    ));
    // Database name
    cmd.push("wordpress");
    cmd.join(" ")
}

/// Helper to create command to import a given file
fn mysql_import_cmd(mysqldump_file: &Path, optimize: bool) -> String {
    // Run command to import sql file
    // https://github.com/wp-cli/db-command/blob/master/src/DB_Command.php#L561
    let mut cmd = utils::StringVec::new();
    // auto-rehash is for completion in the client, which is not needed now
    cmd.push("/usr/bin/env mysql --no-auto-rehash");
    // todo: This is the same as wp-cli does, but can we have better security
    // with passwords? For one, be sure this doesn't show up in logs
    cmd.push("-uwordpress");
    cmd.push("-pwordpress");
    cmd.push("--database=wordpress");
    cmd.push("--host=db");
    let query = if optimize {
        format!("SET autocommit = 0; SET unique_checks = 0; SET foreign_key_checks = 0; SOURCE {}; COMMIT;", mysqldump_file.to_string_lossy())
    } else {
        format!("SOURCE {};", mysqldump_file.to_string_lossy())
    };
    cmd.push(format!("--execute=\"{}\"", query));
    cmd.join(" ")
}

/// Imports database, uploads (todo themes and plugins) from
/// import folder.
/// It recognizes mysqldump.sql file,
/// uploads, plugins and themes folders
pub fn import(env: &CliEnv, project: &mut ProjectConfig, optimize: bool) -> Result<()> {
    // Transfer files into wp-cli and run commands there
    let import_dir = project.dir_and(env, "import");
    let cli_conn = wp_cli_conn(env, project, false)?;
    // todo: I think there should be a setup of project
    // specific users in both wp-cli and wordpress containers
    // at least if multiple sites should be supported
    // currently www-user has home dir /var/www just to note
    // todo: Different path probably
    let home_dir: std::path::PathBuf = "/var/www/html".into();
    let sftp = cli_conn.sftp()?;
    let mut sync_set = SyncSet::new(
        SyncBase::local(import_dir.clone()),
        SyncBase::remote(PathBuf::from("/var/www/html/wp-content"), &sftp),
        SyncSentCache::None,
    );
    // transfer uploads, plugins, themes
    // an alternative is to copy to project folder so docker can sync
    // not sure how best to do it, this seems slightly more portable
    // wrt external servers
    sync_set.resolve_local(&import_dir.join("uploads"), false)?;
    sync_set.resolve_local(&import_dir.join("plugins"), false)?;
    sync_set.resolve_local(&import_dir.join("themes"), false)?;
    sync_set.sync_plain()?;
    // Mysqldump
    let mysqldump_file = import_dir.join("mysqldump.sql");
    if mysqldump_file.is_file() {
        let remote_mysqldump = home_dir.join("import/mysqldump.sql");
        crate::server::SyncSet::from_file(
            SyncBase::local(mysqldump_file),
            SyncBase::remote(remote_mysqldump.clone(), &sftp),
            false,
            SyncSentCache::None,
        )?
        .sync_plain()?;
        drop(sftp);
        cli_conn.exec(mysql_import_cmd(&remote_mysqldump, optimize))?;
        cli_conn.exec(format!(
            "rm -rf {}",
            home_dir.join("import").to_string_lossy()
        ))?;
    // Get site-url
    // Replace site-url throughout database
    } else {
        drop(sftp);
    }
    Ok(())
}

#[derive(Serialize, Deserialize)]
struct VersionFile {
    version: i32,
}

/// Syncs plugins, themes, other site data between local and install
/// on dev or server
pub fn sync_local(env: &CliEnv, project: &mut ProjectConfig, on_server: bool) -> Result<()> {
    let local_data = get_local_site_data(env, &project)?;
    // Increment version of local theme (todo: Should be active theme, or maybe
    // somehow global version.json file)
    // Maybe better, keep this persistant through proxy and get it with a request?
    // this would have slight performance impact though having to make he request
    for (_theme_name, wp_theme) in &local_data.themes {
        let version_file = wp_theme.paths.full_path.0.join("version.json");
        if version_file.is_file() {
            let mut version_json =
                serde_json::from_str::<VersionFile>(&std::fs::read_to_string(&version_file)?)?;
            version_json.version += 1;
            std::fs::write(version_file, serde_json::to_string(&version_json)?)?;
        }
    }
    let cli_conn = wp_cli_conn(env, project, on_server)?;
    if on_server {
        let server = project.require_server(env)?;
        sync_files_to_prod(env, project, &server, &cli_conn, &local_data)?;
    }
    let install_data = match wp_install_data(&cli_conn) {
        Ok(install_data) => install_data,
        Err(e) => return Err(format_err!("Install data error: {}", e)),
    };
    // Ensure local plugins, themes and their dependencies are activated

    // First do deps, ideally this should be a bigger dependency graph,
    // so deps of deps are installed first.
    // also could consider running wp-cli without loading plugins
    for dep in local_data.deps {
        match install_data.plugins.get(&dep) {
            Some(plugin_data) => {
                // Plugin is installed, check for activated
                if plugin_data.status != "active" {
                    activate_plugin(&cli_conn, &plugin_data.name)?;
                }
            }
            None => {
                install_plugin(&cli_conn, &dep, true)?;
            }
        }
    }
    // Activate local plugins
    // Todo: Could verify requirements (plugin.php?) first
    for (plugin_name, _local_plugin) in local_data.plugins {
        match install_data.plugins.get(&plugin_name) {
            Some(plugin_data) => {
                if plugin_data.status != "active" {
                    activate_plugin(&cli_conn, &plugin_name)?;
                } else {
                    println!("Already active: {}", plugin_name);
                }
            }
            None => {
                return Err(format_err!(
                    "Local plugin not found as installed on site, {}",
                    plugin_name
                ));
            }
        }
    }
    // If there is one theme locally, we currently activate this
    // Otherwise, could present a select to activate
    // Todo: Could verify requirements (functions.php and style.css?)
    if local_data.themes.len() == 1 {
        match local_data.themes.into_iter().next() {
            Some((theme_name, _local_theme)) => match install_data.themes.get(&theme_name) {
                Some(site_theme) => {
                    if site_theme.status != "active" {
                        activate_theme(&cli_conn, &theme_name)?;
                    }
                }
                None => {
                    return Err(format_err!(
                        "Local theme not found as installed on site, {}",
                        theme_name
                    ));
                }
            },
            None => (),
        }
    }
    if on_server {
        clear_cache_server(env, project)?;
        println!("Cache cleared on server");
    }
    Ok(())
}

pub fn clear_cache_server(env: &CliEnv, project: &mut ProjectConfig) -> Result<()> {
    use awc::Client;
    use futures::future::lazy;
    use futures::future::Future;
    // Expect https if domain
    match &project.domain {
        Some(domain) => {
            return actix_rt::System::new("clear-cache-request")
                .block_on(lazy(|| {
                    let client = Client::default();
                    client
                        .get(format!("https://{}/--clear-cache", domain))
                        .send()
                        .map(|_| ())
                }))
                .map_err(|_| format_err!("Clear-cache request failed"))
        }
        None => (),
    }
    let server = project.require_server(env)?;
    match server.elastic_ip {
        Some(elastic_ip) => actix_rt::System::new("clear-cache-request")
            .block_on(lazy(|| {
                let client = Client::default();
                client
                    .get(format!("http://{}/--clear-cache", elastic_ip.public_ip))
                    .send()
                    .map(|_| ())
            }))
            .map_err(|_| format_err!("Clear-cache request failed")),
        None => Ok(()),
    }
}

#[derive(Debug)]
pub struct WpPlugin {
    pub name: String,
    pub paths: ProjectItemPaths,
}

#[derive(Debug)]
pub struct WpTheme {
    pub name: String,
    pub paths: ProjectItemPaths,
}

#[derive(Debug)]
pub struct WpLocalSiteData {
    pub project_dir: PathBuf,
    pub plugins: HashMap<String, WpPlugin>,
    pub themes: HashMap<String, WpTheme>,
    pub deps: HashSet<String>,
}

/// Plugin conf from plugin.json in plugin dir
#[derive(Deserialize)]
pub struct PluginConf {
    deps: Vec<String>,
}

// Data from project, ie local
pub fn get_local_site_data(env: &CliEnv, project: &ProjectConfig) -> Result<WpLocalSiteData> {
    let project_dir = project.dir(env);
    let mut site_data = WpLocalSiteData {
        project_dir: project_dir.clone(),
        plugins: HashMap::new(),
        themes: HashMap::new(),
        deps: HashSet::new(),
    };
    // Plugins
    let mut plugins_dir = project_dir.clone();
    plugins_dir.push("plugins");
    if plugins_dir.is_dir() {
        for plugin_path in utils::entries_in_dir(&plugins_dir)? {
            if plugin_path.is_dir() {
                let plugin_name = utils::file_name_string(&plugin_path)?;
                let from_project = plugin_path
                    .strip_prefix(&project_dir)
                    .map_err(|e| er::error(format!("Strip path error: {:?}", e)))?;
                let server_path = Path::new("/var/www/html/wp-content").join(from_project);
                let mut plugin_conf_file = plugin_path.clone();
                site_data.plugins.insert(
                    plugin_name.clone(),
                    WpPlugin {
                        name: plugin_name,
                        paths: ProjectItemPaths::new(
                            from_project.to_path_buf(),
                            plugin_path,
                            server_path,
                        ),
                    },
                );
                plugin_conf_file.push("plugin.json");
                if plugin_conf_file.is_file() {
                    let plugin_conf_str = std::fs::read_to_string(&plugin_conf_file)?;
                    match serde_json::from_str::<PluginConf>(&plugin_conf_str) {
                        Ok(plugin_conf) => {
                            // Local plugin.json config
                            for dep in plugin_conf.deps {
                                // Could have something like "plugin_name:https://github.com/plugin"
                                // to expand capabilities (or something else)
                                site_data.deps.insert(dep);
                            }
                        }
                        Err(e) => println!("Deserialize error {:?}: {:?}", plugin_conf_file, e),
                    }
                }
            }
        }
    }
    let mut themes_dir = project_dir.clone();
    themes_dir.push("themes");
    if themes_dir.is_dir() {
        for theme_path in utils::entries_in_dir(&themes_dir)? {
            if theme_path.is_dir() {
                let theme_name = utils::file_name_string(&theme_path)?;
                let from_project = theme_path
                    .strip_prefix(&project_dir)
                    .map_err(|e| er::error(format!("Strip path error: {:?}", e)))?;
                let server_path = Path::new("/var/www/html/wp-content").join(from_project);
                site_data.themes.insert(
                    theme_name.clone(),
                    WpTheme {
                        name: theme_name,
                        paths: ProjectItemPaths::new(
                            from_project.to_path_buf(),
                            theme_path,
                            server_path,
                        ),
                    },
                );
            }
        }
    }
    Ok(site_data)
}

// Various info from wp installation
#[derive(Deserialize, Debug)]
pub struct WpInstallPlugin {
    pub name: String,
    pub status: String,
    pub update: String,
    pub version: String,
}
#[derive(Deserialize, Debug)]
pub struct WpInstallTheme {
    pub name: String,
    pub status: String,
    pub update: String,
    pub version: String,
}
#[derive(Deserialize, Debug)]
pub struct WpInstallData {
    pub plugins: HashMap<String, WpInstallPlugin>,
    pub themes: HashMap<String, WpInstallTheme>,
}
pub fn wp_install_data(cli_conn: &SshConn) -> Result<WpInstallData> {
    let plugins_output =
        match cli_conn.exec_capture("wp plugin list --format=json", Some("/var/www/html")) {
            Ok(output) => output,
            Err(e) => return Err(format_err!("Plugin list failed: {:?}", e)),
        };
    let themes_output =
        match cli_conn.exec_capture("wp theme list --format=json", Some("/var/www/html")) {
            Ok(output) => output,
            Err(e) => return Err(format_err!("Theme list failed: {:?}", e)),
        };
    let plugins = match serde_json::from_str::<Vec<WpInstallPlugin>>(&plugins_output) {
        Ok(plugins) => plugins,
        Err(e) => {
            return Err(format_err!("Failed deserialize plugins: {:?}", e));
        }
    };
    let themes = match serde_json::from_str::<Vec<WpInstallTheme>>(&themes_output) {
        Ok(themes) => themes,
        Err(e) => {
            return Err(format_err!("Failed deserialize themes: {:?}", e));
        }
    };
    let data = WpInstallData {
        plugins: plugins.into_iter().fold(HashMap::new(), |mut hm, p| {
            hm.insert(p.name.clone(), p);
            hm
        }),
        themes: themes.into_iter().fold(HashMap::new(), |mut hm, t| {
            hm.insert(t.name.clone(), t);
            hm
        }),
    };
    println!("WpData: {:#?}", data);
    Ok(data)
}

/*
pub fn sql_cli(_env: &CliEnv, sql: &str) -> Result<()> {
    use mysql_utils::Db;
    let mut db = Db::new("127.0.0.1", 3307, "wordpress", "wordpress", "wordpress")?;
    db.print_query(sql)?;
    Ok(())
}*/

/// Sets dev permissions for project
/// This might need to be used with root/sudo
pub fn dev_permissions(env: &CliEnv, project: &ProjectConfig) -> Result<()> {
    match dev_permissions_inner(env, project) {
        Ok(_) => Ok(()),
        Err(e) => {
            // Todo: Check specific error
            println!("Dev permissions failed: {:?}", e);
            println!("Do you need to run as sudo?");
            //Err(e)
            Ok(())
        }
    }
}
#[cfg(target_os = "linux")]
fn dev_permissions_inner(env: &CliEnv, project: &ProjectConfig) -> Result<()> {
    // todo: Not sure how best to do this. For now files are
    // owned by www-data, and I add user to www-data group and
    // set appropriate group permissions
    // Plugins
    use std::fs::{set_permissions, File};
    use std::os::unix::fs::PermissionsExt;
    for std_folder in &["plugins", "themes"] {
        for entry in server::iter_dir(
            project.dir_and(env, std_folder),
            None,
            crate::server::SyncIgnore::default(),
        )? {
            let entry = entry?;
            if entry.stats.is_file {
                // Somewhat inefficient to get metadata second time after iterator,
                // doing simple for now. Possibly we could as well keep metadata in
                // entry for all, or a special mode with retain metadata
                let file = File::open(&entry.path)?;
                let meta = file.metadata()?;
                let mut perms = meta.permissions();
                // Prod permission should be 644
                perms.set_mode(0o664);
                set_permissions(&entry.path, perms)?;
            } else if entry.stats.is_dir {
                let file = File::open(&entry.path)?;
                let meta = file.metadata()?;
                let mut perms = meta.permissions();
                // Prod permission should be 755
                perms.set_mode(0o775);
                set_permissions(&entry.path, perms)?;
            }
        }
    }
    Ok(())
}

// todo: I guess files should not be readonly on windows
// if they end up like that somehow
#[cfg(not(target_os = "linux"))]
fn dev_permissions_inner(env: &CliEnv, project: &ProjectConfig) -> Result<()> {
    Ok(())
}
