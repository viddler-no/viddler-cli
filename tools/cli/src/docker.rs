use crate::er::Result;
use crate::project::ProjectConfig;
use crate::server::{SshConn, SyncBase, SyncSentCache, SyncSet};
use crate::utils::{self, CliEnv};
use failure::format_err;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process;

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct ComposeYml {
    pub version: String,
    pub services: IndexMap<String, ComposeService>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct ComposeService {
    pub volumes: Vec<String>,
    pub environment: IndexMap<String, String>,
}
impl ComposeYml {
    pub fn serialize(&self) -> Result<String> {
        match serde_yaml::to_string::<ComposeYml>(self) {
            Ok(yml_str) => Ok(yml_str),
            Err(e) => return Err(format_err!("{:?}", e)),
        }
    }
    pub fn save_if_diff(&self, path: &Path) -> Result<()> {
        if path.is_file() {
            let cur_str = std::fs::read_to_string(path)?;
            let current_yml: ComposeYml = serde_yaml::from_str(&cur_str)?;
            if self != &current_yml {
                let yml_str = self.serialize()?;
                println!("ComposeYml diff (old - new):");
                println!("{}", current_yml.serialize()?);
                println!("{}", &yml_str);
                utils::write_file(path, &yml_str)?;
                println!("Wrote {}", path.to_string_lossy());
                Ok(())
            } else {
                Ok(())
            }
        } else {
            let yml_str = self.serialize()?;
            println!("ComposeYml new:");
            println!("{}", &yml_str);
            utils::write_file(path, &yml_str)?;
            println!("Wrote {}", path.to_string_lossy());
            Ok(())
        }
    }
}

pub fn rebuild_container(
    env: &CliEnv,
    current_process: utils::CurrentProcess,
    project: &ProjectConfig,
    service: String,
) -> Result<utils::CurrentProcess> {
    println!("Rebuilding and restarting service: {}", service);
    // Todo: Should do the following only if dev is running
    // Todo: Option to remove volumes?
    let p = dev_cmds(
        env,
        current_process,
        project,
        vec![
            vec!["build".to_string(), service.clone()],
            vec!["up".to_string(), "-d".to_string(), service.clone()],
        ],
    )?;
    Ok(p)
}

/// Generic rebuild for a rust project with a container
/// by the same name
/// Assets are files or folders that should be moved from the rust source
/// into the container build folder
pub fn rebuild_rust_container(
    env: &CliEnv,
    project_name: &str,
    assets: &Vec<PathBuf>,
    mut current_process: utils::CurrentProcess,
    project: &mut ProjectConfig,
    prod: bool,
) -> Result<utils::CurrentProcess> {
    // This may change, but assuming rust project uses underscores, while
    // docker container is named with hyphens. Underscores has problems in docker
    // when attempting to use as url's with standard request libraries (as underscore
    // is not allowed in domains I believe)
    let hyphen_name = project_name.replace('_', "-");
    // Build rust binary, release if prod = true
    let (process, output_file) = rust_build(env, project_name, current_process, prod)?;
    current_process = process;
    let container_build_folder = if prod {
        env.workdir_dir.join(format!("server/prod/{}", hyphen_name))
    } else {
        env.workdir_dir.join(format!("server/dev/{}", hyphen_name))
    };
    let container_file = container_build_folder.join(&project_name);
    // Move output file to prod container
    std::fs::rename(output_file, container_file)?;
    // Assets
    let rust_project = env.workdir_dir.join(&format!("tools/{}", project_name));
    // Don't need sent cache since it should resolve nicely with modified times
    let mut sync_set = SyncSet::new(
        SyncBase::local(&rust_project),
        SyncBase::local(&container_build_folder),
        SyncSentCache::None,
    );
    for asset in assets {
        sync_set.resolve_local(rust_project.join(asset), false)?;
    }
    sync_set.sync_plain()?;
    if prod {
        let server = project.require_server(env)?;
        // todo: It would be nice with some abstraction for a location that kept the
        // connection in this case.
        crate::server::dockerfiles_to_server(env, &server)?;
        crate::project::prod_cmds(
            env,
            project,
            vec![
                vec!["build".to_string(), hyphen_name],
                vec!["up".to_string(), "-d".to_string()],
            ],
            true,
        )?;
        Ok(current_process)
    } else {
        rebuild_container(env, current_process, project, hyphen_name)
    }
}

/// Rebuilds proxy dev binary, then container and restarts the container
/// for given project
/// Todo: Replace these with rebuild_rust_container above
pub fn rebuild_proxy_dev(
    env: &CliEnv,
    mut current_process: utils::CurrentProcess,
    project: &ProjectConfig,
) -> Result<utils::CurrentProcess> {
    let (process, output_file) = rust_build(env, "proxy", current_process, false)?;
    current_process = process;
    // Move output file to proxy dev container
    let container_file = env.workdir_dir.join("server/dev/proxy-dev/proxy");
    std::fs::rename(output_file, container_file)?;
    rebuild_container(env, current_process, project, "proxy".into())
}

/// Rebuilds proxy prod binary, then container and restarts the container
/// for given project
pub fn rebuild_proxy_prod(
    env: &CliEnv,
    mut current_process: utils::CurrentProcess,
    project: &mut ProjectConfig,
) -> Result<utils::CurrentProcess> {
    let (process, output_file) = rust_build(env, "proxy", current_process, true)?;
    current_process = process;
    // Move output file to proxy dev container
    let container_file = env.workdir_dir.join("server/prod/proxy-prod/proxy");
    std::fs::rename(output_file, container_file)?;
    let server = project.require_server(env)?;
    // todo: It would be nice with some abstraction for a location that kept the
    // connection in this case.
    crate::server::dockerfiles_to_server(env, &server)?;
    crate::project::prod_cmds(
        env,
        project,
        vec![
            vec!["build".to_string(), "proxy".to_string()],
            vec!["up".to_string(), "-d".to_string()],
        ],
        true,
    )?;
    Ok(current_process)
}

/// Convencience for single command
#[inline]
pub fn dev_cmd(
    env: &CliEnv,
    current_process: utils::CurrentProcess,
    project: &ProjectConfig,
    user_args: Vec<String>,
) -> Result<utils::CurrentProcess> {
    dev_cmds(env, current_process, project, vec![user_args])
}

pub fn rust_build_init(env: &CliEnv, mut current_process: utils::CurrentProcess) -> Result<()> {
    // Ensure ssh service is up
    let build_container_dir = env.workdir_dir.join("server/build");
    std::env::set_current_dir(build_container_dir)?;

    // Ensure containers are updated
    let mut cmd = process::Command::new("docker-compose");
    cmd.args(&["build"]);
    // todo: Should check return codes
    current_process = current_process.spawn_and_wait(cmd, false)?;

    // Start containers
    let mut cmd = process::Command::new("docker-compose");
    cmd.args(&["up", "-d"]);
    let _ = current_process.spawn_and_wait(cmd, false)?;

    let ssh = SshConn::connect_container_ssh(env, 9857, "www-data", "www-data", None)?;
    // Installs cargo etc. There is a mode without docs etc for a typical ci setup, but some might be useful
    ssh.exec("curl --proto '=https' --tlsv1.2 https://sh.rustup.rs --output rustup-init.sh && sh rustup-init.sh -y")?;
    // It would be nice to fetch crates.io index
    Ok(())
}

pub fn rust_build_update(env: &CliEnv, mut current_process: utils::CurrentProcess) -> Result<()> {
    let ssh = SshConn::connect_container_ssh(env, 9857, "www-data", "www-data", None)?;
    // PATH should be in .profile
    ssh.exec("PATH=/var/www/.cargo/bin:$PATH && rustup update")?;
    Ok(())
}

/// Copies project code files through ssh to build container,
/// runs build in debug or release
/// Returns the path to the resulting binary
pub fn rust_build(
    env: &CliEnv,
    rust_project: &str,
    current_process: utils::CurrentProcess,
    release: bool,
) -> Result<(utils::CurrentProcess, PathBuf)> {
    // Keeping it simple, assuming service is up and initialized (see rust_build_init above),
    // todo: make more automated (detect running),
    // though we probably want initialize as separate command in any case
    let ssh = SshConn::connect_container_ssh(env, 9857, "www-data", "www-data", None)?;
    // Sync files except target directory
    let sftp = ssh.sftp()?;
    let tools_dir = env.workdir_dir.join("tools");
    let remote_tools_dir = PathBuf::from("/var/www/tools");
    let mut sync_set = SyncSet::new(
        SyncBase::local(&tools_dir),
        SyncBase::remote(&remote_tools_dir, &sftp),
        // todo: Prefix all of these
        SyncSentCache::load(env, "workdir-rust-build")?,
    );
    sync_set.ignore_rel_path("target");
    sync_set.ignore_dirname("node_modules");
    sync_set.resolve_local_remote(&tools_dir, &remote_tools_dir, false)?;
    sync_set.sync_plain()?;
    let build_cmd = if release {
        "cargo build --release"
    } else {
        "cargo build"
    };
    let rust_project_dir = format!("/var/www/tools/{}", rust_project);
    // PATH should be in .profile
    ssh.exec(format!(
        "PATH=/var/www/.cargo/bin:$PATH && cd {} && {}",
        rust_project_dir, build_cmd
    ))?;
    let (built_binary, output_folder, output_dest) = if release {
        // Expecting binary/name in cargo file to be the same as given rust_project
        let output_folder = String::from("/output/release");
        let output_dest = format!("{}/{}", output_folder, rust_project);
        (
            format!("/var/www/tools/target/release/{}", rust_project),
            output_folder,
            output_dest,
        )
    } else {
        let output_folder = String::from("/output/debug");
        let output_dest = format!("{}/{}", output_folder, rust_project);
        (
            format!("/var/www/tools/target/debug/{}", rust_project),
            output_folder,
            output_dest,
        )
    };
    // todo: Permissions for "output" is currently set to 777 to allow build user to write
    ssh.exec(format!(
        "mkdir -p {} && mv {} {}",
        output_folder, built_binary, output_dest
    ))?;
    let bin_local_path = if release {
        env.workdir_dir
            .join(&format!("server/build/output/release/{}", rust_project))
    } else {
        env.workdir_dir
            .join(&format!("server/build/output/debug/{}", rust_project))
    };
    Ok((current_process, bin_local_path))
}

/// Helper to collect a list of files,
/// useful to generate arguments to docker-compose
#[derive(Clone)]
pub struct ComposeCmd {
    project_name: String,
    server_dir: std::path::PathBuf,
    files: Vec<PathBuf>,
    user_args: Option<Vec<String>>,
}
impl ComposeCmd {
    pub fn local<N: Into<String>>(env: &CliEnv, name: N) -> Self {
        ComposeCmd {
            project_name: name.into(),
            server_dir: env.workdir_dir.join("server"),
            files: Vec::with_capacity(3),
            user_args: None,
        }
    }
    pub fn server<N: Into<String>>(name: N) -> Self {
        ComposeCmd {
            project_name: name.into(),
            // todo: Expecting to be called from a project folder
            // better would be probably absolute path
            server_dir: PathBuf::from("../../viddler/server"),
            files: Vec::with_capacity(3),
            user_args: None,
        }
    }

    pub fn workdir_file<F: AsRef<Path>>(&mut self, compose_file: F) -> &mut Self {
        self.files.push(self.server_dir.join(compose_file.as_ref()));
        self
    }

    pub fn relative_file<F: AsRef<Path>>(&mut self, compose_file: F) -> &mut Self {
        self.files.push(compose_file.as_ref().to_owned());
        self
    }

    pub fn user_args(&mut self, user_args: Vec<String>) -> &mut Self {
        self.user_args = Some(user_args);
        self
    }

    pub fn to_args(self) -> Vec<String> {
        let mut args: Vec<String> = self
            .files
            .iter()
            .flat_map(|file| vec!["-f".to_string(), file.to_string_lossy().to_string()])
            .collect();
        // Project name
        args.push("-p".into());
        args.push(self.project_name);
        match self.user_args {
            Some(user_args) => args.extend(user_args),
            None => {
                args.push("up".to_string());
                args.push("-d".to_string());
            }
        }
        args
    }
}

/// Allows multiple commands
// todo: Bit verbose to take String at times
pub fn dev_cmds(
    env: &CliEnv,
    mut current_process: utils::CurrentProcess,
    project: &ProjectConfig,
    cmds: Vec<Vec<String>>,
) -> Result<utils::CurrentProcess> {
    // Generating local docker
    // It would be nice to detect changes beforehand
    // Also it may be a little out of place with wp
    // specifics here. Some module system would be cool

    //crate::wp::create_wp_mounts_docker_yml(env, project)?;
    //crate::wp::create_backup_yml(env, project)?;

    let project_dir = project.dir(env);
    println!("{:?}", project_dir);
    std::env::set_current_dir(project_dir)?;
    let compose_name = format!("{}-dev", project.name);
    // Add base compose files
    let mut compose_cmd = ComposeCmd::local(env, compose_name);
    compose_cmd
        .workdir_file("base/docker-compose.yml")
        .workdir_file("dev/docker-compose.dev.yml");
    //.relative_file("docker/mounts.yml");

    // todo: Ensure docker-compose is installed
    for user_args in cmds {
        let mut compose_cmd = compose_cmd.clone();
        if user_args.len() > 0 {
            compose_cmd.user_args(user_args);
        }
        // Run command
        // By default, the command inherits stdin, out, err
        // when used with .spawn()
        let mut cmd = process::Command::new("docker-compose");
        cmd.args(compose_cmd.to_args());
        //cmd.arg("--remove-orphans");
        current_process = current_process.spawn_and_wait(cmd, false)?;
    }
    Ok(current_process)
}
