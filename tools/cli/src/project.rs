use crate::er::{self, Result};
use crate::git;
use crate::server;
use crate::utils::{self, CliEnv};
use failure::{format_err, Error};
use futures::{
    future::{self, Either},
    Future,
};
use serde::{Deserialize, Serialize};
use server::SshConn;
use std::io;
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ProjectConfig {
    pub name: String,
    pub git_user: String,
    pub git_repo_uri: String,
    pub git_backup_repo: String,
    pub server_name: Option<String>,
    pub domain: Option<String>,
}

impl ProjectConfig {
    /// Return project dir
    pub fn dir(&self, env: &CliEnv) -> PathBuf {
        project_dir(env, &self.name)
    }

    /// Returns project dir with extra joined onto it
    pub fn dir_and(&self, env: &CliEnv, extra: &str) -> PathBuf {
        let mut path = project_dir(env, &self.name);
        path.push(extra);
        path
    }

    /// Gets server config of project, or optionally creates
    pub fn get_server(
        &mut self,
        env: &CliEnv,
        or_create: bool,
    ) -> Result<Option<server::ServerConfig>> {
        match &self.server_name {
            Some(server_name) => server::get_config(env, server_name).map(Some),
            None => {
                if or_create {
                    // todo: Select whether to create
                    println!("No server registered, you can create one");
                    let servers = server::get_servers(env)?;
                    use utils::SelectOrAdd;
                    match env.select_or_add("Server", &servers, None)? {
                        SelectOrAdd::Selected(idx) => {
                            let server_name = servers
                                .get(idx)
                                .ok_or_else(|| er::Custom::msg("Could not find server index"))?;
                            self.server_name = Some(server_name.clone());
                            self.write_config(env)?;
                            Ok(Some(server::get_config(env, server_name)?))
                        }
                        SelectOrAdd::AddNew => {
                            let server_config = server::add_server(env)?;
                            self.server_name = Some(server_config.name.clone());
                            self.write_config(env)?;
                            Ok(Some(server_config))
                        }
                    }
                } else {
                    Ok(None)
                }
            }
        }
    }

    /// Can be used when a server is required,
    /// will get the current server, or when not specified, allow to
    /// define one
    pub fn require_server(&mut self, env: &CliEnv) -> Result<server::ServerConfig> {
        let server_opt = self.get_server(env, true)?;
        match server_opt {
            Some(server) => Ok(server),
            None => Err(er::Custom::msg("Project server required").into()),
        }
    }

    pub fn write_config(&self, env: &CliEnv) -> Result<()> {
        let content_str = serde_json::to_string_pretty(&self)?;
        // Todo: Consider keeping some in <project>/.project
        // Possibly this should be done after git setup after
        // this function, but might also be advantages saving the
        // data. The logic should handle it if re-running
        env.config_dirs.projects.write(&self.name, &content_str)?;
        Ok(())
    }

    /// Writes to a file given a path relative to
    /// project root
    pub fn write_file(&self, env: &CliEnv, file: &str, content: &str) -> Result<()> {
        let mut file_path = self.dir(env);
        file_path.push(file);
        utils::write_file(&file_path, content)
    }
}

pub fn has_config(env: &CliEnv, project: &str) -> bool {
    env.config_dirs.projects.has_file(project)
}

/// Resolves current project interactive, either
/// by figuring it out from the current directory,
/// or asking the user to select one
// todo: Possibly make ProjEnv over CliEnv
// (not so composy)
// or something lessen boilerplate a little
// shorter name
pub fn resolve_current_project_interactive(env: &CliEnv) -> Result<ProjectConfig> {
    match resolve_current_project(env) {
        Ok(project_confir) => Ok(project_confir),
        Err(_e) => {
            // Todo: Could allow init here if in appropriate directory
            let projects = get_projects(env)?;
            // A little speculative, but for now, auto select
            // project if there is only one
            if projects.len() == 1 {
                println!("Only one project, selecting {}!", projects[0]);
                get_config(env, &projects[0])
            } else {
                env.select("Select project", &projects, None)
                    .and_then(|i| match projects.get(i) {
                        Some(project_name) => get_config(env, project_name),
                        None => er::err("Error selecting project"),
                    })
            }
        }
    }
}

/// Resolve project from current directory, or error
pub fn resolve_current_project(env: &CliEnv) -> Result<ProjectConfig> {
    let cd = std::env::current_dir()?;
    let cd = cd
        .strip_prefix(&env.projects_dir)
        .map_err(|e| er::error(format!("{:?}", e)))?;
    // Then use first component
    match cd.components().next() {
        Some(std::path::Component::Normal(os_str)) => {
            match get_config(env, &os_str.to_string_lossy()) {
                Ok(project_config) => Ok(project_config),
                Err(e) => er::err(format!("Could not resolve project config: {:?}", e)),
            }
        }
        _ => er::err("Could not resolve project dir"),
    }
}

pub fn get_config(env: &CliEnv, project: &str) -> Result<ProjectConfig> {
    let json_file = std::fs::File::open(env.config_dirs.projects.filepath(project))?;
    let buf_reader = io::BufReader::new(json_file);
    let config = serde_json::from_reader::<_, ProjectConfig>(buf_reader)?;
    Ok(config)
}

/// Returns names of projects
pub fn get_projects(env: &CliEnv) -> Result<Vec<String>> {
    utils::files_in_dir(&env.config_dirs.projects.0)
}

pub fn project_dir(env: &CliEnv, project: &str) -> PathBuf {
    env.get_project_path(project)
}

fn init_project_config(env: &CliEnv) -> Result<(ProjectConfig, git::InspectGit)> {
    let name = env.get_input("Project name", None)?;
    let current_config = if has_config(env, &name) {
        println!("Project config exists for: {}", &name);
        println!("Modifying entry.");
        Some(get_config(env, &name)?)
    } else {
        println!(
            "Project config does not exist, collecting data for: {}",
            &name
        );
        None
    };
    // Git account
    let git_account =
        git::select_account(env, current_config.as_ref().map(|c| c.git_user.to_owned()))?;
    let git_user = git_account.user.clone();
    // Git repo
    let project_git = git::inspect_git(project_dir(env, &name))?;
    // Todo: !! Prevent tokened url when modifiying entry
    let git_repo_uri = match project_git.origin_url.as_ref() {
        Some(origin_url) => {
            println!(
                "Get repo uri (from existing origin): {}",
                console::style(origin_url).magenta()
            );
            origin_url.to_owned()
        }
        None => {
            let user_uri = format!("https://github.com/{}", &git_user);
            let mut repo_type_options = vec![
                format!(
                    "User repo ({})",
                    console::style(user_uri.clone() + "/..").dim()
                ),
                "Repo uri (user or existing)".to_string(),
            ];
            let default = match current_config.as_ref() {
                Some(current_config) => {
                    repo_type_options.push(format!("Current: {}", &current_config.git_repo_uri));
                    Some(2)
                }
                None => None,
            };
            let repo_type = env.select("Repo uri", &repo_type_options, default)?;
            // todo: Remove after select?
            // better to insert user repo as default input, not sure how
            match repo_type {
                0 => {
                    // User repo
                    let repo_name = env.get_input(&format!("User repo {}/", &user_uri), None)?;
                    format!("{}/{}", &user_uri, &repo_name)
                }
                1 => {
                    // Full repo uri
                    env.get_input("Repo uri", None)?
                }
                _ => return Err(er::Custom::msg("Unrecognized select").into()),
            }
        }
    };
    // Backup repo

    // Server
    let servers = server::get_servers(&env)?;
    let server_name = env
        .select_or_add_or_none(
            "Server",
            &servers,
            current_config.as_ref().and_then(|c| {
                c.server_name
                    .as_ref()
                    .and_then(|server_name| servers.iter().position(|e| e == server_name))
            }),
        )
        .and_then(|selected| {
            use utils::SelectOrAddOrNone;
            match selected {
                SelectOrAddOrNone::Selected(index) => servers
                    .get(index)
                    .ok_or_else(|| {
                        format_err!("Mismatched index when getting server: {}", index).into()
                    })
                    .map(|name| Some(name.to_owned())),
                SelectOrAddOrNone::AddNew => Ok(Some(server::add_server(env)?.name)),
                SelectOrAddOrNone::None => Ok(None),
            }
        })?;
    let domain = env
        .get_input(
            "Domain name",
            current_config.as_ref().and_then(|c| c.domain.to_owned()),
        )
        .map(|domain| {
            let domain = domain.trim();
            if domain.len() > 0 {
                Some(domain.to_string())
            } else {
                None
            }
        })?;
    // todo: This could possibly be improved. Could there be an existing backup dir?
    // It is also possible a non-user repo is selected, in which case this would break it
    let git_backup_repo = git_repo_uri.clone() + "-backup";
    let config = ProjectConfig {
        name,
        git_repo_uri,
        git_backup_repo,
        git_user,
        server_name,
        domain,
    };
    println!("{:?}", &config);

    config.write_config(env)?;
    Ok((config, project_git))
}

// Not ideally, but split initially with init_project_config
// to avoid type complexity with future and io:Result
pub fn init_cmd<'a>(env: &'a CliEnv) -> impl Future<Item = (), Error = Error> + 'a {
    let (config, project_git) = match init_project_config(env) {
        Ok(config) => config,
        Err(io_err) => return Either::A(future::err(Error::from(io_err))),
    };
    // Get projects git account
    let git_config = match git::get_config(env, &config.git_user) {
        Ok(git_config) => git_config,
        Err(io_err) => return Either::A(future::err(Error::from(io_err))),
    };
    Either::B(
        git::setup_git_dir(
            env,
            project_git,
            git_config.clone(),
            config.git_repo_uri.clone(),
        )
        .and_then(move |_| {
            git::do_create_remote(env, git_config, config.git_backup_repo).map(|_| ())
        }),
    )
}

pub fn code(env: &CliEnv, project: &ProjectConfig) -> Result<()> {
    use std::process::Command;
    let project_dir = project.dir(env);
    std::env::set_current_dir(&project_dir)?;
    let mut cmd = Command::new("code");
    cmd.arg(".");
    cmd.spawn()?;
    Ok(())
}

pub fn add_commit_push_git(env: &CliEnv, project: &ProjectConfig) -> Result<()> {
    let project_dir = project.dir(env);
    let dir_git = git::inspect_git(project_dir.clone())?;
    let repo = match dir_git.repo {
        Some(repo) => repo,
        None => {
            // todo: propose run init
            println!("No repository found in project: {}", project.name);
            return er::err("No repo");
        }
    };
    std::env::set_current_dir(&project_dir)?;
    let tree = git::add_all(&repo)?;
    let default_msg = format!("Project commit: {}", utils::now_formatted());
    let message = env.get_input("Message", Some(default_msg))?;
    git::commit(&repo, tree, &message)?;
    git::push_origin_master(&repo)?;
    println!("Commit and push to origin successful");
    Ok(())
}
/// Prod container command through ssh, or local prod
pub fn prod(
    env: &CliEnv,
    project: &mut ProjectConfig,
    user_args: Vec<String>,
    on_server: bool,
) -> Result<()> {
    prod_cmds(env, project, vec![user_args], on_server)
}

/// Prod container command through ssh
pub fn prod_cmds(
    env: &CliEnv,
    project: &mut ProjectConfig,
    cmds: Vec<Vec<String>>,
    on_server: bool,
) -> Result<()> {
    // Create command args
    use crate::docker::ComposeCmd;
    // Especially for local, there should be a different name for prod than dev
    let compose_name = format!("{}-prod", project.name);
    let mut compose_cmd = if on_server {
        ComposeCmd::server(compose_name)
    } else {
        ComposeCmd::local(env, compose_name)
    };
    compose_cmd
        .workdir_file("base/docker-compose.yml")
        .workdir_file("prod/docker-compose.prod.yml");
    if on_server {
        let server = match project.get_server(env, true)? {
            Some(server) => server,
            None => {
                return Err(format_err!(
                    "Missing server in project config, required for prod on server"
                ))
            }
        };
        let conn = SshConn::connect_server(env, &server)?;
        let cd = format!(
            "cd {}/projects/{}",
            server.home_dir().to_string_lossy(),
            project.name
        );
        for user_args in cmds.into_iter() {
            let mut compose_cmd = compose_cmd.clone();
            // Apply user_args or default to "up"
            if user_args.len() > 0 {
                compose_cmd.user_args(user_args);
            }
            // Run compose command
            conn.exec(format!(
                "{}; docker-compose {}",
                cd,
                compose_cmd.to_args().join(" ")
            ))?;
        }
    } else {
        // Run prod locally
        // todo: Maybe there should just be a dedicated function for local
        /*
        crate::wp::create_docker_local_prod_yml(env, project)?;
        compose_cmd.relative_file("docker/prod-local.yml");
        crate::wp::create_wp_mounts_docker_yml(env, project)?;
        compose_cmd.relative_file("docker/mounts.yml");
        */
        let project_dir = project.dir(env);
        println!("{:?}", project_dir);
        std::env::set_current_dir(project_dir)?;
        for user_args in cmds.into_iter() {
            let mut compose_cmd = compose_cmd.clone();
            // Apply user_args or default to "up"
            if user_args.len() > 0 {
                compose_cmd.user_args(user_args);
            }
            // Run compose command
            // By default, the command inherits stdin, out, err
            // when used with .spawn()
            let mut cmd = std::process::Command::new("docker-compose");
            let cmd_args = compose_cmd.to_args();
            println!("{:?}", cmd_args);
            cmd.args(cmd_args);
            cmd.spawn()?;
        }
    }
    Ok(())
}
