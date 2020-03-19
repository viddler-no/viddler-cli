use crate::aws;
use crate::cli;
use crate::docker;
use crate::git;
use crate::jitsi_project;
use crate::project;
use crate::server;
use crate::utils::{self, CliEnv};
use crate::workspace;
use crate::wp;
use failure::format_err;
use failure::Error;
use futures::future::lazy;
use std::path::PathBuf;

fn with_project<F, T>(env: &CliEnv, f: F) -> Result<T, failure::Error>
where
    F: FnOnce(project::ProjectConfig) -> Result<T, failure::Error>,
{
    match project::resolve_current_project_interactive(&env) {
        Ok(project) => f(project),
        Err(e) => {
            println!("Could not resolve project: {:?}", e);
            std::process::exit(1);
        }
    }
}

fn with_server<F, T>(env: &CliEnv, f: F) -> Result<T, failure::Error>
where
    F: FnOnce(server::ServerConfig) -> Result<T, failure::Error>,
{
    match server::select_server(env) {
        Ok(server) => f(server),
        Err(e) => {
            eprintln!("Error selecting server: {:?}", e);
            std::process::exit(1);
        }
    }
}

pub fn run() -> Result<(), failure::Error> {
    let mut clap_app = cli::cli_app();
    let matches = clap_app.clone().get_matches();
    //println!("{:#?}", matches);
    let home_dir = match dirs::home_dir() {
        Some(home_dir) => home_dir,
        None => {
            println!("Couldn't resolve home directory when resolving projects dir");
            std::process::exit(1);
        }
    };
    // Workdir dir
    let workdir_dir = match std::env::var("VIDDLER_PATH") {
        Ok(workdir) => std::path::PathBuf::from(workdir),
        Err(_) => {
            let mut workdir_dir = home_dir.clone();
            workdir_dir.push("code/viddler");
            workdir_dir
        }
    };
    // Projects dir
    let mut projects_dir = home_dir.clone();
    projects_dir.push("viddler");
    let env = CliEnv::new(projects_dir, workdir_dir);
    match matches.subcommand() {
        ("init", Some(_sub_matches)) => {
            actix_rt::System::new("project-api")
                .block_on(lazy(|| project::init_cmd(&env)))
                .map_err(|e| Error::from(e))
            //env.display_result(res);
        }
        ("setup-project", Some(_sub_matches)) => {
            with_project(&env, |mut project| jitsi_project::setup_project(&env, &mut project))
        }
        ("setup-project-prod", Some(_sub_matches)) => {
            with_project(&env, |mut project| jitsi_project::setup_project_prod(&env, &mut project))
        }
        ("dev", Some(sub_matches)) => {
            let args = match sub_matches.values_of_lossy("dev-args") {
                Some(args) => args,
                None => Vec::new(),
            };
            with_project(&env, |project| {
                let current_process = utils::CurrentProcess::new();
                docker::dev_cmd(&env, current_process, &project, args).map_err(|e| e.into())
            })
            .map(|_| ())
        }
        ("code", Some(_sub_matches)) => with_project(&env, |project| project::code(&env, &project)),
        ("push", Some(_sub_matches)) => {
            with_project(&env, |project| project::add_commit_push_git(&env, &project))
        }
        /*
        ("sql", Some(sub_matches)) => {
            let args = match sub_matches.values_of_lossy("sql-args") {
                Some(args) => args,
                None => Vec::new(),
            };
            let sql = args.join(" ");
            with_project(&env, |_project| wp::sql_cli(&env, &sql))
        }*/
        ("cli", Some(sub_matches)) => {
            let args = match sub_matches.values_of_lossy("cli-args") {
                Some(args) => args,
                None => Vec::new(),
            };
            with_project(&env, |mut project| {
                let current_process = utils::CurrentProcess::new();
                wp::wp_cli(&env, current_process, &mut project, args, false).map_err(|e| e.into())
            })
            .map(|_| ())
        }
        .map(|_| ()),
        ("dev-permissions", Some(_sub_matches)) => {
            with_project(&env, |project| wp::dev_permissions(&env, &project))
        }
        ("sync-local", Some(_sub_matches)) => with_project(&env, |mut project| {
            wp::sync_local(&env, &mut project, false)
        }),
        ("sync-server", Some(_sub_matches)) => {
            with_project(&env, |mut project| wp::sync_local(&env, &mut project, true))
        }
        ("content-to-prod", Some(_sub_matches)) => with_project(&env, |mut project| {
            wp::sync_content_to_prod(&env, &mut project)
        }),
        ("content-to-local", Some(_sub_matches)) => with_project(&env, |mut project| {
            wp::sync_content_to_local(&env, &mut project)
        }),
        ("clean-dev", Some(_sub_matches)) => with_project(&env, |project| {
            let current_process = utils::CurrentProcess::new();
            wp::wp_clean(&env, &project, current_process).map_err(|e| e.into())
        })
        .map(|_| ()),
        /*
        ("vscode-debug-config", Some(_sub_matches)) => with_project(&env, |project| {
            wp::gen_vscode_debug_config(&env, &project).map_err(|e| e.into())
        }),*/
        ("admin-server", Some(_sub_matches)) => {
            server::add_server(&env).map_err(|e| e.into()).map(|_| ())
        }
        ("admin-git-account", Some(_sub_matches)) => {
            git::add_user(&env).map(|_| ()).map_err(|e| e.into())
        }
        ("admin-aws", Some(_sub_matches)) => {
            // Credentials config
            aws::aws_config(&env).map_err(|e| e.into())
        }
        ("provision", Some(_sub_matches)) => {
            aws::provision_server(&env, false).map_err(|e| e.into())
        }
        ("deploy", Some(_sub_matches)) => with_server(&env, |server| {
            server::setup_server(&env, server).map_err(|e| e.into())
        }),
        ("docker-files-to-server", Some(_)) => {
            with_server(&env, |server| server::dockerfiles_to_server(&env, &server))
        }
        ("wp-ssh", Some(_sub_matches)) => server::wp_cli_ssh(&env, 2345, None),
        ("wp-ssh-server", Some(_sub_matches)) => {
            with_server(&env, |server| server::wp_cli_ssh(&env, 2345, Some(&server)))
        }
        ("ssh-server", Some(_sub_matches)) => with_server(&env, |server| server::ssh(&env, server)),
        ("prod", Some(sub_matches)) => {
            let args = match sub_matches.values_of_lossy("prod-args") {
                Some(args) => args,
                None => Vec::new(),
            };
            with_project(&env, |mut project| {
                project::prod(&env, &mut project, args, true)
            })
        }
        ("prod-locally", Some(sub_matches)) => {
            let args = match sub_matches.values_of_lossy("prod-args") {
                Some(args) => args,
                None => Vec::new(),
            };
            with_project(&env, |mut project| {
                project::prod(&env, &mut project, args, false)
            })
        }
        ("workspace-init", Some(_sub_matches)) => actix_rt::System::new("project-api")
            .block_on(lazy(|| workspace::init_git(&env)))
            .map_err(|e| Error::from(e)),
        ("workspace-push", Some(_sub_matches)) => {
            workspace::push_workspace(&env).map_err(|e| e.into())
        }
        ("workspace-clone", Some(_sub_matches)) => {
            workspace::clone_workspace(&env).map_err(|e| e.into())
        }
        ("rebuild-container", Some(sub_matches)) => {
            let service = match sub_matches.value_of_lossy("service") {
                Some(service) => service.to_string(),
                None => {
                    eprint!("Service name is required");
                    std::process::exit(1);
                }
            };
            with_project(&env, |project| {
                let current_process = utils::CurrentProcess::new();
                docker::rebuild_container(&env, current_process, &project, service)
                    .map_err(|e| e.into())
            })
            .map(|_| ())
        }
        ("rust-build-init", Some(_sub_matches)) => {
            let current_process = utils::CurrentProcess::new();
            docker::rust_build_init(&env, current_process)
        }
        ("proxy-log-server", Some(_sub_matches)) => with_project(&env, |mut project| {
            let current_process = utils::CurrentProcess::new();
            server::proxy_to_localhost(&env, current_process, &mut project, 7006, 7007)
        }),
        ("rust-build-update", Some(_sub_matches)) => {
            let current_process = utils::CurrentProcess::new();
            docker::rust_build_update(&env, current_process)
        }
        ("rebuild-log-dev", Some(_sub_matches)) => with_project(&env, |mut project| {
            let current_process = utils::CurrentProcess::new();
            docker::rebuild_rust_container(
                &env,
                "log_server",
                &vec![PathBuf::from("assets")],
                current_process,
                &mut project,
                false,
            )
        })
        .map(|_| ()),
        ("rebuild-log-prod", Some(_sub_matches)) => with_project(&env, |mut project| {
            let current_process = utils::CurrentProcess::new();
            docker::rebuild_rust_container(
                &env,
                "log_server",
                &vec![PathBuf::from("assets")],
                current_process,
                &mut project,
                true,
            )
        })
        .map(|_| ()),
        other => {
            env.error_msg(&format!("Command not recognized, {:?}", other));
            match clap_app.print_long_help() {
                Ok(_) => {
                    println!("");
                    Ok(())
                }
                Err(e) => Err(format_err!("Clap error: {:?}", e)),
            }
        }
    }
}
