// Handles config related to the workspace
// Current use case is setting up a git repo
// for the workspace

use crate::er::{self, Result};
use crate::git;
use crate::utils::{self, CliEnv};
use futures::{
    future::{self, Either},
    Future,
};

/// Initializes a git repo for the workspace, using
/// defined git account
pub fn init_git<'a>(env: &'a CliEnv) -> impl Future<Item = (), Error = failure::Error> + 'a {
    let git_config = match git::select_account(env, None) {
        Ok(git_account) => git_account,
        Err(e) => return Either::A(future::err(failure::Error::from(e))),
    };
    let repo_name = match env.get_input("Repo name", Some("workspace".into())) {
        Ok(repo_name) => repo_name,
        Err(e) => return Either::A(future::err(failure::Error::from(e))),
    };

    let dir_git = match git::inspect_git(env.config_dirs.config_root.clone()) {
        Ok(dir_git) => dir_git,
        Err(e) => return Either::A(future::err(failure::Error::from(e))),
    };

    let git_uri = git_config.repo_uri(repo_name);

    Either::B(
        git::setup_git_dir(env, dir_git, git_config, git_uri).map_err(|e| failure::Error::from(e)),
    )
}

/// Given git username and password, can recreate
/// the workspace (with todos)
pub fn clone_workspace(env: &CliEnv) -> Result<()> {
    let dir_git = git::inspect_git(env.config_dirs.config_root.clone())?;
    if dir_git.repo.is_some() {
        println!("Found existing repo, not proceeding with clone");
        return Ok(());
    } else if dir_git.has_files {
        println!("Found no repo, but existing files. Not proceeding with clone");
        println!("Could initialize repository instead");
        return er::err("No repo, but files");
    }

    let git_user = env.get_input("Git user", None)?;
    let repo_name = env.get_input("Repo name", Some("workspace".into()))?;
    let git_pass = env.get_pass("Git password")?;

    let repo_uri = format!("https://github.com/{}/{}", git_user, repo_name);

    Ok(git::clone_repo(
        git_user,
        git_pass,
        &repo_uri,
        &env.config_dirs.config_root,
    ))
}

// todo: Could run this automatically after config files have changed
// when repo is initialized, could propose to add if not
pub fn push_workspace(env: &CliEnv) -> Result<()> {
    let dir_git = git::inspect_git(env.config_dirs.config_root.clone())?;
    let repo = match dir_git.repo {
        Some(repo) => {
            println!("Found repo");
            repo
        }
        None => {
            // todo: propose run init
            println!("Please try workspace init-git, or setup repository manually");
            return er::err("No repo");
        }
    };
    // todo: Possibly not necessary, could test,
    // also good to err on side of doing it
    std::env::set_current_dir(&dir_git.dir)?;
    let tree = git::add_all(&repo)?;
    let default_msg = format!("Workspace commit: {}", utils::now_formatted());
    let message = env.get_input("Message", Some(default_msg))?;
    git::commit(&repo, tree, &message)?;
    git::push_origin_master(&repo)?;
    println!("Commit and push to origin successful");
    Ok(())
}
