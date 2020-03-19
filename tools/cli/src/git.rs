use crate::er::{self, Result};
use crate::utils::{self, CliEnv};
use actix_web::{
    http::{self, uri::Uri},
    web,
};
use awc::Client;
use failure::Error;
use futures::stream::Stream;
use futures::{
    future::{self, Either},
    Future,
};
use graphql_client::*;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

// Could have a site key here. For now, only github is
// supported/implemented anyway
#[derive(Serialize, Deserialize, Clone)]
pub struct GitConfig {
    pub user: String,
    pub email: String,
    pub token: String,
}

impl GitConfig {
    pub fn repo_uri(&self, repo_name: String) -> String {
        format!("https://github.com/{}/{}", self.user, repo_name)
    }
}

pub fn has_config(env: &CliEnv, user: &str) -> bool {
    env.config_dirs.git_accounts.has_file(user)
}

pub fn get_config(env: &CliEnv, user: &str) -> Result<GitConfig> {
    let json_file = std::fs::File::open(env.config_dirs.git_accounts.filepath(user))?;
    let buf_reader = io::BufReader::new(json_file);
    let config = serde_json::from_reader::<_, GitConfig>(buf_reader)?;
    Ok(config)
}

pub fn get_accounts(env: &CliEnv) -> Result<Vec<String>> {
    utils::files_in_dir(&env.config_dirs.git_accounts.0)
}

pub fn select_account(env: &CliEnv, default: Option<String>) -> Result<GitConfig> {
    let entries = get_accounts(&env)?;
    if entries.len() == 0 {
        // No existing accounts, allow user to create one
        println!("No git accounts registered, please input one");
        return add_user(env);
    }
    let key = env
        .select(
            "Git account",
            &entries,
            default.and_then(|key| entries.iter().position(|e| *e == key)),
        )
        .and_then(|i| {
            entries
                .get(i)
                .ok_or_else(|| er::error("Could not resolve account").into())
        })?
        .to_owned();
    get_config(env, &key)
}

/// Add or modify git account
pub fn add_user(env: &CliEnv) -> Result<GitConfig> {
    // Todo: It would be nice to allow "proxy" git communications
    // where the project participants is administered

    // List current accounts
    let current_files = utils::files_in_dir(&env.config_dirs.git_accounts.0)?;
    if current_files.len() > 0 {
        println!("Current accounts:");
        for file in current_files {
            println!("{}", file);
        }
    } else {
        println!("No existing accounts");
    }

    let user = env.get_input("Git user", None)?;
    let current_config = if has_config(env, &user) {
        println!("Account config exists for: {}", &user);
        println!("Modifying entry.");
        Some(get_config(env, &user)?)
    } else {
        None
    };
    let email = env.get_input(
        "Git email",
        current_config.as_ref().map(|c| c.email.to_string()),
    )?;
    let token = env.get_input("Git token", current_config.map(|c| c.token))?;

    let config = GitConfig { user, email, token };

    let content_str = match serde_json::to_string_pretty(&config) {
        Ok(content_str) => content_str,
        Err(e) => return Err(er::SerdeJson::e(e).into()),
    };

    env.config_dirs
        .git_accounts
        .write(&config.user, &content_str)?;
    println!("Wrote git account: {}", &config.user);
    Ok(config)
}

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/github_schema.graphql",
    query_path = "src/graphql/check_repo_exists.graphql",
    response_derives = "Debug"
)]
struct CheckRepoExists;

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum RepoExistsError {
    RepoParseFailed(String),
    HostNotSupported,
    ApiError(GithubApiError),
}

pub struct GitUriParts {
    pub host: String,
    pub owner: String,
    pub repo_name: String,
}

pub fn parse_git_uri(repo_uri: &str) -> Result<GitUriParts> {
    let repo_uri = match repo_uri.parse::<Uri>() {
        Ok(uri) => uri,
        Err(_) => {
            return er::err("Could not parse uri");
        }
    };
    let host = match repo_uri.host() {
        Some(host) => {
            if host != "github.com" {
                return er::err("Host not supported");
            } else {
                host
            }
        }
        None => return er::err("Host not found"),
    };
    let path = Path::new(repo_uri.path());
    let path_names = path
        .components()
        .filter_map(|c| match c {
            std::path::Component::Normal(name) => Some(name),
            _ => None,
        })
        .collect::<Vec<_>>();
    if path_names.len() < 2 {
        return er::err("Repo owner and name not found");
    };
    let repo_owner = path_names[0];
    // Strip .git from repo_name
    let repo_name = {
        let repo_name = PathBuf::from(path_names[1]);
        // Strip .git from repo_name if there
        if repo_name.extension() == Some(std::ffi::OsStr::new("git")) {
            match repo_name.file_stem() {
                Some(stem) => stem.to_owned(),
                None => return er::err("Repo name not recognized"),
            }
        } else {
            path_names[1].to_owned()
        }
    };
    Ok(GitUriParts {
        host: host.to_string(),
        owner: repo_owner.to_string_lossy().to_string(),
        repo_name: repo_name.to_string_lossy().to_string(),
    })
}

pub struct InspectGit {
    pub dir: PathBuf,
    pub has_dir: bool,
    pub has_files: bool,
    pub repo: Option<git2::Repository>,
    pub origin_url: Option<String>,
}

pub fn inspect_git(dir: PathBuf) -> Result<InspectGit> {
    let (has_dir, has_files, repo, origin_url) = if !dir.is_dir() {
        // Dir does not yet exist
        (false, false, None, None)
    } else if dir.is_file() {
        return er::err("Given directory is a file");
    } else {
        println!("Directory exists");
        let has_files = match crate::utils::entries_in_dir(&dir) {
            Ok(entries) => entries.len() > 0,
            Err(err) => return Err(err),
        };
        let mut git_dir = dir.clone();
        git_dir.push(".git");
        if git_dir.is_dir() {
            println!("Git repo found");
            match git2::Repository::open(&dir) {
                Ok(repo) => {
                    let origin_url = match repo.find_remote("origin") {
                        Ok(remote) => match remote.url() {
                            Some(origin_url) => Some(origin_url.to_owned()),
                            None => {
                                println!("Could not parse origin url to utf8, aborting");
                                return er::err("Could not parse origin url to utf8");
                            }
                        },
                        Err(_err) => {
                            println!("No remote named `origin` in repository");
                            None
                        }
                    };
                    (true, has_files, Some(repo), origin_url)
                }
                Err(err) => {
                    println!("Failed opening existing repository, aborting: {:?}", err);
                    return er::err(format!("Failed opening existing repo: {:?}", err));
                }
            }
        } else {
            println!("Directory found without repository");
            (true, has_files, None, None)
        }
    };
    Ok(InspectGit {
        dir,
        has_dir,
        has_files,
        repo,
        origin_url,
    })
}

// 6b44cec414da957b9c31be12a38af1345f7d8481
// Todo: Differentiate no access and non-exist
// if not already?
pub fn check_repo_exists(
    git_account: &GitConfig,
    repo_uri: &str,
) -> impl Future<Item = bool, Error = RepoExistsError> {
    let uri_parts = match parse_git_uri(repo_uri) {
        Ok(parts) => parts,
        Err(err) => {
            return Either::A(future::err(RepoExistsError::RepoParseFailed(format!(
                "{:?}",
                err
            ))))
        }
    };
    // Make github request
    let query = CheckRepoExists::build_query(check_repo_exists::Variables {
        owner: uri_parts.owner,
        name: uri_parts.repo_name,
    });
    let response = github_api_query::<_, check_repo_exists::ResponseData>(
        &git_account.token,
        &git_account.user,
        query,
    );
    Either::B(
        response
            .map_err(|e| RepoExistsError::ApiError(e))
            .and_then(|r| {
                println!("{:#?}", r);
                Ok(r.repository.is_some())
            }),
    )
}

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/github_schema.graphql",
    query_path = "src/graphql/viewer_info.graphql",
    response_derives = "Debug"
)]
struct ViewerInfo;
pub fn viewer_info(
    git_account: &GitConfig,
) -> impl Future<Item = viewer_info::ResponseData, Error = GithubApiError> {
    // Make github request
    let query = ViewerInfo::build_query(viewer_info::Variables {});
    github_api_query::<_, viewer_info::ResponseData>(&git_account.token, &git_account.user, query)
}

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/github_schema.graphql",
    query_path = "src/graphql/create_remote_repo.graphql",
    response_derives = "Debug"
)]
struct CreateRemoteRepo;
pub fn create_remote_repo(
    git_account: &GitConfig,
    name: String,
    owner_id: String,
) -> impl Future<Item = create_remote_repo::ResponseData, Error = GithubApiError> {
    // Make github request
    let query = CreateRemoteRepo::build_query(create_remote_repo::Variables { name, owner_id });
    github_api_query::<_, create_remote_repo::ResponseData>(
        &git_account.token,
        &git_account.user,
        query,
    )
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum GithubApiError {
    NetworkError(String),
    DeserializeError(String, String),
}

fn github_api_query<V: serde::Serialize, R: serde::de::DeserializeOwned>(
    token: &str,
    github_user: &str,
    query: QueryBody<V>,
) -> impl Future<Item = R, Error = GithubApiError> {
    let client = Client::default();
    client
        .post("https://api.github.com/graphql")
        .bearer_auth(token)
        .header(http::header::USER_AGENT, github_user)
        .timeout(std::time::Duration::from_secs(15))
        .send_json(&query)
        .map_err(|e| GithubApiError::NetworkError(format!("{:?}", e)))
        .and_then(|r| {
            r.map_err(|e| GithubApiError::NetworkError(format!("{:?}", e)))
                .fold(web::BytesMut::new(), move |mut body, chunk| {
                    body.extend_from_slice(&chunk);
                    Ok::<_, GithubApiError>(body)
                })
                .and_then(move |body| {
                    let body = body.freeze().to_vec();
                    let body = String::from_utf8_lossy(&body);
                    //println!("{}", &body);
                    // Graphql client seems to work with the data
                    // below "data" key.
                    let body2 = body.clone();
                    serde_json::from_str::<serde_json::Value>(&body)
                        .map_err(|e| {
                            GithubApiError::DeserializeError(format!("{:?}", e), body2.into())
                        })
                        .and_then(|json_value| {
                            //println!("{:#?}", &json_value);
                            // The json may contain an error message
                            // {"repository":null},"errors":[{"type":"NOT_FOUND","path":["repository"],
                            // "locations":[{"line":2,"column":5}],
                            // "message":"Could not resolve to a Repository with the name 'unknow-repo-name'."}
                            match json_value {
                                serde_json::Value::Object(map) => match map.get("data") {
                                    Some(data_value) => serde_json::from_value::<R>(
                                        data_value.clone(),
                                    )
                                    .map_err(|e| {
                                        GithubApiError::DeserializeError(
                                            format!("{:?}", e),
                                            body.into(),
                                        )
                                    }),
                                    None => Err(GithubApiError::DeserializeError(
                                        "Data key not found in root".to_string(),
                                        body.into(),
                                    )),
                                },
                                _ => Err(GithubApiError::DeserializeError(
                                    "Json root not object".to_string(),
                                    body.into(),
                                )),
                            }
                        })
                })
        })
}

/// Clone git repo
/// Note that git_pass in the case of github also can be
/// passed a token.
// TODO: Errors
pub fn clone_repo(git_user: String, git_pass: String, repo_uri: &str, clone_to: &Path) {
    // Progress bars
    let indexed_status = indicatif::ProgressBar::new(0);
    indexed_status.set_style(
        indicatif::ProgressStyle::default_bar().template("{bar:25} {pos}/{len} objects {msg}"),
    );
    // Attempt to clone repository
    let mut options = git2::FetchOptions::new();
    let mut callbacks = git2::RemoteCallbacks::new();
    callbacks
        .credentials(|repo_uri, arg2, cred_type| {
            println!("repo_uri: {}, arg2: {:?}", repo_uri, arg2);
            if cred_type.is_user_pass_plaintext() {
                println!("Userpass plain");
                git2::Cred::userpass_plaintext(&git_user, &git_pass)
            } else if cred_type.is_username() {
                println!("Username");
                git2::Cred::username(&git_user)
            } else {
                Err(git2::Error::from_str(&format!(
                    "Unrecognized cred type: {:?}",
                    cred_type
                )))
            }
        })
        .transfer_progress(|p| {
            indexed_status.set_length(p.total_objects() as u64);
            indexed_status.set_position(p.indexed_objects() as u64);
            indexed_status.set_message(&format!(
                "{}",
                indicatif::HumanBytes(p.received_bytes() as u64)
            ));
            true
        });
    options.remote_callbacks(callbacks);
    let mut clone_builder = git2::build::RepoBuilder::new();
    clone_builder.fetch_options(options);
    match clone_builder.clone(repo_uri, clone_to) {
        Ok(_repo) => {
            println!("Cloned repo");
        }
        Err(err) => {
            println!("Clone error {:?}", err);
        }
    }
    indexed_status.finish();
}

pub fn set_account_config(config: &GitConfig, repo: &git2::Repository) -> Result<()> {
    let mut c = repo.config()?;
    c.open_level(git2::ConfigLevel::Local)?;
    c.set_str("user.name", &config.user)?;
    c.set_str("user.email", &config.email)?;
    Ok(())
}

pub fn name_email_from_repo(repo: &git2::Repository) -> Result<(String, String)> {
    let c = repo.config()?;
    let name = c.get_string("user.name")?;
    let email = c.get_string("user.email")?;
    Ok((name, email))
}

#[derive(Clone, Eq, PartialEq, Debug, Fail)]
pub enum SetupGitError {
    GitError(String),
    ApiError(GithubApiError),
    CheckRepoError(RepoExistsError),
}
impl fmt::Display for SetupGitError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

pub fn setup_git_dir<'a>(
    env: &'a CliEnv,
    dir_git: InspectGit,
    git_config: GitConfig,
    git_repo_uri: String,
) -> impl Future<Item = (), Error = failure::Error> + 'a {
    // Decide what to do based on status of inspected directory git
    let init_repo = match dir_git.repo {
        Some(repo) => {
            match dir_git.origin_url {
                Some(_origin_url) => {
                    // We are pretty much done when project already
                    // has git repository with origin_url.
                    // Todo: Could propose to save credientials somehow
                    Either::A(future::ok((repo, git_config)))
                }
                None => {
                    // Repo without origin
                    // If remote does not exist, we can create it and
                    // initialize with this repository
                    // If remote exists, we fail communicating the problem
                    Either::B(Either::A(
                        check_repo_exists(&git_config, &git_repo_uri)
                            .map_err(|e| Error::from(SetupGitError::CheckRepoError(e)))
                            .and_then(move |exists| {
                                if exists {
                                    env.error_msg("There is both a local repository, and a remote.");
                                    env.error_msg("Please move local files, redo process and manually merge if intended.");
                                    Either::A(future::err(Error::from(SetupGitError::GitError("Both local and remote repo".into()))))
                                } else {
                                    Either::B(do_create_remote(env, git_config, git_repo_uri.clone())
                                        .map_err(|e| Error::from(e))
                                        .and_then(move |git_config| {
                                            // Repository created, now add as origin to local repository
                                            let origin_uri = match make_origin_url(&git_config, &git_repo_uri) {
                                                Ok(origin_uri) => origin_uri,
                                                Err(err) => {
                                                    println!("Warning: Parse error: {:?}, using original uri", err);
                                                    git_repo_uri
                                                }
                                            };
                                            match repo.remote("origin", &origin_uri) {
                                                Ok(_remote) => (),
                                                Err(err) => return Err(Error::from(SetupGitError::GitError(format!("{:?}", err))))
                                            };
                                            // Should be ready for push,
                                            // possibly there should be a push here
                                            Ok((repo, git_config))
                                        }))
                                }
                            }),
                    ))
                }
            }
        }
        None => {
            // No repo yet.
            // If there is no remote, create it and initialize repo
            // If remote exist, we can clone if dir is empty,
            // else fail communicating need for empty dir
            // Possibly we could do some merging, but may be better
            // to let user handle
            Either::B(Either::B(
                check_repo_exists(&git_config, &git_repo_uri)
                    .map_err(|e| Error::from(SetupGitError::CheckRepoError(e)))
                    .and_then(move |exists| {
                        let target_path = dir_git.dir.clone();
                        if exists {
                            // We need empty, or no dir to clone
                            if dir_git.has_dir && dir_git.has_files {
                                env.error_msg("A remote repository exist and the target folder is not empty.");
                                env.error_msg("Please move files out, re-run the process, then manually merge files as intended.");
                                return Either::A(future::err(Error::from(SetupGitError::GitError("Non empty dir".into()))));
                            }
                            // Clone existing
                            clone_repo(git_config.user.clone(), git_config.token.clone(), &git_repo_uri, &target_path);
                            match git2::Repository::open(target_path) {
                                Ok(repo) => Either::A(future::ok((repo, git_config))),
                                Err(err) => Either::A(future::err(Error::from(SetupGitError::GitError(format!("Could not open repository: {:?}", err)))))
                            }
                        } else {
                            // Repository does not exist, attempt to create
                            // Local repo does not exist, but there might be
                            // files
                            Either::B(do_create_remote(env, git_config, git_repo_uri.clone())
                                .and_then(move |git_config| {
                                    // Remote repository created
                                    match git2::Repository::init(&target_path) {
                                        Ok(repo) => {
                                            let origin_uri = match make_origin_url(&git_config, &git_repo_uri) {
                                                Ok(origin_uri) => origin_uri,
                                                Err(err) => {
                                                    println!("Warning: Parse error: {:?}, using original uri", err);
                                                    git_repo_uri
                                                }
                                            };
                                            match repo.remote("origin", &origin_uri) {
                                                Ok(_remote) => (),
                                                Err(err) => return Err(Error::from(SetupGitError::GitError(format!("{:?}", err))))
                                            };
                                            // Should be ready for push,
                                            // possibly there should be a push here
                                            Ok((repo, git_config))
                                        }
                                        Err(err) => Err(Error::from(SetupGitError::GitError(format!("Could not init local repository: {:?}", err))))
                                    }
                                }))
                        }
                    }),
            ))
        }
    };
    init_repo.and_then(|(repo, git_config)| {
        // Here, repo should be initialized
        // Just setting config git user and email here,
        // and confirming repo location
        match set_account_config(&git_config, &repo) {
            Ok(_) => (),
            Err(err) => return Err(Error::from(SetupGitError::GitError(format!("{:?}", err)))),
        };
        match repo.workdir() {
            Some(work_dir) => {
                println!("Repository at: {}", work_dir.display());
            }
            None => println!("Warning: Working directory of new git repository not resolved."),
        };
        Ok(())
    })
}

pub fn do_create_remote<'a>(
    env: &'a CliEnv,
    git_config: GitConfig,
    git_repo_uri: String,
) -> impl Future<Item = GitConfig, Error = failure::Error> + 'a {
    // Create remote
    // Currently require owner to be the same as git_account
    let uri_parts = match parse_git_uri(&git_repo_uri) {
        Ok(parts) => parts,
        Err(err) => {
            return Either::A(future::err(Error::from(SetupGitError::GitError(format!(
                "Git uri parse error: {}",
                err
            )))))
        }
    };
    let repo_name2 = uri_parts.repo_name.clone();
    if &uri_parts.owner != &git_config.user {
        env.error_msg("Cannot currently create repository with a different owner from user.");
        env.error_msg("Create the repository manually, then re-run this process,");
        env.error_msg("or create a repository with the given git account.");
    }
    Either::B(
        viewer_info(&git_config)
            .map_err(|e| Error::from(SetupGitError::ApiError(e)))
            .and_then(move |viewer_info| {
                create_remote_repo(&git_config, uri_parts.repo_name, viewer_info.viewer.id)
                    .map_err(|e| Error::from(SetupGitError::ApiError(e)))
                    .and_then(move |create_remote_repo| {
                        if create_remote_repo.create_repository.is_some() {
                            // todo: --set-upstream?
                            println!("Created private repository: {}", repo_name2);
                            future::ok(git_config)
                        } else {
                            future::err(Error::from(SetupGitError::GitError(
                                "Create repo failed".into(),
                            )))
                        }
                    })
            }),
    )
}

pub fn make_origin_url(config: &GitConfig, repo_uri: &str) -> Result<String> {
    // Todo: This is not good security
    // Would like some credientials helper
    // or other solution
    let parts = parse_git_uri(repo_uri)?;
    Ok(format!(
        "https://{}:{}@{}/{}/{}",
        config.user, config.token, parts.host, parts.owner, parts.repo_name
    ))
}

pub fn add_all(repo: &git2::Repository) -> Result<git2::Tree> {
    let mut index = match repo.index() {
        Ok(index) => index,
        Err(e) => {
            eprintln!("Couldn't get repo index: {:?}", e);
            return er::err(format!("Get index failed: {:?}", e));
        }
    };
    let cb = &mut |path: &std::path::Path, _matched_spec: &[u8]| -> i32 {
        // Return 0 = add, 1 = skip, -1 = error
        match repo.status_file(path) {
            Ok(status) => {
                if status.is_index_new() {
                    println!("Index new: {:?}", path);
                    0
                } else if status.is_index_modified() {
                    println!("Index modified: {:?}", path);
                    0
                } else if status.is_index_deleted() {
                    println!("Index deleted: {:?}", path);
                    0
                } else if status.is_index_renamed() {
                    println!("Index renamed: {:?}", path);
                    0
                } else if status.is_index_typechange() {
                    println!("Index typechange: {:?}", path);
                    0
                } else if status.is_wt_new() {
                    println!("New: {:?}", path);
                    0
                } else if status.is_wt_modified() {
                    println!("Modified: {:?}", path);
                    0
                } else if status.is_wt_deleted() {
                    println!("Deleted: {:?}", path);
                    0
                } else if status.is_wt_renamed() {
                    println!("Renamed: {:?}", path);
                    0
                } else if status.is_wt_typechange() {
                    println!("Typechange: {:?}", path);
                    0
                } else if status.is_ignored() {
                    println!("Ignored: {:?}", path);
                    1
                } else if status.is_conflicted() {
                    println!("Conflicted: {:?}", path);
                    1
                } else {
                    println!("Status other: {:?}", status);
                    1
                }
            }
            Err(_) => {
                eprintln!("Could not get status for file: {:?}", path);
                -1
            }
        }
    };
    // Add all
    // todo: If any changes
    match index.add_all(
        vec![".".to_string()],
        git2::IndexAddOption::DEFAULT,
        Some(cb as &mut git2::IndexMatchedPath),
    ) {
        Ok(_) => println!("Added files"),
        Err(e) => {
            eprintln!("Error adding files: {:?}", e);
            return er::err("Error adding files");
        }
    }
    match index.write() {
        Ok(_) => (),
        Err(e) => return er::err(format!("Failed to write index: {:?}", e)),
    }
    // Index tree
    // todo: Don't think this will work for first commit
    let tree = match index.write_tree() {
        Ok(oid) => match repo.find_tree(oid) {
            Ok(tree) => tree,
            Err(e) => return er::err(format!("Error finding index tree: {:?}", e)),
        },
        Err(e) => return er::err(format!("Error writing tree: {:?}", e)),
    };
    Ok(tree)
}

pub fn commit(repo: &git2::Repository, tree: git2::Tree, message: &str) -> Result<()> {
    // Commit
    let signature = match name_email_from_repo(&repo) {
        Ok((conf_name, conf_email)) => match git2::Signature::now(&conf_name, &conf_email) {
            Ok(signature) => signature,
            Err(e) => return er::err(format!("Error creating signature: {:?}", e)),
        },
        Err(e) => {
            eprintln!("Failed getting name and email from config: {:?}", e);
            return er::err("Failed getting name and email from config");
        }
    };
    // Get parent commit(s)
    // https://stackoverflow.com/questions/27672722/libgit2-commit-example
    let head_commit = match repo.head() {
        Ok(head) => match head.peel_to_commit() {
            Ok(commit) => Some(commit),
            Err(e) => return er::err(format!("Failed getting commit of head: {:?}", e)),
        },
        Err(_e) => None,
    };
    let parents = match &head_commit {
        Some(head_commit) => vec![head_commit],
        None => vec![],
    };
    // todo: Git lessons...
    let _oid = match repo.commit(
        Some("HEAD"),
        &signature,
        &signature,
        &message,
        &tree,
        &parents,
    ) {
        Ok(oid) => oid,
        Err(e) => return er::err(format!("Commit error: {:?}", e)),
    };
    Ok(())
}

pub fn push_origin_master(repo: &git2::Repository) -> Result<()> {
    // Get origin remote
    let mut origin = match repo.find_remote("origin") {
        Ok(remote) => remote,
        Err(e) => return er::err(format!("Error getting origin remote: {:?}", e)),
    };
    // Make callback with reference push feedback
    let mut remote_callbacks = git2::RemoteCallbacks::new();
    remote_callbacks.push_update_reference(|ref_name, status| {
        match status {
            None => {
                println!("Reference push ok: {}", ref_name);
            }
            Some(error) => {
                eprintln!("Reference push error: {}, {}", ref_name, error);
            }
        }
        Ok(())
    });
    let mut push_options = git2::PushOptions::new();
    push_options.remote_callbacks(remote_callbacks);
    // Do push
    // todo: I don't quite understand refs
    match origin.push(&["refs/heads/master"], Some(&mut push_options)) {
        Ok(_) => Ok(()),
        Err(e) => er::err(format!("Push error: {:?}", e)),
    }
}
