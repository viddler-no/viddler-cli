use console::style;
use dialoguer::{theme, Input, Select};
use std::fs;
use std::path::{Path, PathBuf};

use shared_child::SharedChild;
use std::sync::Arc;
use std::sync::RwLock;

use std::net::TcpStream;
use std::net::ToSocketAddrs;

use crate::er::{self, Result};

pub struct ConfigDir(pub PathBuf);

impl ConfigDir {
    pub fn new(config_root: &PathBuf, folder: &str) -> ConfigDir {
        let mut config_dir = config_root.clone();
        config_dir.push(folder);
        ConfigDir(config_dir)
    }

    pub fn filepath(&self, file: &str) -> PathBuf {
        let mut filepath = self.0.clone();
        filepath.push(file);
        filepath
    }

    pub fn has_file(&self, file: &str) -> bool {
        let mut test = self.0.clone();
        test.push(file);
        test.is_file()
    }

    /// Write to a file relative to config dir
    /// Will ensure parent dir exist and create if not
    pub fn write(&self, file: &str, content: &str) -> Result<()> {
        write_file(&self.filepath(file), content)
    }
}

pub struct ConfigDirs {
    pub git_accounts: ConfigDir,
    pub projects: ConfigDir,
    pub servers: ConfigDir,
    pub config_root: PathBuf,
}

impl ConfigDirs {
    pub fn new(projects_dir: PathBuf) -> ConfigDirs {
        let mut config_root = projects_dir.clone();
        config_root.push(".config");
        ConfigDirs {
            git_accounts: ConfigDir::new(&config_root, "git_accounts"),
            projects: ConfigDir::new(&config_root, "projects"),
            servers: ConfigDir::new(&config_root, "servers"),
            config_root,
        }
    }
}

pub struct CliEnv {
    pub projects_dir: PathBuf,
    pub workdir_dir: PathBuf,
    pub config_dirs: ConfigDirs,
    theme: theme::ColorfulTheme,
}

pub enum SelectOrAdd {
    Selected(usize),
    AddNew,
}

pub enum SelectOrAddOrNone {
    Selected(usize),
    AddNew,
    None,
}

impl CliEnv {
    pub fn new(projects_dir: PathBuf, workdir_dir: PathBuf) -> CliEnv {
        CliEnv {
            projects_dir: projects_dir.clone(),
            workdir_dir,
            config_dirs: ConfigDirs::new(projects_dir),
            theme: theme::ColorfulTheme::default(),
        }
    }

    pub fn get_input(&self, prompt: &str, default: Option<String>) -> Result<String> {
        // console crate uses stderr
        let term = console::Term::stderr();
        let mut input_build = Input::<String>::with_theme(&self.theme);
        input_build.with_prompt(&prompt);
        default.iter().for_each(|default| {
            input_build.default(default.to_owned());
        });
        let input = input_build.interact_on(&term)?;
        let input = input.trim();
        let resolved = if input != "" {
            String::from(input)
        } else {
            match default {
                Some(default) => default.into(),
                _ => String::from(input),
            }
        };
        // Replace previous line with resolved value
        term.clear_last_lines(1)?;
        term.write_line(&format!("{}: {}", prompt, style(&resolved).magenta()))?;
        Ok(resolved)
    }

    pub fn get_pass(&self, prompt: &str) -> Result<String> {
        let mut input_build = dialoguer::PasswordInput::with_theme(&self.theme);
        input_build.with_prompt(&prompt);
        input_build.interact().map_err(|e| er::Io::e(e).into())
    }

    // todo: Add new. Select none. Handle 0 items
    pub fn select<T: ToString + std::cmp::PartialEq + Clone>(
        &self,
        prompt: &str,
        items: &Vec<T>,
        default: Option<usize>,
    ) -> Result<usize> {
        let prompt = match default {
            Some(default) => match items.get(default) {
                Some(default_val) => {
                    format!("{} ({})", prompt, style(default_val.to_string()).dim())
                }
                None => prompt.to_string(),
            },
            None => String::from(prompt),
        };
        let mut select_build = Select::with_theme(&self.theme);
        select_build.with_prompt(&prompt).items(items);
        select_build.default(default.unwrap_or(0));
        let index = select_build.interact()?;
        Ok(index)
    }

    pub fn select_or_add_or_none<T>(
        &self,
        prompt: &str,
        items: &Vec<T>,
        default: Option<usize>,
    ) -> Result<SelectOrAddOrNone>
    where
        T: ToString + std::cmp::PartialEq + Clone,
    {
        // Inject none at the beginning
        let mut items2 = vec!["NONE".to_string()];
        items2.append(&mut items.into_iter().map(|i| i.to_string()).collect());
        // Account for added NONE
        let default = default.map(|default| default + 1);
        match self.select_or_add(prompt, &items2, default)? {
            SelectOrAdd::Selected(selected) => {
                if selected == 0 {
                    Ok(SelectOrAddOrNone::None)
                } else {
                    Ok(SelectOrAddOrNone::Selected(selected - 1))
                }
            }
            SelectOrAdd::AddNew => Ok(SelectOrAddOrNone::AddNew),
        }
    }

    pub fn select_or_add<T>(
        &self,
        prompt: &str,
        items: &Vec<T>,
        default: Option<usize>,
    ) -> Result<SelectOrAdd>
    where
        T: ToString + std::cmp::PartialEq + Clone,
    {
        if items.len() > 0 {
            // Append "add new" option to items
            let num_regular = items.len();
            let mut items2 = items.iter().map(|i| i.to_string()).collect::<Vec<String>>();
            items2.push("ADD NEW".to_string());
            let select_res = self.select(prompt, &items2, default)?;
            if select_res < num_regular {
                Ok(SelectOrAdd::Selected(select_res))
            } else {
                Ok(SelectOrAdd::AddNew)
            }
        } else {
            Ok(SelectOrAdd::AddNew)
        }
    }

    pub fn error_msg(&self, msg: &str) {
        println!("{}", style(msg).red());
    }

    pub fn get_project_path(&self, extra: &str) -> PathBuf {
        let mut cloned = self.projects_dir.clone();
        cloned.push(extra);
        cloned
    }

    pub fn display_result<T>(&self, result: Result<T>) {
        match result {
            Ok(_) => (),
            Err(err) => self.error_msg(&format!("{:?}", err)),
        }
    }
}

pub fn entries_in_dir(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut entries = Vec::new();
    if !dir.is_dir() {
        return er::err("Given path is not a directory");
    }
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() || path.is_file() {
            entries.push(path);
        }
    }
    Ok(entries)
}

pub fn files_in_dir(dir: &Path) -> Result<Vec<String>> {
    if dir.is_dir() {
        let mut entries = Vec::new();
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            match entry.file_name().into_string() {
                Ok(string) => entries.push(string),
                Err(_) => (),
            }
        }
        Ok(entries)
    } else {
        Ok(Vec::new())
    }
}

pub fn name_after_prefix(full_path: &Path, prefix: &Path) -> Result<String> {
    match full_path.strip_prefix(&prefix) {
        Ok(stripped) => {
            // Todo: Could verify one component
            match stripped.file_name() {
                Some(name) => Ok(name.to_string_lossy().to_string()),
                None => er::err(format!("Could not get name from: {:?}", stripped)),
            }
        }
        Err(e) => er::err(format!("Error strip prefix: {:?}", e)),
    }
}

pub fn file_name_string(path: &Path) -> Result<String> {
    match path.file_name() {
        Some(file_name) => Ok(file_name.to_string_lossy().to_string()),
        None => er::err(format!("Could not get file_name from {:?}", path)),
    }
}

pub fn ensure_parent_dir(path: &Path) -> Result<()> {
    match path.parent() {
        Some(parent) => {
            if parent.is_dir() {
                Ok(())
            } else {
                fs::create_dir_all(parent).map_err(|e| er::Io::e(e).into())
            }
        }
        None => er::err(format!("Could not resolve parent of {:?}", path)),
    }
}

/// Ensures parent dir and writes content
pub fn write_file(path: &Path, content: &str) -> Result<()> {
    ensure_parent_dir(path)?;
    fs::write(path, content).map_err(|e| er::Io::e(e).into())
}

/// There should only be one current process
/// so we can register a global ctrlc handler
// SharedChild, then end_on_ctrlc
pub struct CurrentProcess(Arc<RwLock<Option<(SharedChild, bool)>>>);

// Todo: Go over error handling
impl CurrentProcess {
    pub fn new() -> CurrentProcess {
        let current_process: Arc<RwLock<Option<(SharedChild, bool)>>> = Arc::new(RwLock::new(None));
        let current_process_ctrlc = current_process.clone();
        // todo: Possibly ctrl-c is forwarded to the command anyway
        // through stdin?
        match ctrlc::set_handler(move || {
            let current_process = match current_process_ctrlc.read() {
                Ok(lock) => lock,
                Err(e) => {
                    println!("Error aquiring lock: {:?}", e);
                    return ();
                }
            };
            match &*current_process {
                Some((process, end_on_ctrlc)) => {
                    if *end_on_ctrlc {
                        match process.kill() {
                            Ok(_) => {
                                println!("Ended process by ctrl-c");
                                ()
                            }
                            Err(e) => println!("Error ending dev process: {:?}", e),
                        }
                    }
                }
                None => {
                    println!("No current process in ctrlc");
                    std::process::exit(0);
                }
            }
            // CurrentProcess will be set to none in
            // dedicated process wait thread
        }) {
            Ok(_) => (),
            Err(e) => println!("Ctrlc error: {:?}", e),
        }
        CurrentProcess(current_process)
    }

    pub fn spawn_and_wait(
        self,
        mut cmd: std::process::Command,
        end_on_ctrlc: bool,
    ) -> Result<Self> {
        // Spawn and put into shared value with ctrlc
        {
            let shared_child = shared_child::SharedChild::spawn(&mut cmd)?;
            // By default, inherit stdin, out, err
            match self.0.write() {
                Ok(mut write_lock) => *write_lock = Some((shared_child, end_on_ctrlc)),
                Err(e) => {
                    println!("Couldn't aqcuire write lock: {:?}", e);
                }
            }
        }
        let wait_clone = self.0.clone();
        let thread = std::thread::spawn(move || {
            {
                let reader = match wait_clone.read() {
                    Ok(reader) => reader,
                    Err(e) => {
                        print!("Could not get read lock: {:?}", e);
                        return ();
                    }
                };
                let wait_process = match &*reader {
                    Some((wait_process, _)) => wait_process,
                    None => return (),
                };
                match wait_process.wait() {
                    Ok(exit_status) => {
                        println!("Exited dev process with status: {}", exit_status);
                    }
                    Err(e) => {
                        println!("Error waiting for process: {:?}", e);
                        return ();
                    }
                }
            }
            // Remove from current process
            match wait_clone.write() {
                Ok(mut lock) => {
                    *lock = None;
                }
                Err(e) => println!("Failed getting write on current process: {:?}", e),
            }
        });
        let _thread_res = match thread.join() {
            Ok(_res) => {
                println!("Joined thread");
            }
            Err(e) => println!("Error ending process: {:?}", e),
        };
        Ok(self)
    }
}

pub fn wait_for<A: ToSocketAddrs>(addr: A) -> bool {
    let mut attempts = 0;
    let max_attempts = 15;
    loop {
        match TcpStream::connect(&addr) {
            Ok(_) => {
                // todo: Better solution..
                if attempts > 0 {
                    // If server is getting up, allow some time
                    std::thread::sleep(std::time::Duration::from_millis(2000));
                }
                return true;
            }
            Err(e) => {
                println!("Could not connect, retrying...");
                attempts = attempts + 1;
                if attempts >= max_attempts {
                    format!("Aborting after max attempts: {}, {:?}", max_attempts, e);
                    return false;
                }
                std::thread::sleep(std::time::Duration::from_millis(1500));
            }
        }
    }
}

pub fn now_formatted() -> String {
    let system_time = std::time::SystemTime::now();
    let datetime: chrono::DateTime<chrono::Utc> = system_time.into();
    format!("{}", datetime.format("%Y-%m-%d %T"))
}

/// Convenience to build string vecs while
/// accepting Into<String>
pub struct StringVec {
    vec: Vec<String>,
}
impl StringVec {
    pub fn new() -> Self {
        StringVec { vec: Vec::new() }
    }

    pub fn push(&mut self, x: impl Into<String>) -> &mut Self {
        self.vec.push(x.into());
        self
    }

    pub fn join(&self, separator: &str) -> String {
        self.vec.join(separator)
    }
}
