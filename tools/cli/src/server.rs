use crate::er::{self, FailExt, Result};
use crate::utils::{self, CliEnv};
use failure::format_err;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};

#[derive(Serialize, Deserialize, Clone)]
pub struct ServerConfig {
    pub name: String,
    pub url: String,
    pub pem: String,
    pub instance_id: Option<String>,
    pub elastic_ip: Option<ElasticIp>,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct ElasticIp {
    pub allocation_id: String,
    pub public_ip: String,
}
impl ServerConfig {
    pub fn pem_path(&self, env: &CliEnv) -> PathBuf {
        env.config_dirs
            .servers
            .filepath(&format!(".pem/{}", self.pem))
    }

    pub fn home_dir(&self) -> PathBuf {
        PathBuf::from("/home/ec2-user")
    }
    pub fn home_dir_and(&self, extra: &str) -> PathBuf {
        let mut home_dir = self.home_dir();
        home_dir.push(extra);
        home_dir
    }
}

pub fn has_config(env: &CliEnv, server: &str) -> bool {
    env.config_dirs.servers.has_file(server)
}

pub fn get_config(env: &CliEnv, server: &str) -> Result<ServerConfig> {
    let json_file = std::fs::File::open(env.config_dirs.servers.filepath(server))?;
    let buf_reader = io::BufReader::new(json_file);
    let config = serde_json::from_reader::<_, ServerConfig>(buf_reader)?;
    Ok(config)
}

pub fn get_servers(env: &CliEnv) -> Result<Vec<String>> {
    utils::files_in_dir(&env.config_dirs.servers.0).map(|files| {
        // todo: Different location for .pem?
        files.into_iter().filter(|f| f != ".pem").collect()
    })
}

pub fn select_server(env: &CliEnv) -> Result<ServerConfig> {
    let servers = get_servers(env)?;
    env.select("Select server", &servers, None)
        .and_then(|i| match servers.get(i) {
            Some(server_name) => get_config(env, server_name),
            None => er::err("Error selecting server"),
        })
}

/// Manually input or edit a server
/// When running `provision`, a config will also be created
pub fn add_server(env: &CliEnv) -> Result<ServerConfig> {
    // List current servers
    let current_files = utils::files_in_dir(&env.config_dirs.servers.0)?;
    if current_files.len() > 0 {
        println!("Current servers:");
        for file in current_files {
            println!("{}", file);
        }
    } else {
        println!("No existing servers");
    }

    let name = env.get_input("Internal server name", None)?;
    let current_config = if has_config(env, &name) {
        println!("Server config exists for: {}", &name);
        println!("Modifying entry.");
        Some(get_config(env, &name)?)
    } else {
        None
    };
    let url = env.get_input(
        "Ssh url",
        current_config.as_ref().map(|c| c.url.to_string()),
    )?;
    let pem = env.get_input("Pem filename", current_config.map(|c| c.pem))?;

    // If this is aws, we could allow to select instance by
    // describe_instance_status or similar
    let config = ServerConfig {
        name,
        url,
        pem,
        instance_id: None,
        elastic_ip: None,
    };
    write_config(env, &config)?;
    Ok(config)
}

pub fn write_config(env: &CliEnv, config: &ServerConfig) -> Result<()> {
    let content_str = match serde_json::to_string_pretty(&config) {
        Ok(content_str) => content_str,
        Err(e) => return Err(er::SerdeJson::e(e).into()),
    };

    env.config_dirs.servers.write(&config.name, &content_str)
}

pub struct SshConn {
    pub session: ssh2::Session,
    pub tunnel: Option<SshTunnel>,
}
impl Drop for SshConn {
    fn drop(&mut self) {
        if let Some(tunnel) = self.tunnel.take() {
            match tunnel.close() {
                Ok(_) => println!("Closed tunnel"),
                Err(e) => eprintln!("Failed closing tunnel: {:?}", e),
            }
        }
    }
}
impl SshConn {
    /// Initial connection to a given address
    /// Before authentication
    pub fn init_connection<A: std::net::ToSocketAddrs + std::fmt::Display>(
        addr: A,
    ) -> Result<ssh2::Session> {
        match SshConn::init_connection_inner(addr) {
            Ok(session) => Ok(session),
            Err(e) => {
                println!("Could not connect: {:?}", e);
                Err(e)
            }
        }
    }

    fn init_connection_inner<A: std::net::ToSocketAddrs + std::fmt::Display>(
        addr: A,
    ) -> Result<ssh2::Session> {
        println!("Connecting to {}", addr);
        let tcp = TcpStream::connect(addr)?;
        let mut session = match ssh2::Session::new() {
            Ok(session) => session,
            Err(e) => return er::Ssh::msg("Could not create session struct", e).err(),
        };
        println!("Connected");
        session.set_tcp_stream(tcp);
        match session.handshake() {
            Ok(_) => (),
            Err(e) => return er::Ssh::msg("Failed handshake", e).err(),
        }
        Ok(session)
    }
    /// Establish ssh connection to given server,
    /// currently based on config
    /// We want this to have security that makes sense
    pub fn connect<A, P>(addr: A, pem_file: P, server_name: &str) -> Result<Self>
    where
        A: std::net::ToSocketAddrs + std::fmt::Display,
        P: AsRef<Path>,
    {
        match SshConn::connect_inner(addr, pem_file, server_name) {
            Ok(session) => Ok(session),
            Err(e) => {
                println!("Could not connect to: {:?}", e);
                Err(e)
            }
        }
    }

    fn connect_inner<A, P>(addr: A, pem_file: P, server_name: &str) -> Result<Self>
    where
        A: std::net::ToSocketAddrs + std::fmt::Display,
        P: AsRef<Path>,
    {
        // http://api.libssh.org/master/libssh_tutorial.html
        let session = SshConn::init_connection(addr)?;
        // Todo: Verify public key
        // Don't know how to get this in advance
        /*let known_hosts = match session.known_hosts() {
            Ok(known_hosts) => known_hosts,
            Err(e) => return er::err(format!("Could not get known hosts: {:?}", e))
        };*/
        //known_hosts.
        /*
        println!(
            "Sha1 {:?}",
            session
                .host_key_hash(ssh2::HashType::Sha1)
                .map(String::from_utf8_lossy)
        );
        println!(
            "Md5 {:?}",
            session
                .host_key_hash(ssh2::HashType::Md5)
                .map(String::from_utf8_lossy)
        );
        println!(
            "{:?}",
            session.host_key().map(|(s, t)| (
                match t {
                    ssh2::HostKeyType::Dss => "dss",
                    ssh2::HostKeyType::Rsa => "rsa",
                    ssh2::HostKeyType::Unknown => "unknown",
                },
                String::from_utf8_lossy(s)
            ))
        );*/

        // Attempt authenticate
        match session.userauth_pubkey_file("ec2-user", None, pem_file.as_ref(), None) {
            Ok(_) => (),
            Err(e) => return er::Ssh::msg("Authentication failed", e).err(),
        }
        if !session.authenticated() {
            return Err(format_err!("Authenticated failed"));
        } else {
            println!("Authenticated to server: {}", server_name);
        }
        Ok(SshConn {
            session,
            tunnel: None,
        })
    }

    pub fn connect_server(env: &CliEnv, server: &ServerConfig) -> Result<Self> {
        Self::connect(&server.url, server.pem_path(env), &server.name)
    }

    /// Connects to ssh server either locally or on the server via tunnel
    pub fn connect_container_ssh(
        env: &CliEnv,
        port: u16,
        user: &str,
        pass: &str,
        tunnel: Option<&ServerConfig>,
    ) -> Result<Self> {
        let (tunnel, port) = match tunnel {
            Some(server_config) => {
                // Setup tunnel into container on server
                println!("Making tunnel to server on port: {}", port);
                let (tunnel, local_port) = SshTunnel::new(env, server_config, port)?;
                (Some(tunnel), local_port)
            }
            None => (None, port),
        };
        let url = format!("127.0.0.1:{}", port);
        println!("Connecting to local {}", url);
        let session = SshConn::init_connection(&url)?;
        match session.userauth_password(user, pass) {
            Ok(_) => (),
            Err(e) => return er::Ssh::msg("Authentication failed", e).err(),
        }
        if !session.authenticated() {
            return Err(format_err!("Authenticated failed"));
        } else {
            println!("Authenticated!");
        }
        Ok(SshConn { session, tunnel })
    }

    pub fn channel(&self) -> Result<ssh2::Channel> {
        // These feels a little brittle, but needed here
        // Don't know if worth to keep own variable for it?
        self.session.set_blocking(true);
        match self.session.channel_session() {
            Ok(channel) => Ok(channel),
            Err(e) => er::Ssh::msg("Error opening channel", e).err(),
        }
    }

    fn update_pty_size(channel: &mut ssh2::Channel) {
        use terminal_size::{terminal_size, Height, Width};
        let size = terminal_size();
        if let Some((Width(width), Height(height))) = size {
            match channel.request_pty_size(width.into(), height.into(), None, None) {
                Ok(()) => (),
                Err(e) => eprintln!("Failed setting pty size: {:?}", e),
            }
        }
    }

    pub fn shell(&self) -> Result<()> {
        let mut channel = self.channel()?;
        // xterm should have more features, support colors etc
        // other options, vanilla, vt220, vt100 etc
        // Don't know if xterm could be bad for security
        // https://unix.stackexchange.com/questions/43945/whats-the-difference-between-various-term-variables
        // Mode at least cooked and raw. Cooked will process the input, for example
        // deleting a character when backspace is pressed
        // https://en.wikipedia.org/wiki/Terminal_mode
        // Had problems with both mode: Some("cooked") and Some("raw") on aws
        match channel.request_pty("xterm", None, None) {
            Ok(_) => (),
            Err(e) => {
                eprintln!("Could not request pty");
                return er::Ssh::msg("Could not request pty", e).err();
            }
        }
        Self::update_pty_size(&mut channel);
        match channel.shell() {
            Ok(_) => (),
            Err(e) => {
                eprintln!("Could not request shell");
                return er::Ssh::msg("Could not request shell", e).err();
            }
        }
        // Switch to raw mode for this stdin
        use termion::raw::IntoRawMode;
        // "raw_mode" will act as stdout, as well as keeping
        // state of the terminal and restore when dropped
        let mut raw_mode = match std::io::stdout().into_raw_mode() {
            Ok(restorer) => restorer,
            Err(e) => {
                eprintln!("Could not enter raw mode");
                return er::Io::msg("Could not enter raw mode", e).err();
            }
        };
        let mut inp = std::io::stdin();
        // Keep a thread to receive stdin
        let (tx, rx) = std::sync::mpsc::channel();
        let _thread = std::thread::spawn(move || {
            let mut inp_buf: [u8; 256] = [0; 256];
            use std::io::Read;
            loop {
                match inp.read(&mut inp_buf) {
                    Ok(num) => {
                        if num > 0 {
                            match tx.send(Vec::from(&inp_buf[0..num])) {
                                Ok(_) => (),
                                Err(e) => eprintln!("Failed sending input: {:?}", e),
                            }
                        } else {
                            println!("Received 0, breaking");
                            break;
                        }
                    }
                    Err(e) => {
                        eprintln!("Input read error, breaking, {:?}", e);
                        break;
                    }
                }
            }
        });
        let mut err = std::io::stderr();
        self.pipe_loop(&mut channel, &mut raw_mode, Some(rx), &mut err)?;
        // Todo: I haven't found solution to handling stdin well.
        // The stdin thread is blocking on read and no way to exit
        // Possibly a better solution could be some global handler tied
        // to env
        /*
        match thread.join() {
            Ok(_) => (),
            Err(e) => {
                eprintln!("Failed to join thread: {:?}", e);
            }
        }*/
        Ok(())
    }

    /// Loops while piping channels stdout and stderr to
    /// respective fds on host system
    /// Also pipes input. It might make sense to do
    /// this as an option
    fn pipe_loop<W, E>(
        &self,
        channel: &mut ssh2::Channel,
        mut out: &mut W,
        inp: Option<std::sync::mpsc::Receiver<Vec<u8>>>,
        mut err: &mut E,
    ) -> Result<()>
    where
        W: std::io::Write,
        E: std::io::Write,
    {
        let mut acc_buf = Vec::with_capacity(2048);
        use std::io::Read;
        let mut read_buf: [u8; 2048] = [0; 2048];
        // If there is still something in stderr, channel should not eof
        use std::error::Error;
        while !channel.eof() {
            // Read stdout while there is bytes
            // Not sure how to do this well. Consideration is
            // to support "streaming"
            // Also, probably don't want to write in the middle
            // of certain bytes? Like utf8 chars etc?
            // This will block unless self.session.set_blocking is set to false
            self.session.set_blocking(false);
            loop {
                match channel.read(&mut read_buf) {
                    Ok(num) => {
                        if num > 0 {
                            acc_buf.extend_from_slice(&read_buf[0..num]);
                        } else {
                            break;
                        }
                    }
                    Err(e) => {
                        // Accept WouldBlock and Interrupted
                        match e.kind() {
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted => {
                                // todo: Atleast wouldblock kicks in some times, not sure
                                // if this should include "interrupted"
                                break;
                            }
                            std::io::ErrorKind::Other => {
                                //use std::io::Error;
                                // todo: Better detection
                                if e.description() != "would block" {
                                    return er::Io::msg("Read failed", e).err();
                                }
                                break;
                            }
                            _ => {
                                return er::Io::msg("Read failed", e).err();
                            }
                        }
                    }
                }
            }
            if acc_buf.len() > 0 {
                match write!(&mut out, "{}", String::from_utf8_lossy(&acc_buf)) {
                    Ok(()) => (),
                    Err(e) => eprintln!("Failed to write output: {:?}", e),
                }
                match out.flush() {
                    Ok(_) => (),
                    Err(_) => (),
                }
                acc_buf.clear();
            }
            // Now check stderr
            let mut err_stream = channel.stderr();
            loop {
                match err_stream.read(&mut read_buf) {
                    Ok(num) => {
                        if num > 0 {
                            acc_buf.extend_from_slice(&read_buf[0..num]);
                        } else {
                            break;
                        }
                    }
                    Err(e) => {
                        // Accept "would block"
                        if e.description() != "would block" {
                            println!("Read error: {}, {:?}", e.description(), e.source());
                        }
                        break;
                    }
                }
            }
            drop(err_stream);
            if acc_buf.len() > 0 {
                match write!(&mut err, "{}", String::from_utf8_lossy(&acc_buf)) {
                    Ok(()) => (),
                    Err(e) => eprintln!("Failed to write output: {:?}", e),
                }
                match out.flush() {
                    Ok(_) => (),
                    Err(_) => (),
                }
                acc_buf.clear();
            }
            // Sleeping I think to not use too much cpu and
            // allow other threads some time
            std::thread::sleep(std::time::Duration::from_millis(20));
            if let Some(rx) = &inp {
                // Check stdin and send to channel
                loop {
                    match rx.try_recv() {
                        Ok(inp_buf) => {
                            use std::io::Write;
                            // Block while writing to ensure all is written
                            self.session.set_blocking(true);
                            match channel.write_all(&inp_buf) {
                                Ok(_) => (),
                                Err(e) => eprintln!("Error writing input to channel: {:?}", e),
                            }
                            self.session.set_blocking(false);
                        }
                        Err(_) => break,
                    }
                }
            }
        }
        // There may be something in out_buf if we got to .eof()
        // before reading Ok(0)
        /*
        if out_buf.len() > 0 {
            println!("{}", String::from_utf8_lossy(&out_buf));
            match writeln!(&mut out, "{}", String::from_utf8_lossy(&out_buf)) {
                Ok(()) => (),
                Err(e) => eprintln!("Failed to write output: {:?}", e),
            }
            out_buf.clear();
        }*/
        self.session.set_blocking(true);
        Ok(())
    }

    // Todo: Communicate error code better, possibly custom Result type
    /// Runs command, captures and returns output
    pub fn exec_capture<S: Into<String>, WD: Into<String>>(
        &self,
        cmd: S,
        working_dir: Option<WD>,
    ) -> Result<String> {
        // There could be better solutions for this,
        // somehow setting it on session
        // I think the problem is it would be harder to get
        // error code then.
        let cmd = match working_dir {
            Some(working_dir) => format!("cd {}; {}", working_dir.into(), cmd.into()),
            None => cmd.into(),
        };
        let mut channel = self.channel()?;
        match channel.exec(&cmd) {
            Ok(_) => (),
            Err(e) => return er::Ssh::msg(format!("Error executing command: {}", cmd), e).err(),
        }
        let mut captured = String::with_capacity(128);
        use std::io::Read;
        channel.read_to_string(&mut captured)?;
        let mut stderr_capture = String::new();
        channel.stderr().read_to_string(&mut stderr_capture)?;
        if stderr_capture.len() > 0 {
            eprintln!("Stderr: {}", stderr_capture);
        }
        let exit_code = Self::finish_exec(channel)?;
        if exit_code == 0 {
            Ok(captured)
        } else {
            Err(format_err!(
                "Command with non-zero exit code: {}, {}",
                exit_code,
                cmd
            ))
        }
    }

    pub fn exec<S: Into<String>>(&self, cmd: S) -> Result<i32> {
        let cmd = cmd.into();
        println!("{}", console::style(&cmd).green());
        let mut channel = self.channel()?;
        match channel.exec(&cmd) {
            Ok(_) => (),
            Err(e) => return er::Ssh::msg(format!("Error executing command: {}", cmd), e).err(),
        }
        let mut out = std::io::stdout();
        let mut err = std::io::stderr();
        self.pipe_loop(&mut channel, &mut out, None, &mut err)?;
        Self::finish_exec(channel)
    }

    /// Internal helper to close exec channel and get status code
    fn finish_exec(mut channel: ssh2::Channel) -> Result<i32> {
        // Send signal to close
        match channel.close() {
            Ok(_) => (),
            Err(e) => {
                eprintln!("Error closing channel: {:?}", e);
                return Err(format_err!("Error closing channel"));
            }
        }
        // Wait for remote channel to close
        match channel.wait_close() {
            Ok(_) => (),
            Err(e) => {
                eprintln!("Error waiting for close: {:?}", e);
            }
        }
        match channel.exit_status() {
            Ok(status) => {
                if status != 0 {
                    eprintln!("Non-zero exit status: {}", status);
                }
                Ok(status)
            }
            Err(e) => er::Ssh::msg("Error getting exit status", e).err(),
        }
    }

    pub fn sftp(&self) -> Result<ssh2::Sftp> {
        let sftp = self
            .session
            .sftp()
            .map_err(|e| er::Ssh::msg("Failed to start sftp subsystem", e))?;
        Ok(sftp)
    }
}

trait SftpExt {
    fn exist_stat(&self, p: &Path) -> Result<Option<ssh2::FileStat>>;
}
impl SftpExt for ssh2::Sftp {
    /// Extend sftp stat to return None when file does not
    /// exist, and Some<FileStat> when it does
    fn exist_stat(&self, p: &Path) -> Result<Option<ssh2::FileStat>> {
        match self.stat(&p) {
            Ok(stat) => Ok(Some(stat)),
            Err(e) => {
                if e.code() == 2 {
                    Ok(None)
                } else {
                    return Err(failure::Error::from(er::Ssh::e(e)));
                }
            }
        }
    }
}

pub fn iter_dir(
    base: PathBuf,
    remote: Option<&ssh2::Sftp>,
    ignore: SyncIgnore,
) -> Result<DirIterator> {
    let mut iter = DirIterator {
        stack: Vec::with_capacity(32),
        remote,
        ignore,
    };
    iter.push_base(base)?;
    Ok(iter)
}
// todo: a better api would be a builder struct,
// then turned into an iterator with IntoIterator trait
/// Abstract dir walker, handling local and remote
pub struct DirIterator<'a> {
    // As directories are encountered, their entries are pushed onto
    // this stack. As they are yielded from the iterator, entries are
    // popped from the end.
    stack: Vec<DirIterEntry>,
    remote: Option<&'a ssh2::Sftp>,
    ignore: SyncIgnore,
}
#[derive(Debug)]
pub struct DirIterEntry {
    pub path: PathBuf,
    pub stats: SyncEntryStats,
}
impl<'a> DirIterator<'a> {
    /// Adds base dir to stack
    fn push_base(&mut self, path: PathBuf) -> Result<()> {
        if self.ignore.ignore_abs_path(&path, true) {
            return Ok(());
        }
        match self.remote {
            Some(sftp) => match sftp.exist_stat(&path)? {
                Some(sftp_stats) => {
                    self.stack.push(DirIterEntry {
                        path,
                        stats: sftp_stats.into(),
                    });
                    Ok(())
                }
                None => Err(format_err!(
                    "Base for iterator does not exists on remote: {:?}",
                    path
                )),
            },
            None => {
                use std::fs;
                let file = fs::File::open(&path)?;
                self.stack.push(DirIterEntry {
                    path,
                    stats: file.metadata()?.into(),
                });
                Ok(())
            }
        }
    }
    /// Pushes dir entries reversed onto stack
    fn push_dir_entries(&mut self, path: &Path) -> Result<()> {
        // I think this is superflous, but to be sure
        if self.ignore.ignore_abs_path(path, true) {
            return Ok(());
        }
        match self.remote {
            Some(sftp) => {
                for (child_path, sftp_stats) in sftp.readdir(path)?.into_iter().rev() {
                    let stats: SyncEntryStats = sftp_stats.into();
                    if self.ignore.ignore_abs_path(&child_path, stats.is_dir) {
                        continue;
                    }
                    self.stack.push(DirIterEntry {
                        path: child_path,
                        stats,
                    });
                }
                Ok(())
            }
            None => {
                use std::fs;
                for entry in fs::read_dir(path)?.collect::<Vec<_>>().into_iter().rev() {
                    let entry = entry?;
                    let path = entry.path();
                    let meta = entry.metadata().map_err(er::Io::e)?;
                    let stats: SyncEntryStats = meta.into();
                    if self.ignore.ignore_abs_path(&path, stats.is_dir) {
                        continue;
                    }
                    self.stack.push(DirIterEntry { path, stats });
                }
                Ok(())
            }
        }
    }
}
impl<'a> Iterator for DirIterator<'a> {
    type Item = Result<DirIterEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(entry) = self.stack.pop() {
            if entry.stats.is_dir {
                match self.push_dir_entries(&entry.path) {
                    Ok(()) => (),
                    Err(e) => {
                        // Returning the error somehow. It would probably make more sense
                        // to return on the entry it actually came from
                        return Some(Err(e));
                    }
                }
            }
            Some(Ok(entry))
        } else {
            None
        }
    }
}

// Todo: Consider taking sftp as member (or go over
// argument positions for consistency)
// Todo:! Especially for sftp -> sftp sync_plain transfers, there can be gains
// by parallellizing resolving and transfer
/// Helper to sync as an archive, then decompress on server
pub struct SyncSet<'a> {
    pub source_base: SyncBase<'a>,
    pub dest_base: SyncBase<'a>,
    entries: Vec<SyncSetEntry>,
    // Keeps track of modified when last sent
    pub sent_cache: SyncSentCache,
    pub ignore: SyncIgnore,
}
#[derive(Clone, Default)]
pub struct SyncIgnore {
    // Absolute paths
    pub paths: HashSet<PathBuf>,
    pub dir_names: HashSet<String>,
}
impl SyncIgnore {
    pub fn ignore_abs_path(&self, path: impl AsRef<Path>, is_dir: bool) -> bool {
        let path = path.as_ref();
        if self.paths.contains(path) {
            return true;
        }
        if is_dir && self.dir_names.len() > 0 {
            if let Some(dir_name) = path.file_name() {
                if self
                    .dir_names
                    .contains(&dir_name.to_string_lossy().to_string())
                {
                    return true;
                }
            }
        }
        return false;
    }
}
// Todo: It's a pretty bad implementation to ease pain
pub enum SyncSentCache {
    None,
    Some {
        file_path: PathBuf,
        sent_cache: HashMap<String, u64>,
    },
}
impl SyncSentCache {
    pub fn none() -> Self {
        SyncSentCache::None
    }
    pub fn load<N: Into<String>>(env: &CliEnv, cache_key: N) -> Result<SyncSentCache> {
        let cache_key = cache_key.into();
        let sent_cache_dir = env.config_dirs.config_root.join("sent_cache");
        if !sent_cache_dir.is_dir() {
            std::fs::create_dir_all(&sent_cache_dir)?;
        }
        let sent_cache_file = sent_cache_dir.join(&cache_key);
        if sent_cache_file.is_file() {
            let json_file = std::fs::File::open(&sent_cache_file)?;
            let buf_reader = io::BufReader::new(json_file);
            let sent_cache = serde_json::from_reader::<_, HashMap<String, u64>>(buf_reader)?;
            return Ok(SyncSentCache::Some {
                file_path: sent_cache_file,
                sent_cache,
            });
        }
        Ok(SyncSentCache::Some {
            file_path: sent_cache_file,
            sent_cache: HashMap::new(),
        })
    }

    pub fn write(&self) -> Result<()> {
        match self {
            SyncSentCache::None => (),
            SyncSentCache::Some {
                file_path,
                sent_cache,
            } => {
                let content_str = serde_json::to_string_pretty(sent_cache)?;
                utils::write_file(file_path, &content_str)?;
            }
        }
        Ok(())
    }

    #[inline]
    pub fn set(&mut self, dest_path: &Path, modified: &Option<u64>, write: bool) -> Result<()> {
        if let Some(modified) = modified {
            match self {
                Self::None => (),
                Self::Some { sent_cache, .. } => {
                    *sent_cache
                        .entry(dest_path.to_string_lossy().to_string())
                        .or_insert(*modified) = *modified;
                    if write {
                        self.write()?;
                    }
                }
            }
        }
        Ok(())
    }

    #[inline]
    pub fn get(&self, dest_path: &Path) -> Option<u64> {
        match self {
            Self::None => None,
            Self::Some { sent_cache, .. } => {
                // Could we use string ref somehow?
                match sent_cache.get(&dest_path.to_string_lossy().to_string()) {
                    Some(sent_cache_mtime) => Some(sent_cache_mtime.to_owned()),
                    None => None,
                }
            }
        }
    }
}
/// Abstraction for base path whether it's on server or local
pub struct SyncBase<'a> {
    path: PathBuf,
    remote: Option<&'a ssh2::Sftp>,
}
#[derive(Debug)]
pub struct SyncEntryStats {
    pub is_file: bool,
    pub is_dir: bool,
    pub mtime: Option<u64>,
    pub bytes: Option<u64>,
}
impl SyncEntryStats {
    /// Attepts to get stats from a local file. Returns None
    /// if file does not exist (or no permission? todo)
    pub fn from_local(abs_path: &Path) -> Result<Option<Self>> {
        // todo: Possibly this would just return false in case
        // of permission error, in which case we'd probably want an error
        if abs_path.exists() {
            let meta = abs_path.metadata().map_err(er::Io::e)?;
            Ok(Some(meta.into()))
        } else {
            Ok(None)
        }
    }

    pub fn from_remote(abs_path: &Path, sftp: &ssh2::Sftp) -> Result<Option<Self>> {
        match sftp.exist_stat(&abs_path)? {
            Some(stats) => Ok(Some(stats.into())),
            None => Ok(None),
        }
    }
}
impl From<std::fs::Metadata> for SyncEntryStats {
    fn from(meta: std::fs::Metadata) -> SyncEntryStats {
        let mtime = SyncSet::modified_timestamp(&meta);
        let is_file = meta.is_file();
        let bytes = if is_file { Some(meta.len()) } else { None };
        SyncEntryStats {
            is_file,
            is_dir: meta.is_dir(),
            mtime,
            bytes,
        }
    }
}
impl From<ssh2::FileStat> for SyncEntryStats {
    fn from(stats: ssh2::FileStat) -> SyncEntryStats {
        SyncEntryStats {
            is_file: stats.is_file(),
            is_dir: stats.is_dir(),
            mtime: stats.mtime,
            bytes: stats.size,
        }
    }
}
pub enum SyncFileHandle<'a> {
    Local(std::fs::File),
    Remote(ssh2::File<'a>),
}
impl<'a> SyncBase<'a> {
    pub fn local<P: AsRef<Path>>(base: P) -> Self {
        SyncBase {
            path: base.as_ref().to_path_buf(),
            remote: None,
        }
    }

    pub fn remote<P: AsRef<Path>>(base: P, sftp: &'a ssh2::Sftp) -> Self {
        SyncBase {
            path: base.as_ref().to_path_buf(),
            remote: Some(sftp),
        }
    }

    /// Gets stats for file or dir, local or remote
    pub fn stats(&self, abs_path: &Path) -> Result<Option<SyncEntryStats>> {
        match self.remote {
            None => SyncEntryStats::from_local(abs_path),
            Some(sftp) => SyncEntryStats::from_remote(abs_path, sftp),
        }
    }

    /// Consumes this SyncBase, and returns one pointing to
    /// the parent as well as the full PathBuf
    pub fn to_parent(self) -> Result<(Self, PathBuf)> {
        match self.path.parent() {
            Some(parent) => Ok((
                SyncBase {
                    path: parent.to_path_buf(),
                    remote: self.remote,
                },
                self.path,
            )),
            None => Err(format_err!("Could not resolve parent of {:?}", self.path)),
        }
    }

    pub fn mkdir(&self, path: &Path) -> Result<()> {
        match self.remote {
            Some(sftp) => {
                sftp.mkdir(path, 0o0755)?;
                Ok(())
            }
            None => {
                std::fs::create_dir(path)?;
                Ok(())
            }
        }
    }

    pub fn ensure_dir(&self, path: &Path) -> Result<()> {
        let mut stack = Vec::new();
        let mut ancestors = path.ancestors();
        while let Some(ancestor) = ancestors.next() {
            match self.stats(ancestor)? {
                Some(stat) => {
                    if stat.is_dir {
                        break;
                    } else {
                        return Err(format_err!(
                            "Ensure dir: Expected dir, found file: {:?}",
                            ancestor
                        ));
                    }
                }
                None => {
                    stack.push(ancestor);
                }
            }
        }
        stack.reverse();
        for ancestor in stack.into_iter() {
            println!("Creating parent directory: {:?}", ancestor);
            self.mkdir(ancestor)?;
        }
        Ok(())
    }

    pub fn file_read_handle(&self, path: &Path) -> Result<SyncFileHandle<'a>> {
        match self.remote {
            Some(sftp) => {
                let handle = sftp.open(path)?;
                Ok(SyncFileHandle::Remote(handle))
            }
            None => {
                let handle = std::fs::File::open(path).map_err(er::Io::e)?;
                Ok(SyncFileHandle::Local(handle))
            }
        }
    }

    pub fn file_write_handle(&self, path: &Path) -> Result<SyncFileHandle<'a>> {
        match self.remote {
            Some(sftp) => {
                // As per ssh2::Sft::create(), using WRITE | TRUNCATE here to mean create
                // The `create` method does not take permission, so keeping this
                let handle = sftp
                    .open_mode(
                        &path,
                        ssh2::OpenFlags::WRITE | ssh2::OpenFlags::TRUNCATE,
                        0o644,
                        ssh2::OpenType::File,
                    )
                    .map_err(er::Ssh::e)?;
                Ok(SyncFileHandle::Remote(handle))
            }
            None => {
                // Open in write mode. todo: Permissions
                let handle = std::fs::File::create(path).map_err(er::Io::e)?;
                Ok(SyncFileHandle::Local(handle))
            }
        }
    }

    pub fn set_stats(&self, path: &Path, modified: Option<u64>) -> Result<()> {
        match self.remote {
            Some(sftp) => {
                if let Some(modified) = modified {
                    // Set modified time stat
                    let stat_setter = ssh2::FileStat {
                        size: None,
                        uid: None,
                        gid: None,
                        perm: None,
                        atime: None,
                        mtime: Some(modified),
                    };
                    sftp.setstat(path, stat_setter).map_err(er::Ssh::e)?;
                }
                Ok(())
            }
            None => {
                if let Some(modified) = modified {
                    filetime::set_file_mtime(
                        path,
                        filetime::FileTime::from_unix_time(modified as i64, 0),
                    )?;
                }
                Ok(())
            }
        }
    }
}
enum SyncSetEntry {
    File {
        /// Local relative path
        rel_path: PathBuf,
        /// Remote absolute path
        dest_path: PathBuf,
        /// Local absolute path
        source_path: PathBuf,
        modified: Option<u64>,
        bytes: u64,
    },
    Dir {
        rel_path: PathBuf,
        dest_path: PathBuf,
        source_path: PathBuf,
        modified: Option<u64>,
    },
}
// todo: Most helper creators should allow builder pattern
impl<'a> SyncSet<'a> {
    /// New SyncSet to "manually" call resolve(), or add
    /// functions on
    pub fn new(
        source_base: SyncBase<'a>,
        dest_base: SyncBase<'a>,
        sent_cache: SyncSentCache,
    ) -> Self {
        SyncSet {
            source_base,
            dest_base,
            entries: Vec::new(),
            sent_cache,
            ignore: SyncIgnore::default(),
        }
    }

    // todo: Allow more patterns, also important to make builder
    // patterns from creators for this to not be ignored itself
    pub fn ignore_rel_path(&mut self, rel_path: impl AsRef<Path>) {
        if self.entries.len() > 0 {
            eprintln!("Added ignore, but there are already entries!");
        }
        // Adding as abs_path
        let abs_path = self.source_base.path.join(rel_path);
        self.ignore.paths.insert(abs_path);
    }

    pub fn ignore_dirname(&mut self, dirname: &str) {
        if self.entries.len() > 0 {
            eprintln!("Added ignore, but there are already entries!");
        }
        self.ignore.dir_names.insert(dirname.to_owned());
    }

    // TODO: Change setup so we can transfer to different
    // named files/folders (I think this was done now?)

    /// Sets up a SyncSet, mapping the file's parent
    /// folder to given remote folder and resolves
    /// whether the file is newer
    pub fn from_file(
        file_path: SyncBase<'a>,
        dest_path: SyncBase<'a>,
        force: bool,
        sent_cache: SyncSentCache,
    ) -> Result<Self> {
        let (parent, file_path) = file_path.to_parent()?;
        let (remote_parent, dest_path) = dest_path.to_parent()?;
        let mut sync_set = Self::new(parent, remote_parent, sent_cache);
        sync_set.resolve_local_remote(&file_path, &dest_path, force)?;
        Ok(sync_set)
    }

    /// Given a source file, sync to dest folder
    pub fn from_file_to_folder(
        file_path: SyncBase<'a>,
        remote_folder: SyncBase<'a>,
        force: bool,
        sent_cache: SyncSentCache,
    ) -> Result<Self> {
        // There should always be a parent for local, at least `/`
        let (parent, file_path) = file_path.to_parent()?;
        let mut sync_set = Self::new(parent, remote_folder, sent_cache);
        sync_set.resolve_local(&file_path, force)?;
        Ok(sync_set)
    }

    /// Sets up a SyncSet mapping a local to a remote folder,
    /// and resolves which files in it are newer than
    /// on the server
    pub fn from_dir(
        local: SyncBase<'a>,
        remote: SyncBase<'a>,
        sftp: &ssh2::Sftp,
        force: bool,
        sent_cache: SyncSentCache,
    ) -> Result<Self> {
        // todo:! this ends up the same as from_file, so could just consolidate probably
        let (parent, file_path) = local.to_parent()?;
        let (remote_parent, dest_path) = remote.to_parent()?;
        // When given a folder, there should always be a parent
        // We could use directly local/remote, but this aligns with
        // file setup, and dedups calls to ensure_dir,
        // since given directory will be part of DirWalker.
        let mut sync_set = Self::new(parent, remote_parent, sent_cache);
        sync_set.resolve_local_remote(&file_path, &dest_path, force)?;
        Ok(sync_set)
    }

    /// Attempts to get seconds since unix epoch of metadata
    /// Returns none if it fails somehow
    fn modified_timestamp(metadata: &std::fs::Metadata) -> Option<u64> {
        match metadata.modified() {
            Ok(modified) => match modified.duration_since(std::time::UNIX_EPOCH) {
                Ok(duration) => Some(duration.as_secs()),
                Err(e) => {
                    eprintln!("Could not read modified since unix epoch: {:?}", e);
                    None
                }
            },
            Err(e) => {
                eprintln!("Could not read modified: {:?}", e);
                None
            }
        }
    }
    /// Resolves deriving from a local absolute path
    pub fn resolve_local<P: AsRef<Path>>(&mut self, local: P, force: bool) -> Result<()> {
        let local = local.as_ref();
        let rel_path = self.rel_from_abs(local)?;
        let remote = self.dest_base.path.join(&rel_path);
        self.resolve_specified(local, &remote, &rel_path, force)
    }

    /// Resolves deriving from a local absolute path, and a remote absolute path
    pub fn resolve_local_remote(&mut self, local: &Path, remote: &Path, force: bool) -> Result<()> {
        let rel_path = self.rel_from_abs(&local)?;
        self.resolve_specified(local, &remote, &rel_path, force)
    }

    // todo: Clearer naming with source/dest
    /// Expects absolute path. Walks through a directory, or single file
    /// and compares modified times with possible server file.
    /// Will add unless a server file exists with the same or higher
    /// modified time
    fn resolve_specified(
        &mut self,
        local: &Path,
        remote: &Path,
        rel_path: &Path,
        force: bool,
    ) -> Result<()> {
        let root_meta = {
            let meta = self.source_base.stats(local)?;
            meta.ok_or_else(|| format_err!("Source does not exist: {:?}", local))?
        };
        // If ignore set contains source path, we skip all
        if self.ignore.ignore_abs_path(local, root_meta.is_dir) {
            return Ok(());
        }
        // Just copying to old names to incrementally refactor
        let root_rel_path = rel_path.to_path_buf();
        let root_server_path = remote.to_path_buf();
        let root_server_meta = self.dest_base.stats(&root_server_path)?;
        println!("Stat for {:?} {:?}", root_server_path, root_server_meta);
        let mut failed_mtime = false;
        if root_meta.is_file {
            // This is a single file
            //println!("Single file: {:?}", local);
            // Do transfer unless we can confirm equal or
            // higher mtime on server
            // In the case of equal mtime, also check bytes to be more robust
            // for example in the event of failed/partial transfer
            let do_transfer = force
                || match (root_meta.mtime, root_meta.bytes, root_server_meta) {
                    (
                        Some(source_mtime),
                        Some(source_bytes),
                        Some(SyncEntryStats {
                            mtime: Some(dest_mtime),
                            bytes: Some(dest_bytes),
                            ..
                        }),
                    ) => {
                        if dest_mtime == source_mtime && dest_bytes == source_bytes {
                            false
                        } else if dest_mtime > source_mtime {
                            // Conservatively does not overwrite newer
                            false
                        } else {
                            true
                        }
                    }
                    (
                        Some(source_mtime),
                        _,
                        Some(SyncEntryStats {
                            mtime: Some(dest_mtime),
                            ..
                        }),
                    ) => {
                        // If we only have information on mtime
                        dest_mtime < source_mtime
                    }
                    (None, _, _) => {
                        failed_mtime = true;
                        true
                    }
                    _ => true,
                };
            if do_transfer {
                self.entries.push(SyncSetEntry::File {
                    rel_path: root_rel_path,
                    dest_path: root_server_path,
                    source_path: local.to_path_buf(),
                    modified: root_meta.mtime,
                    bytes: root_meta.bytes.ok_or_else(|| {
                        format_err!("Could not get bytes of local file: {:?}", local)
                    })?,
                });
            };
        } else if root_meta.is_dir {
            //println!("Walking dir: {:?}", local);
            let root_exist = root_server_meta.is_some();
            for entry in iter_dir(
                local.to_path_buf(),
                self.source_base.remote,
                self.ignore.clone(),
            )? {
                //println!("Entry is: {:?}", entry);
                let entry = entry?;
                let rel_path = self.rel_from_abs(&entry.path)?;
                if entry.stats.is_file {
                    let server_path = self.dest_base.path.join(&rel_path);
                    let do_transfer = if !root_exist || force {
                        // Skip check if root does not exist or force
                        true
                    } else {
                        match (entry.stats.mtime, self.sent_cache.get(&server_path)) {
                            (Some(source_time), Some(sent_cache_mtime)) => {
                                // Resolve by sent_cache
                                if source_time > sent_cache_mtime {
                                    true
                                } else {
                                    false
                                }
                            }
                            _ => {
                                // Could not resolve by sent cache, regular check
                                let server_path = self.dest_base.path.join(&rel_path);
                                let server_meta = self.dest_base.stats(&server_path)?;
                                match (entry.stats.mtime, entry.stats.bytes, server_meta) {
                                    (
                                        Some(source_mtime),
                                        Some(source_bytes),
                                        Some(SyncEntryStats {
                                            mtime: Some(dest_mtime),
                                            bytes: Some(dest_bytes),
                                            ..
                                        }),
                                    ) => {
                                        if dest_mtime == source_mtime && dest_bytes == source_bytes
                                        {
                                            false
                                        } else if dest_mtime > source_mtime {
                                            // Conservatively does not overwrite newer
                                            false
                                        } else {
                                            true
                                        }
                                    }
                                    (
                                        Some(source_mtime),
                                        _,
                                        Some(SyncEntryStats {
                                            mtime: Some(dest_mtime),
                                            ..
                                        }),
                                    ) => {
                                        // If we only have information on mtime
                                        dest_mtime < source_mtime
                                    }
                                    (None, _, _) => {
                                        failed_mtime = true;
                                        true
                                    }
                                    _ => true,
                                }
                            }
                        }
                    };
                    //println!("File: {:?}, do_transfer: {:?}", entry_path, do_transfer);
                    if do_transfer {
                        println!("Adding: {:?}", entry.path);
                        self.entries.push(SyncSetEntry::File {
                            dest_path: server_path,
                            rel_path,
                            source_path: entry.path.clone(),
                            modified: entry.stats.mtime,
                            bytes: entry.stats.bytes.ok_or_else(|| {
                                format_err!("Bytes missing from {:?}", entry.path)
                            })?,
                        });
                    } else {
                        // Add to sync cache here since we will not get to transfer
                        self.sent_cache
                            .set(&server_path, &entry.stats.mtime, false)?;
                    }
                } else if entry.stats.is_dir {
                    //println!("Adding dir: {:?}", entry_path);
                    // Adding all dirs to be safe with zip for now (ediţ: is checked when using sync_simple)
                    // todo: Possible optimization when syncing through sftp,
                    // to only add missing folders
                    let server_path = self.dest_base.path.join(&rel_path);
                    /*
                    let dir_meta = sftp.exist_stat(&server_path)?;
                    match dir_meta {
                        Some(_) => (),
                        None => {
                            self.entries.push(SyncSetEntry::Dir {
                                dest_path: server_path,
                                rel_path,
                                source_path: local.to_path_buf(),
                                modified: local_mtime,
                            });
                        }
                    }
                    */
                    self.entries.push(SyncSetEntry::Dir {
                        dest_path: server_path,
                        rel_path,
                        source_path: local.to_path_buf(),
                        modified: entry.stats.mtime,
                    });
                } else {
                    return Err(format_err!("Unrecognized type: {:?}", entry.path));
                }
            }
        } else {
            return Err(format_err!("Only files and dirs supported: {:?}", local));
        }
        // Do a sent_cache write since we might have added skipped items
        self.sent_cache.write()?;
        if failed_mtime {
            eprintln!("Notice: Failed reading local modified time on some entries");
        }
        Ok(())
    }
    #[inline]
    pub fn rel_from_abs(&self, path: &Path) -> Result<PathBuf> {
        path.strip_prefix(&self.source_base.path)
            .map_err(|_| {
                format_err!(
                    "Could not strip path, {:?} from: {:?}",
                    self.source_base.path,
                    path
                )
            })
            .map(|p| p.to_path_buf())
    }
    /// Note, these will not handle links currently
    pub fn sync_plain(&mut self) -> Result<()> {
        self.dest_base.ensure_dir(&self.dest_base.path)?;
        // Progress bar
        // todo: Slight problem this will show 0/0 until going (normally not even flash)
        let progress_bar = indicatif::ProgressBar::new(0);
        // todo: Can this have fixed width? Would clean up layout (or other solution)
        progress_bar.set_style(
            indicatif::ProgressStyle::default_bar()
                .template("{bar:25} {bytes}/{total_bytes} {msg}"),
        );
        for entry in &self.entries {
            match entry {
                SyncSetEntry::File {
                    dest_path,
                    source_path,
                    modified,
                    bytes,
                    ..
                } => {
                    self.transfer_file(source_path, dest_path, *bytes, *modified, &progress_bar)?;
                    // Sent cache
                    // todo: this is wasteful, just until other solution. We do want to
                    // continually update in case of interruption
                    self.sent_cache.set(dest_path, modified, true)?;
                }
                SyncSetEntry::Dir { dest_path, .. } => {
                    // Check for existing directory here, alternative is when resolving,
                    // in that case, ensure it works out with zip
                    let dir_meta = self.dest_base.stats(dest_path)?;
                    match dir_meta {
                        Some(_) => println!("Directory exist: {:?}", dest_path),
                        None => {
                            println!("Creating directory: {:?}", dest_path);
                            self.dest_base.mkdir(dest_path)?;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    pub fn transfer_file(
        &self,
        source_path: &Path,
        dest_path: &Path,
        bytes: u64,
        modified: Option<u64>,
        progress_bar: &indicatif::ProgressBar,
    ) -> Result<()> {
        // Wrapping inner in attempt to handle errors and clean up,
        // todo: I think this can panic, how to catch panic
        match self.transfer_file_inner(source_path, dest_path, bytes, modified, progress_bar) {
            Ok(_) => Ok(()),
            Err(e) => {
                match self.dest_base.remote {
                    Some(ssh) => {
                        // TODO: Make work. Maybe with a timeout, could also make some "todo queue" for the destination
                        ssh.unlink(dest_path)?;
                    }
                    None => {
                        // Remove potentially halfway transferred file
                        std::fs::remove_file(dest_path)?;
                    }
                }
                Err(e)
            }
        }
    }

    fn transfer_file_inner(
        &self,
        source_path: &Path,
        dest_path: &Path,
        bytes: u64,
        modified: Option<u64>,
        progress_bar: &indicatif::ProgressBar,
    ) -> Result<()> {
        //println!("Transfer file {:?} to {:?}", source_path, dest_path);
        progress_bar.set_message(&format!("{:?}", dest_path));
        progress_bar.set_length(bytes);
        // Just going through the permutations. It might be a good idea to parameterize,
        // though sometimes it may be good with some dynamic things, also
        // it would need to propagate a bit I think
        // Besides that, there might be a more elegant solution similar to this
        // todo: Rather take enums from <create>_file_handle
        match (
            self.source_base.file_read_handle(source_path)?,
            self.dest_base.file_write_handle(dest_path)?,
        ) {
            (SyncFileHandle::Local(mut source_handle), SyncFileHandle::Remote(mut dest_handle)) => {
                // Local to remote
                Self::copy(&mut source_handle, &mut dest_handle, progress_bar)?;
                self.dest_base.set_stats(dest_path, modified)?;
            }
            (SyncFileHandle::Remote(mut source_handle), SyncFileHandle::Local(mut dest_handle)) => {
                // Remote to local
                Self::copy(&mut source_handle, &mut dest_handle, progress_bar)?;
                self.dest_base.set_stats(dest_path, modified)?;
            }
            (
                SyncFileHandle::Remote(mut source_handle),
                SyncFileHandle::Remote(mut dest_handle),
            ) => {
                // Remote to remote
                Self::copy(&mut source_handle, &mut dest_handle, progress_bar)?;
                self.dest_base.set_stats(dest_path, modified)?;
            }
            // Interesting option, from local to another local
            (SyncFileHandle::Local(mut source_handle), SyncFileHandle::Local(mut dest_handle)) => {
                // Local to local
                Self::copy(&mut source_handle, &mut dest_handle, progress_bar)?;
                self.dest_base.set_stats(dest_path, modified)?;
            }
        }
        use std::io::Write;
        let _ = std::io::stdout().flush();
        println!(
            "{}",
            console::style(dest_path.as_os_str().to_string_lossy()).green()
        );
        let _ = std::io::stdout().flush();
        Ok(())
    }

    /// Utility function to copy from a read to a write handle
    /// while displaying progress
    /// Based on io::copy
    fn copy<R, W>(
        reader: &mut R,
        writer: &mut W,
        progress_bar: &indicatif::ProgressBar,
    ) -> Result<u64>
    where
        R: std::io::Read,
        W: std::io::Write,
    {
        use std::time::{Duration, Instant};
        // 8 bytes buffer
        let mut buf: [u8; 8192] = [0; 8192];
        let mut written = 0;
        progress_bar.set_position(0);
        let progress_interval = Duration::from_millis(200);
        let mut last_progress = Instant::now();
        loop {
            let len = match reader.read(&mut buf) {
                Ok(0) => {
                    progress_bar.finish();
                    return Ok(written);
                }
                Ok(len) => {
                    if last_progress.elapsed() >= progress_interval {
                        progress_bar.set_position(written);
                        last_progress = Instant::now();
                    }
                    len
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(er::Io::e(e).into()),
            };
            writer.write_all(&buf[..len]).map_err(er::Io::e)?;
            written += len as u64;
        }
    }

    /// Zips the registered files, transfers to server,
    /// unzips and deletes the zip-file
    pub fn sync_zipped(&mut self, ssh: &SshConn, sftp: &ssh2::Sftp) -> Result<()> {
        // As (at least) a quick fix after adding support for local/remote bases,
        // only supporting the original local to sftp, else fall back to sync_plain
        if !(self.source_base.remote.is_none() && self.dest_base.remote.is_some()) {
            println!("Falling back from sync_zipped to sync_plain");
            return self.sync_plain();
        }
        if self.entries.len() == 0 {
            // Todo: Better handling of added folders to zip
            println!("No files to sync");
            return Ok(());
        }
        let zip_file = self.source_base.path.join("to_sync.zip");
        print!("Compressing.. ");
        self.make_zip(&zip_file)?;
        println!("OK");
        let mut zip_set = SyncSet::from_file_to_folder(
            SyncBase::local(zip_file.clone()),
            SyncBase::remote(self.dest_base.path.clone(), sftp),
            true,
            SyncSentCache::None,
        )?;
        zip_set.sync_plain()?;
        // Write sync_cache
        self.sent_cache.write()?;
        // Decompress on the other side
        let server_zip_file = self.dest_base.path.join("to_sync.zip");
        let server_zip_str = server_zip_file.to_string_lossy();
        // Todo: Pay attention to paths when implementing support for file.a -> file.b
        ssh.exec(format!(
            "unzip -o {} -d {}",
            server_zip_str,
            zip_set.dest_base.path.to_string_lossy()
        ))?;
        // And remove zip file
        ssh.exec(format!("rm {}", server_zip_str))?;
        std::fs::remove_file(zip_file)?;
        Ok(())
    }
    fn make_zip(&mut self, zip_file: &Path) -> Result<()> {
        use std::fs;
        let to_sync_file = fs::File::create(zip_file)?;
        let mut zip_out = zip::ZipWriter::new(to_sync_file);
        for entry in &self.entries {
            match entry {
                SyncSetEntry::File {
                    dest_path,
                    source_path,
                    rel_path,
                    modified,
                    ..
                } => {
                    // Deflate (default) compression is pure rust,
                    // while bzip should compresss more but slower
                    // The size difference is not huge, but could be worth it
                    // https://cran.r-project.org/web/packages/brotli/vignettes/brotli-2015-09-22.pdf
                    let mut options = zip::write::FileOptions::default();
                    if let Some(modified) = modified {
                        options = options.last_modified_time(Self::seconds_to_datetime(*modified)?);
                    }
                    zip_out
                        .start_file_from_path(&rel_path, options)
                        .map_err(|e| format_err!("Zip file error: {:?}", e))?;
                    let mut file = fs::File::open(source_path)?;
                    io::copy(&mut file, &mut zip_out)?;
                    println!("Adding: {:?}", rel_path);
                    // Sent cache
                    self.sent_cache.set(dest_path, modified, false)?;
                }
                SyncSetEntry::Dir {
                    rel_path, modified, ..
                } => {
                    let mut options = zip::write::FileOptions::default();
                    if let Some(modified) = modified {
                        options = options.last_modified_time(Self::seconds_to_datetime(*modified)?);
                    }
                    zip_out
                        .add_directory_from_path(&rel_path, options)
                        .map_err(|e| format_err!("Zip directory error: {:?}", e))?;
                }
            }
        }
        zip_out
            .finish()
            .map_err(|e| format_err!("Zip finish error: {:?}", e))?;
        Ok(())
    }
    /// Expects duration since unix epoch and returns a zip::DateTime
    fn seconds_to_datetime(secs: u64) -> Result<zip::DateTime> {
        use chrono::{Datelike, Timelike};
        use std::convert::TryInto;
        let secs: i64 = secs
            .try_into()
            .map_err(|_| format_err!("Failed to convert seconds to i64"))?;
        let m = chrono::NaiveDateTime::from_timestamp(secs, 0);
        let date = m.date();
        let time = m.time();
        // Adding 1 to seconds as there was a `1` mismatch after transfer,
        // and unlike chrono, zip::DateTime has seconds bound 0:60 (vs 0:59)
        let seconds: u8 = time
            .second()
            .try_into()
            .map_err(|_| format_err!("Failed to convert second"))?;
        zip::DateTime::from_date_and_time(
            m.year()
                .try_into()
                .map_err(|_| format_err!("Failed to convert year"))?,
            date.month()
                .try_into()
                .map_err(|_| format_err!("Failed to convert month"))?,
            date.day()
                .try_into()
                .map_err(|_| format_err!("Failed to convert day"))?,
            time.hour()
                .try_into()
                .map_err(|_| format_err!("Failed to convert hour"))?,
            time.minute()
                .try_into()
                .map_err(|_| format_err!("Failed to convert minute"))?,
            seconds + 1,
        )
        .map_err(|_| format_err!("Failed to convert to zip::DateTime"))
    }
}

/// Sets up remote server. Mainly docker
pub fn setup_server(env: &CliEnv, server: ServerConfig) -> Result<()> {
    // Could check instance status here
    let conn = SshConn::connect_server(env, &server)?;
    // https://gist.github.com/npearce/6f3c7826c7499587f00957fee62f8ee9
    conn.exec("sudo yum update -y")?;
    conn.exec("sudo amazon-linux-extras install docker")?;
    // Start docker and enable auto-start
    conn.exec("sudo systemctl enable --now docker.service")?;
    conn.exec("sudo usermod -a -G docker ec2-user")?;
    // Docker compose
    conn.exec("sudo curl -L https://github.com/docker/compose/releases/download/1.25.4/docker-compose-$(uname -s)-$(uname -m) -o /usr/local/bin/docker-compose")?;
    conn.exec("sudo chmod +x /usr/local/bin/docker-compose")?;
    // Can see error code if docker-compose successfully installed
    conn.exec("docker-compose version")?;
    Ok(())
}

/// Ssh shell
pub fn ssh(env: &CliEnv, server: ServerConfig) -> Result<()> {
    let conn = SshConn::connect_server(env, &server)?;
    conn.shell()
}
/// Wp-cli ssh shell
pub fn wp_cli_ssh(env: &CliEnv, port: u16, server: Option<&ServerConfig>) -> Result<()> {
    let conn = SshConn::connect_container_ssh(env, port, "www-data", "www-data", server)?;
    conn.shell()
}

// todo: Some of this would be phased out to dedicated images
// hosted in docker hub or otherwise, though some remain like
// compose files and custom images
// In any case handy for development of server setup
/// Syncs server base files, like Dockerfiles to server
pub fn dockerfiles_to_server(env: &CliEnv, server: &ServerConfig) -> Result<()> {
    let conn = SshConn::connect_server(env, server)?;
    let mut server_dir = env.workdir_dir.clone();
    server_dir.push("server");
    let remote_server_dir = server.home_dir_and("viddler/server");
    let sftp = conn.sftp()?;
    let mut sync_set = SyncSet::new(
        SyncBase::local(server_dir.clone()),
        SyncBase::remote(remote_server_dir.clone(), &sftp),
        SyncSentCache::load(env, &server.name)?,
    );
    for subdir in ["base", "prod"].into_iter() {
        let mut local = server_dir.clone();
        local.push(subdir);
        sync_set.resolve_local(&local, false)?;
    }
    sync_set.sync_zipped(&conn, &sftp)?;
    Ok(())
}

/// Read non-blocking from channel until
/// 0 read
fn read_until_zero<R: std::io::Read>(
    r: &mut R,
    read_buf: &mut [u8; 2048],
    acc_buf: &mut Vec<u8>,
) -> Result<()> {
    loop {
        match r.read(read_buf) {
            Ok(num) => {
                if num > 0 {
                    acc_buf.extend_from_slice(&read_buf[0..num]);
                } else {
                    break;
                }
            }
            Err(e) => {
                // Accept WouldBlock and Interrupted
                match e.kind() {
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted => {
                        break;
                    }
                    std::io::ErrorKind::Other => {
                        use std::error::Error;
                        // todo: Better detection
                        if e.description() != "would block" {
                            return er::Io::msg("Read failed", e).err();
                        }
                        break;
                    }
                    _ => {
                        return er::Io::msg("Read tunnel", e).err();
                    }
                }
            }
        }
    }
    Ok(())
}

pub struct SshTunnel {
    join_handle: std::thread::JoinHandle<Result<()>>,
    close_sender: std::sync::mpsc::SyncSender<bool>,
}
impl SshTunnel {
    /// Tunnels incoming requests to a port on
    /// server. Runs in a thread so it's possible
    /// to connect from other functions.
    /// Will shut down tunnel after the first connection is closed
    /// Looks for first available port between 4000-4999
    pub fn new(env: &CliEnv, server: &ServerConfig, remote_port: u16) -> Result<(Self, u16)> {
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        // look for available port/successful bind
        let (listener, local_port) = {
            let mut listener = None;
            for local_port in 4000..5000 {
                match TcpListener::bind(format!("127.0.0.1:{}", local_port)) {
                    Ok(bound) => {
                        listener = Some((bound, local_port));
                        break;
                    }
                    Err(_) => (),
                }
            }
            match listener {
                Some(listener_and_port) => listener_and_port,
                None => {
                    return Err(format_err!(
                        "Could not find successful bound over ports 4000-4999"
                    ))
                }
            }
        };
        println!("Tunnel opened on: {}", local_port);
        let handle = {
            // or elastic_ip
            let addr = server.url.clone();
            let pem_file = server.pem_path(env);
            let server_name = server.name.clone();
            std::thread::spawn(move || -> Result<()> {
                let conn = SshConn::connect(addr, pem_file, &server_name)?;
                listener.set_nonblocking(true)?;
                for stream in listener.incoming() {
                    match stream {
                        Ok(mut socket) => {
                            conn.session.set_blocking(true);
                            let mut channel = conn
                                .session
                                .channel_direct_tcpip("127.0.0.1", remote_port, None)
                                .map_err(|e| er::Ssh::msg("Failed to connect on server", e))?;
                            println!("Opened tunnel");
                            conn.session.set_blocking(false);
                            socket.set_nonblocking(true).map_err(er::Io::e)?;
                            // Now pipe both ways
                            let mut acc_buf = Vec::with_capacity(2048);
                            use std::io::Write;
                            let mut read_buf: [u8; 2048] = [0; 2048];
                            // Loop until connection is closed
                            while !channel.eof() {
                                // Stdio
                                read_until_zero(&mut channel, &mut read_buf, &mut acc_buf)?;
                                // Write back to socket
                                if acc_buf.len() > 0 {
                                    socket.write_all(&acc_buf).map_err(er::Io::e)?;
                                    socket.flush().map_err(er::Io::e)?;
                                    acc_buf.clear();
                                }
                                // Stderr
                                read_until_zero(
                                    &mut channel.stderr(),
                                    &mut read_buf,
                                    &mut acc_buf,
                                )?;
                                // Write back to socket
                                if acc_buf.len() > 0 {
                                    socket.write_all(&acc_buf).map_err(er::Io::e)?;
                                    socket.flush().map_err(er::Io::e)?;
                                    acc_buf.clear();
                                }
                                // Read any data on socket and forward to tunneled
                                read_until_zero(&mut socket, &mut read_buf, &mut acc_buf)?;
                                // Write back to channel
                                if acc_buf.len() > 0 {
                                    channel.write_all(&acc_buf).map_err(er::Io::e)?;
                                    channel.flush().map_err(er::Io::e)?;
                                    acc_buf.clear();
                                }
                                std::thread::sleep(std::time::Duration::from_millis(50));
                            }
                            println!("Channel closed");
                        }
                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                            std::thread::sleep(std::time::Duration::from_millis(200));
                        }
                        Err(e) => return er::Io::msg("Tunnel listener failed", e).err(),
                    }
                    // Check if we have close signal
                    match rx.try_recv() {
                        Ok(_) => break,
                        Err(_) => (),
                    }
                }
                println!("Done listener loop");
                Ok(())
            })
        };
        Ok((
            SshTunnel {
                join_handle: handle,
                close_sender: tx,
            },
            local_port,
        ))
    }

    pub fn close(self) -> Result<()> {
        self.close_sender.send(true)?;
        let thread_result = self
            .join_handle
            .join()
            .map_err(|_| format_err!("Failed to join tunnel thread"))?;
        thread_result
    }
}

pub fn proxy_to_localhost(
    env: &CliEnv,
    mut current_process: utils::CurrentProcess,
    project: &mut crate::project::ProjectConfig,
    remote_port: u16,
    local_port: u16,
) -> Result<()> {
    let server = project.require_server(env)?;
    // Should we allow specific local port?
    let (tunnel, local_port) = SshTunnel::new(env, &server, remote_port)?;
    println!("Local port: {}", local_port);
    // This should maybe close on ctrl-c, or other input
    tunnel
        .join_handle
        .join()
        .map_err(|_| format_err!("Failed to join tunnel thread"))??;
    Ok(())
}
