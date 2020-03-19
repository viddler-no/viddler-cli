use clap::{self, App, Arg, SubCommand};

struct DisplayOrderCounter(usize);
impl DisplayOrderCounter {
    fn next(&mut self) -> usize {
        self.0 = self.0 + 1;
        self.0
    }
}

pub fn cli_app() -> App<'static, 'static> {
    let mut order = DisplayOrderCounter(0);
    App::new("Project-cli")
        .version("0.1")
        .subcommand(
            SubCommand::with_name("init")
                .about("Initialize a project")
                .arg(Arg::with_name("name"))
                .display_order(order.next()),
        )
        .subcommand(
            SubCommand::with_name("setup-project")
                .about("Creates config folders and .env file")
                .display_order(order.next()),
        )
        .subcommand(
            SubCommand::with_name("setup-project-prod")
                .about("Creates config folders and .env file on server")
                .display_order(order.next()),
        )
        .subcommand(
            SubCommand::with_name("dev")
                .about("For a given project, starts/creates dev containers")
                .setting(clap::AppSettings::TrailingVarArg)
                .display_order(order.next())
                .arg(
                    Arg::with_name("dev-args")
                        .multiple(true)
                        .help("Arguments passed to docker-compose"),
                ),
        )
        .subcommand(
            SubCommand::with_name("code")
                .about("Opens code editor with a project")
                .display_order(order.next()),
        )
        .subcommand(
            SubCommand::with_name("push")
                .about("Commits and pushes a project to git")
                .display_order(order.next()),
        )
        .subcommand(
            SubCommand::with_name("content-to-prod")
                .about("Transfers uploads and database to prod")
                .display_order(order.next()),
        )
        .subcommand(
            SubCommand::with_name("content-to-local")
                .about("Transfers uploads and database from prod to local")
                .display_order(order.next()),
        )
        .subcommand(
            SubCommand::with_name("sync-server")
                .about("Transfers local plugins/themes to server, activates if needed")
                .display_order(order.next()),
        )
        .subcommand(
            SubCommand::with_name("sync-local")
                .about("Activates local plugins, themes and dependencies on dev server")
                .display_order(order.next()),
        )
        .subcommand(
            SubCommand::with_name("wp-ssh")
                .about("Wp-cli shell through ssh")
                .display_order(order.next()),
        )
        .subcommand(
            SubCommand::with_name("wp-ssh-server")
                .about("Wp-cli shell through ssh and tunnel from server")
                .display_order(order.next()),
        )
        .subcommand(
            SubCommand::with_name("ssh-server")
                .about("For a server, enter shell through ssh")
                .display_order(order.next()),
        )
        .subcommand(
            SubCommand::with_name("prod")
                .about("For a given project, updates, starts prod containers")
                .setting(clap::AppSettings::TrailingVarArg)
                .display_order(order.next())
                .arg(
                    Arg::with_name("prod-args")
                        .multiple(true)
                        .help("Arguments passed to docker-compose"),
                ),
        )
        .subcommand(
            SubCommand::with_name("prod-locally")
                .about("For a given project, starts prod setup locally")
                .setting(clap::AppSettings::TrailingVarArg)
                .display_order(order.next())
                .arg(
                    Arg::with_name("prod-args")
                        .multiple(true)
                        .help("Arguments passed to docker-compose"),
                ),
        )
        .subcommand(
            SubCommand::with_name("dev-permissions")
                .about("Sets dev permissions so usable with www-data group")
                .display_order(order.next()),
        )
        .subcommand(
            SubCommand::with_name("clean-dev")
                .about("DANGER: Shuts down containers and removes volumes")
                .display_order(order.next()),
        )
        .subcommand(
            SubCommand::with_name("vscode-debug-config")
                .about("Creates vscode debug config")
                .display_order(order.next()),
        )
        .subcommand(
            SubCommand::with_name("admin-server")
                .about("Adds or modifies server config")
                .display_order(order.next()),
        )
        .subcommand(
            SubCommand::with_name("admin-git-account")
                .about("Adds or modifies a git account")
                .display_order(order.next()),
        )
        .subcommand(
            SubCommand::with_name("admin-aws")
                .about("Configures aws credentials")
                .display_order(order.next()),
        )
        .subcommand(
            SubCommand::with_name("provision")
                .about("Provisions an ec2 instance")
                .display_order(order.next()),
        )
        .subcommand(
            SubCommand::with_name("deploy")
                .about("Installs required software on server, and set it up")
                .display_order(order.next()),
        )
        .subcommand(
            SubCommand::with_name("docker-files-to-server")
                .about("Syncs base files like Dockerfiles to server. Required for prod command")
                .display_order(order.next()),
        )
        .subcommand(
            SubCommand::with_name("workspace-init")
                .about("Inits and creates a git repo given a registered git account")
                .display_order(order.next()),
        )
        .subcommand(
            SubCommand::with_name("workspace-push")
                .about("Pushes workspace repository to origin master")
                .display_order(order.next()),
        )
        .subcommand(
            SubCommand::with_name("workspace-clone")
                .about("Clones a given git repository into workspace location")
                .display_order(order.next()),
        )
        .subcommand(
            SubCommand::with_name("rebuild-container")
                .about("Rebuilds a given service/container")
                .display_order(order.next())
                .arg(Arg::with_name("service").help("Container to rebuild and restart")),
        )
        .subcommand(
            SubCommand::with_name("proxy-log-server")
                .about("Proxies prod log server to localhost:7007")
                .display_order(order.next()),
        )
        // These are mostly for devs of these tools
        .subcommand(
            SubCommand::with_name("rust-build-init")
                .about("Sets up build container for building workdir/tools projects")
                .display_order(order.next()),
        )
        .subcommand(
            SubCommand::with_name("rust-build-update")
                .about("Runs rustup update on rust build container")
                .display_order(order.next()),
        )
        .subcommand(
            SubCommand::with_name("rebuild-log-dev")
                .about("Rebuilds log server for dev")
                .display_order(order.next()),
        )
        .subcommand(
            SubCommand::with_name("rebuild-log-prod")
                .about("Rebuilds log server for prod")
                .display_order(order.next()),
        )
}
