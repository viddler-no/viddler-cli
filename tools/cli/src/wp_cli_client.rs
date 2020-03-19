// Adapted from https://github.com/actix/examples/tree/master/websocket

use std::time::Duration;

use crate::server::{self, ServerConfig};
use crate::utils::{self, CliEnv};
use actix::io::SinkWrite;
use actix::*;
use actix_codec::{AsyncRead, AsyncWrite, Framed};
use awc::{
    error::WsProtocolError,
    ws::{Codec, Frame, Message},
    Client,
};
use futures::{
    lazy,
    stream::{SplitSink, Stream},
    Future,
};
use serde::{Deserialize, Serialize};

// Todo: (Seriously) consider another protocol, possibly ssh
// Although multi-site setup might gain advantages of something else,
// some multi-user setup might be a solid solution

/// Used to pass a list of commands
/// This is serialized and passed to command
/// actor.
#[derive(Serialize)]
pub struct CmdMsg {
    pub cmd: String,
    pub args: Vec<String>,
}
#[derive(Serialize, Message)]
pub enum WsMsg {
    CmdMsg(CmdMsg),
    DoneMsg,
}

use std::sync::mpsc::{Receiver, SyncSender};
pub struct CliConnection {
    send_cmd: SyncSender<WsMsg>,
    recv_from_cmd: Receiver<FromCmdMsg>,
}
// Attempt graceful shutdown
impl Drop for CliConnection {
    fn drop(&mut self) {
        match self.send_cmd.send(WsMsg::DoneMsg) {
            Ok(_) => match self.recv_from_cmd.recv() {
                Ok(from_cmd) => match from_cmd {
                    FromCmdMsg::AllDone => {
                        println!("Got AllDone in drop");
                    }
                    _ => println!("Got other than AllDone in drop: {:?}", from_cmd),
                },
                Err(e) => println!("Error in drop: {:?}", e),
            },
            Err(e) => println!("Send failed in drop: {:?}", e),
        }
    }
}
// todo: The whole protocol is complex and brittle. Has helped
// learning, but a simpler solution would be nice
impl CliConnection {
    pub fn new(env: &CliEnv, server: Option<&ServerConfig>) -> Self {
        let (send_cmd, recv_cmd) = std::sync::mpsc::sync_channel(0);
        let (send_from_cmd, recv_from_cmd) = std::sync::mpsc::sync_channel(0);
        // todo: Detect/start docker
        // Also would be better to loop on ws() I think
        let (ws_url, tunnel_handle) = match server {
            Some(server_config) => {
                let ws_url = "127.0.0.1:5712".to_string();
                // Todo: Wait for, currently tunnel will only
                // process one request
                let handle = match server::tunnel_single_thread(&env, server_config, 5712, 5711) {
                    Ok(handle) => handle,
                    Err(e) => panic!("Tunnel failed: {:?}", e),
                };
                (ws_url, Some(handle))
            }
            None => {
                let ws_url = "127.0.0.1:5711".to_string();
                if !utils::wait_for(&ws_url) {
                    panic!("Failed to connect to cli server");
                }
                (ws_url, None)
            }
        };
        let _handle = std::thread::spawn(move || {
            ::std::env::set_var("RUST_LOG", "actix_web=info");
            match env_logger::try_init() {
                Ok(_) => {
                    println!("Logger initialized");
                }
                Err(e) => {
                    println!("Logger might be initialized: {:?}", e);
                }
            }
            let sys = actix::System::new("wp-cli-client");
            Arbiter::spawn(lazy(move || {
                Client::new()
                    .ws(format!("http://{}/ws/", ws_url))
                    .connect()
                    .map_err(|e| {
                        println!("Ws connect error: {}", e);
                        ()
                    })
                    .map(move |(_response, framed)| {
                        let (sink, stream) = framed.split();
                        let addr = ChatClient::create(|ctx| {
                            ChatClient::add_stream(stream, ctx);
                            ChatClient {
                                sink: SinkWrite::new(sink, ctx),
                                send_from_cmd,
                            }
                        });
                        // Thread looping to wait for messages
                        std::thread::spawn(move || {
                            loop {
                                match recv_cmd.recv() {
                                    Ok(ws_msg) => {
                                        println!("Received mpsc");
                                        match &ws_msg {
                                            WsMsg::CmdMsg(_cmd_msg) => addr.do_send(ws_msg),
                                            WsMsg::DoneMsg => {
                                                addr.do_send(ws_msg);
                                                // Break this loop, system should
                                                // go on until commands are processed
                                                // and done message processed
                                                break;
                                            }
                                        }
                                    }
                                    Err(e) => eprintln!("Receive error: {:?}", e),
                                }
                            }
                        });
                    })
            }));
            let _ = sys.run();
            match tunnel_handle {
                Some(handle) => match handle.join() {
                    Ok(res) => {
                        println!("Joined tunnel handle: {:?}", res);
                    }
                    Err(e) => {
                        eprintln!("Error joining tunnel handle: {:?}", e);
                    }
                },
                None => (),
            }
            println!("System done");
        });
        CliConnection {
            send_cmd,
            recv_from_cmd,
        }
    }

    pub fn cmd<S, S2>(&self, cmd: S, args: Vec<S2>) -> Result<String, String>
    where
        S: Into<String>,
        S2: Into<String>,
    {
        self.cmd_msg(CmdMsg {
            cmd: cmd.into(),
            args: args.into_iter().map(|i| i.into()).collect(),
        })
    }

    pub fn cmd_msg(&self, cmd: CmdMsg) -> Result<String, String> {
        match self.send_cmd.send(WsMsg::CmdMsg(cmd)) {
            Ok(_) => (),
            Err(e) => return Err(format!("Send error: {:?}", e)),
        }
        let mut out_buffer = String::new();
        loop {
            match self.recv_from_cmd.recv() {
                Ok(from_cmd) => {
                    // Handle FromCmdMsg
                    match from_cmd {
                        FromCmdMsg::Info(info) => println!("Info: {}", info),
                        FromCmdMsg::Line(line) => {
                            // I think we need stderr in here too (different msg)
                            // as this doesn't capture all apparently
                            println!("{}", line);
                            out_buffer.push('\n');
                            out_buffer.push_str(&line);
                        }
                        FromCmdMsg::CmdDone => {
                            println!("Command done");
                            break;
                        }
                        FromCmdMsg::AllDone => (),
                    }
                }
                Err(e) => eprintln!("Error receiving from_cmd: {:?}", e),
            }
        }
        Ok(out_buffer)
    }
}

/// Message mirroring those coming from command actor
/// Line is output,
/// Info is additional info around command execution,
/// in our case, waiting for services to come online
/// When a process is finished, CmdDone is sent
#[derive(Deserialize, Debug)]
pub enum FromCmdMsg {
    Line(String),
    CmdDone,
    Info(String),
    AllDone,
}

struct ChatClient<T: AsyncRead + AsyncWrite> {
    sink: SinkWrite<SplitSink<Framed<T, Codec>>>,
    send_from_cmd: SyncSender<FromCmdMsg>,
}

impl<T: 'static> Actor for ChatClient<T>
where
    T: AsyncRead + AsyncWrite,
{
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Context<Self>) {
        // start heartbeats otherwise server will disconnect after 10 seconds
        self.hb(ctx)
    }

    fn stopped(&mut self, _: &mut Context<Self>) {
        println!("Disconnected");

        // Stop application on disconnect
        System::current().stop();
    }
}

impl<T: 'static> ChatClient<T>
where
    T: AsyncRead + AsyncWrite,
{
    // Heartbeats might be less relevant for our use
    // case. I'm not sure we want the process to
    // terminate without heartbeat.
    // Interrupts on the other hand would be nice
    // todo: Is heartbeats part of the ws protocol, though?
    fn hb(&self, ctx: &mut Context<Self>) {
        ctx.run_later(Duration::new(1, 0), |act, ctx| {
            act.sink.write(Message::Ping(String::new())).unwrap();
            act.hb(ctx);

            // client should also check for a timeout here, similar to the
            // server code
        });
    }
}

/// Handle command and stop messages
impl<T: 'static> Handler<WsMsg> for ChatClient<T>
where
    T: AsyncRead + AsyncWrite,
{
    type Result = ();

    // Serialize and write to socket sink
    fn handle(&mut self, msg: WsMsg, _ctx: &mut Context<Self>) {
        println!("In handle");
        match serde_json::to_string(&msg) {
            Ok(json) => {
                println!("Ready to write: {}", json);
                match self.sink.write(Message::Text(json)) {
                    Ok(ok) => {
                        // Possible AsyncSink::NotReady, AsyncSink::Ready
                        println!("Wrote: {:?}", ok);
                    }
                    Err(e) => {
                        println!("Error writing: {:?}", e);
                    }
                }
            }
            Err(e) => {
                println!("Could not serialize: {:?}", e);
            }
        }
    }
}

/// Handle server websocket messages
impl<T: 'static> StreamHandler<Frame, WsProtocolError> for ChatClient<T>
where
    T: AsyncRead + AsyncWrite,
{
    fn handle(&mut self, msg: Frame, ctx: &mut Context<Self>) {
        match msg {
            Frame::Text(txt) => {
                // Attempt to extract FromCmdMsg
                let from_cmd = match txt {
                    Some(bytes) => match serde_json::from_slice::<FromCmdMsg>(&bytes) {
                        Ok(from_cmd) => from_cmd,
                        Err(e) => {
                            println!("Deserialize error: {:?}", e);
                            return;
                        }
                    },
                    None => {
                        println!("Received none");
                        return;
                    }
                };
                let stop_ctx = match &from_cmd {
                    FromCmdMsg::AllDone => {
                        // All commands in list processed, shutting down
                        println!("Got AllDone, shuttings down system and closing connection");
                        true
                    }
                    _ => false,
                };
                // Send message to mpsc channel
                match self.send_from_cmd.send(from_cmd) {
                    Ok(_) => (),
                    Err(e) => eprintln!("Send error, {:?}", e),
                }
                if stop_ctx {
                    ctx.stop();
                }
            }
            _ => (),
        }
    }

    fn started(&mut self, _ctx: &mut Context<Self>) {
        println!("Connected");
    }

    fn finished(&mut self, ctx: &mut Context<Self>) {
        println!("Server disconnected");
        ctx.stop()
    }
}

impl<T: 'static> actix::io::WriteHandler<WsProtocolError> for ChatClient<T> where
    T: AsyncRead + AsyncWrite
{
}
