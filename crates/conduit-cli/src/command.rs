use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};
use serde_json::{Map, Value};

use crate::CliError;

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum OutputFormat {
    Text,
    Json,
    Jsonl,
}

#[derive(Debug, Parser)]
#[command(
    name = "conduit",
    version,
    about = "Operate Conduit without the dashboard"
)]
pub struct Cli {
    #[arg(
        long,
        env = "CONDUIT_CONTROL_PLANE_URL",
        default_value = "http://127.0.0.1:8787"
    )]
    pub control_plane: String,
    #[arg(long, value_enum, default_value = "text")]
    pub output: OutputFormat,
    #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(1..=300))]
    pub timeout_seconds: u64,
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    Auth {
        #[command(subcommand)]
        command: AuthCommand,
    },
    Device {
        #[command(subcommand)]
        command: DeviceCommand,
    },
    Project {
        #[command(subcommand)]
        command: ProjectCommand,
    },
    Session {
        #[command(subcommand)]
        command: SessionCommand,
    },
    Board {
        #[command(subcommand)]
        command: BoardCommand,
    },
    Agent {
        #[command(subcommand)]
        command: AgentCommand,
    },
    Assignment {
        #[command(subcommand)]
        command: AssignmentCommand,
    },
    Run {
        #[command(subcommand)]
        command: RunCommand,
    },
    Quick {
        #[command(subcommand)]
        command: QuickCommand,
    },
    Runtime {
        #[command(subcommand)]
        command: RuntimeCommand,
    },
    Task {
        #[command(subcommand)]
        command: TaskCommand,
    },
    Logs {
        #[command(subcommand)]
        command: LogsCommand,
    },
    Eval {
        #[command(subcommand)]
        command: EvalCommand,
    },
    Connector {
        #[command(subcommand)]
        command: ConnectorCommand,
    },
    Storage {
        #[command(subcommand)]
        command: StorageCommand,
    },
    Backup {
        #[command(subcommand)]
        command: BackupCommand,
    },
    Doctor,
}

#[derive(Debug, Args, Clone)]
pub struct InputArgs {
    #[arg(long, value_name = "JSON")]
    pub data: Option<String>,
    #[arg(long, value_name = "PATH")]
    pub file: Option<PathBuf>,
}

#[derive(Debug, Args, Clone)]
pub struct MutationArgs {
    #[arg(value_name = "ID")]
    pub id: Option<String>,
    #[command(flatten)]
    pub input: InputArgs,
    #[arg(long)]
    pub revision: Option<u64>,
    #[arg(long)]
    pub idempotency_key: Option<String>,
}

#[derive(Debug, Args, Clone)]
pub struct IdArgs {
    pub id: String,
}

#[derive(Debug, Subcommand)]
pub enum AuthCommand {
    Register(InputArgs),
    Login(InputArgs),
    Logout(MutationArgs),
    Status,
    Recover(InputArgs),
    RevokePasskey(MutationArgs),
}

#[derive(Debug, Subcommand)]
pub enum DeviceCommand {
    Enroll(MutationArgs),
    List,
    Show(IdArgs),
    Revoke(MutationArgs),
    RotateKey(MutationArgs),
    Doctor,
}

#[derive(Debug, Subcommand)]
pub enum ProjectCommand {
    Create(MutationArgs),
    List,
    Show(IdArgs),
    AddSource(MutationArgs),
    AddLocation(MutationArgs),
    Update(MutationArgs),
}

#[derive(Debug, Subcommand)]
pub enum SessionCommand {
    Create(MutationArgs),
    List,
    Show(IdArgs),
    Accept(MutationArgs),
}

#[derive(Debug, Subcommand)]
pub enum BoardCommand {
    Post(MutationArgs),
    Read(IdArgs),
    Search(InputArgs),
    Edit(MutationArgs),
}

#[derive(Debug, Subcommand)]
pub enum AgentCommand {
    Add(MutationArgs),
    List,
    Show(IdArgs),
    Remove(MutationArgs),
    Probe(MutationArgs),
}

#[derive(Debug, Subcommand)]
pub enum AssignmentCommand {
    Create(MutationArgs),
    Show(IdArgs),
    Cancel(MutationArgs),
    Input(MutationArgs),
    Steer(MutationArgs),
}

#[derive(Debug, Subcommand)]
pub enum RunCommand {
    List,
    Show(IdArgs),
    Follow(IdArgs),
    Pause(MutationArgs),
    Resume(MutationArgs),
    Cancel(MutationArgs),
    Recover(MutationArgs),
}

#[derive(Debug, Subcommand)]
pub enum QuickCommand {
    Command(MutationArgs),
    Agent(MutationArgs),
    Vm(MutationArgs),
}

#[derive(Debug, Subcommand)]
pub enum RuntimeCommand {
    List,
    Show(IdArgs),
    Start(MutationArgs),
    Stop(MutationArgs),
    Pause(MutationArgs),
    Resume(MutationArgs),
    Snapshot(MutationArgs),
    Archive(MutationArgs),
    Restore(MutationArgs),
    Destroy(MutationArgs),
}

#[derive(Debug, Subcommand)]
pub enum TaskCommand {
    Create(MutationArgs),
    List,
    Show(IdArgs),
    Update(MutationArgs),
    Link(MutationArgs),
}

#[derive(Debug, Subcommand)]
pub enum LogsCommand {
    Search(InputArgs),
    Show(IdArgs),
    Export(MutationArgs),
}

#[derive(Debug, Subcommand)]
pub enum EvalCommand {
    Start(MutationArgs),
    Show(IdArgs),
    Compare(InputArgs),
}

#[derive(Debug, Subcommand)]
pub enum ConnectorCommand {
    Create(MutationArgs),
    List,
    Show(IdArgs),
    Pause(MutationArgs),
    Resume(MutationArgs),
    Revoke(MutationArgs),
    Policy(MutationArgs),
}

#[derive(Debug, Subcommand)]
pub enum StorageCommand {
    List,
    Show(IdArgs),
    Configure(MutationArgs),
    Pin(MutationArgs),
    Unpin(MutationArgs),
    Move(MutationArgs),
    Restore(MutationArgs),
}

#[derive(Debug, Subcommand)]
pub enum BackupCommand {
    Create(MutationArgs),
    Verify(MutationArgs),
    Restore(MutationArgs),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Target {
    ControlPlane,
    Node,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Method {
    Get,
    Post,
    Patch,
    Delete,
}

#[derive(Debug, Clone)]
pub(crate) struct JsonInput {
    pub inline: Option<String>,
    pub file: Option<PathBuf>,
}

impl From<InputArgs> for JsonInput {
    fn from(value: InputArgs) -> Self {
        Self {
            inline: value.data,
            file: value.file,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Invocation {
    pub target: Target,
    pub method: Method,
    pub route: String,
    pub body: Option<Value>,
    pub input: Option<JsonInput>,
    pub revision: Option<u64>,
    pub idempotency_key: Option<String>,
    pub effectful: bool,
    pub auth_required: bool,
}

impl Invocation {
    fn get(route: impl Into<String>) -> Self {
        Self {
            target: Target::ControlPlane,
            method: Method::Get,
            route: route.into(),
            body: None,
            input: None,
            revision: None,
            idempotency_key: None,
            effectful: false,
            auth_required: true,
        }
    }

    fn mutation(
        method: Method,
        route: impl Into<String>,
        args: MutationArgs,
    ) -> Result<Self, CliError> {
        let mut body = Map::new();
        if let Some(id) = args.id.as_ref() {
            validate_segment(id)?;
            body.insert("targetId".to_owned(), Value::String(id.clone()));
        }
        Ok(Self {
            target: Target::ControlPlane,
            method,
            route: route.into(),
            body: Some(Value::Object(body)),
            input: Some(args.input.into()),
            revision: args.revision,
            idempotency_key: args.idempotency_key,
            effectful: true,
            auth_required: true,
        })
    }

    fn input(method: Method, route: impl Into<String>, input: InputArgs) -> Self {
        Self {
            target: Target::ControlPlane,
            method,
            route: route.into(),
            body: None,
            input: Some(input.into()),
            revision: None,
            idempotency_key: None,
            effectful: method != Method::Get,
            auth_required: true,
        }
    }

    fn node(mut self) -> Self {
        self.target = Target::Node;
        self
    }

    fn public(mut self) -> Self {
        self.auth_required = false;
        self
    }
}

impl Commands {
    pub(crate) fn into_invocation(self) -> Result<Invocation, CliError> {
        let invocation = match self {
            Self::Auth { command } => auth(command)?,
            Self::Device { command } => device(command)?,
            Self::Project { command } => project(command)?,
            Self::Session { command } => session(command)?,
            Self::Board { command } => board(command)?,
            Self::Agent { command } => agent(command)?,
            Self::Assignment { command } => assignment(command)?,
            Self::Run { command } => run(command)?,
            Self::Quick { command } => quick(command)?,
            Self::Runtime { command } => runtime(command)?,
            Self::Task { command } => task(command)?,
            Self::Logs { command } => logs(command)?,
            Self::Eval { command } => eval(command)?,
            Self::Connector { command } => connector(command)?,
            Self::Storage { command } => storage(command)?,
            Self::Backup { command } => backup(command)?,
            Self::Doctor => unreachable!("doctor is handled before routing"),
        };
        Ok(invocation)
    }
}

fn auth(command: AuthCommand) -> Result<Invocation, CliError> {
    Ok(match command {
        AuthCommand::Register(input) => {
            Invocation::input(Method::Post, "/api/v1/auth/passkeys/register", input).public()
        }
        AuthCommand::Login(input) => {
            Invocation::input(Method::Post, "/api/v1/auth/login", input).public()
        }
        AuthCommand::Logout(args) => {
            Invocation::mutation(Method::Post, "/api/v1/auth/logout", args)?
        }
        AuthCommand::Status => Invocation::get("/api/v1/auth/status"),
        AuthCommand::Recover(input) => {
            Invocation::input(Method::Post, "/api/v1/auth/recovery", input).public()
        }
        AuthCommand::RevokePasskey(args) => {
            Invocation::mutation(Method::Delete, "/api/v1/auth/passkeys/revoke", args)?
        }
    })
}

fn device(command: DeviceCommand) -> Result<Invocation, CliError> {
    Ok(match command {
        DeviceCommand::Enroll(args) => {
            Invocation::mutation(Method::Post, "device.enroll", args)?.node()
        }
        DeviceCommand::List => Invocation::get("/api/v1/devices"),
        DeviceCommand::Show(args) => Invocation::get(id_route("/api/v1/devices", &args.id)?),
        DeviceCommand::Revoke(args) => {
            Invocation::mutation(Method::Delete, "/api/v1/devices/revoke", args)?
        }
        DeviceCommand::RotateKey(args) => {
            Invocation::mutation(Method::Post, "device.rotate_key", args)?.node()
        }
        DeviceCommand::Doctor => Invocation::get("device.doctor").node(),
    })
}

fn project(command: ProjectCommand) -> Result<Invocation, CliError> {
    Ok(match command {
        ProjectCommand::Create(args) => {
            Invocation::mutation(Method::Post, "/api/v1/projects", args)?
        }
        ProjectCommand::List => Invocation::get("/api/v1/projects"),
        ProjectCommand::Show(args) => Invocation::get(id_route("/api/v1/projects", &args.id)?),
        ProjectCommand::AddSource(args) => {
            Invocation::mutation(Method::Post, "/api/v1/projects/sources", args)?
        }
        ProjectCommand::AddLocation(args) => {
            Invocation::mutation(Method::Post, "project.add_location", args)?.node()
        }
        ProjectCommand::Update(args) => {
            Invocation::mutation(Method::Patch, "/api/v1/projects", args)?
        }
    })
}

fn session(command: SessionCommand) -> Result<Invocation, CliError> {
    Ok(match command {
        SessionCommand::Create(args) => {
            Invocation::mutation(Method::Post, "/api/v1/sessions", args)?
        }
        SessionCommand::List => Invocation::get("/api/v1/sessions"),
        SessionCommand::Show(args) => Invocation::get(id_route("/api/v1/sessions", &args.id)?),
        SessionCommand::Accept(args) => {
            Invocation::mutation(Method::Post, "/api/v1/sessions/accept", args)?
        }
    })
}

fn board(command: BoardCommand) -> Result<Invocation, CliError> {
    Ok(match command {
        BoardCommand::Post(args) => {
            Invocation::mutation(Method::Post, "/api/v1/board/messages", args)?
        }
        BoardCommand::Read(args) => Invocation::get(id_route("/api/v1/board/messages", &args.id)?),
        BoardCommand::Search(input) => {
            Invocation::input(Method::Get, "/api/v1/board/search", input)
        }
        BoardCommand::Edit(args) => {
            Invocation::mutation(Method::Patch, "/api/v1/board/messages", args)?
        }
    })
}

fn agent(command: AgentCommand) -> Result<Invocation, CliError> {
    Ok(match command {
        AgentCommand::Add(args) => Invocation::mutation(Method::Post, "/api/v1/agents", args)?,
        AgentCommand::List => Invocation::get("/api/v1/agents"),
        AgentCommand::Show(args) => Invocation::get(id_route("/api/v1/agents", &args.id)?),
        AgentCommand::Remove(args) => Invocation::mutation(Method::Delete, "/api/v1/agents", args)?,
        AgentCommand::Probe(args) => {
            Invocation::mutation(Method::Post, "agent.probe", args)?.node()
        }
    })
}

fn assignment(command: AssignmentCommand) -> Result<Invocation, CliError> {
    Ok(match command {
        AssignmentCommand::Create(args) => {
            Invocation::mutation(Method::Post, "/api/v1/assignments", args)?
        }
        AssignmentCommand::Show(args) => {
            Invocation::get(id_route("/api/v1/assignments", &args.id)?)
        }
        AssignmentCommand::Cancel(args) => {
            Invocation::mutation(Method::Post, "/api/v1/assignments/cancel", args)?
        }
        AssignmentCommand::Input(args) => {
            Invocation::mutation(Method::Post, "/api/v1/assignments/input", args)?
        }
        AssignmentCommand::Steer(args) => {
            Invocation::mutation(Method::Post, "/api/v1/assignments/steer", args)?
        }
    })
}

fn run(command: RunCommand) -> Result<Invocation, CliError> {
    Ok(match command {
        RunCommand::List => Invocation::get("/api/v1/runs"),
        RunCommand::Show(args) => Invocation::get(id_route("/api/v1/runs", &args.id)?),
        RunCommand::Follow(args) => {
            Invocation::get(format!("/api/v1/runs/{}/events", safe_id(&args.id)?))
        }
        RunCommand::Pause(args) => Invocation::mutation(Method::Post, "/api/v1/runs/pause", args)?,
        RunCommand::Resume(args) => {
            Invocation::mutation(Method::Post, "/api/v1/runs/resume", args)?
        }
        RunCommand::Cancel(args) => {
            Invocation::mutation(Method::Post, "/api/v1/runs/cancel", args)?
        }
        RunCommand::Recover(args) => {
            Invocation::mutation(Method::Post, "/api/v1/runs/recover", args)?
        }
    })
}

fn quick(command: QuickCommand) -> Result<Invocation, CliError> {
    Ok(match command {
        QuickCommand::Command(args) => {
            Invocation::mutation(Method::Post, "/api/v1/quick/command", args)?
        }
        QuickCommand::Agent(args) => {
            Invocation::mutation(Method::Post, "/api/v1/quick/agent", args)?
        }
        QuickCommand::Vm(args) => Invocation::mutation(Method::Post, "/api/v1/quick/vm", args)?,
    })
}

fn runtime(command: RuntimeCommand) -> Result<Invocation, CliError> {
    Ok(match command {
        RuntimeCommand::List => Invocation::get("runtime.list").node(),
        RuntimeCommand::Show(args) => {
            Invocation::get(format!("runtime.show/{}", safe_id(&args.id)?)).node()
        }
        RuntimeCommand::Start(args) => {
            Invocation::mutation(Method::Post, "runtime.start", args)?.node()
        }
        RuntimeCommand::Stop(args) => {
            Invocation::mutation(Method::Post, "runtime.stop", args)?.node()
        }
        RuntimeCommand::Pause(args) => {
            Invocation::mutation(Method::Post, "runtime.pause", args)?.node()
        }
        RuntimeCommand::Resume(args) => {
            Invocation::mutation(Method::Post, "runtime.resume", args)?.node()
        }
        RuntimeCommand::Snapshot(args) => {
            Invocation::mutation(Method::Post, "runtime.snapshot", args)?.node()
        }
        RuntimeCommand::Archive(args) => {
            Invocation::mutation(Method::Post, "runtime.archive", args)?.node()
        }
        RuntimeCommand::Restore(args) => {
            Invocation::mutation(Method::Post, "runtime.restore", args)?.node()
        }
        RuntimeCommand::Destroy(args) => {
            Invocation::mutation(Method::Delete, "runtime.destroy", args)?.node()
        }
    })
}

fn task(command: TaskCommand) -> Result<Invocation, CliError> {
    Ok(match command {
        TaskCommand::Create(args) => Invocation::mutation(Method::Post, "/api/v1/tasks", args)?,
        TaskCommand::List => Invocation::get("/api/v1/tasks"),
        TaskCommand::Show(args) => Invocation::get(id_route("/api/v1/tasks", &args.id)?),
        TaskCommand::Update(args) => Invocation::mutation(Method::Patch, "/api/v1/tasks", args)?,
        TaskCommand::Link(args) => Invocation::mutation(Method::Post, "/api/v1/tasks/link", args)?,
    })
}

fn logs(command: LogsCommand) -> Result<Invocation, CliError> {
    Ok(match command {
        LogsCommand::Search(input) => Invocation::input(Method::Get, "logs.search", input).node(),
        LogsCommand::Show(args) => {
            Invocation::get(format!("logs.show/{}", safe_id(&args.id)?)).node()
        }
        LogsCommand::Export(args) => {
            Invocation::mutation(Method::Post, "logs.export", args)?.node()
        }
    })
}

fn eval(command: EvalCommand) -> Result<Invocation, CliError> {
    Ok(match command {
        EvalCommand::Start(args) => {
            Invocation::mutation(Method::Post, "/api/v1/evaluations", args)?
        }
        EvalCommand::Show(args) => Invocation::get(id_route("/api/v1/evaluations", &args.id)?),
        EvalCommand::Compare(input) => {
            Invocation::input(Method::Get, "/api/v1/evaluations/compare", input)
        }
    })
}

fn connector(command: ConnectorCommand) -> Result<Invocation, CliError> {
    Ok(match command {
        ConnectorCommand::Create(args) => {
            Invocation::mutation(Method::Post, "/api/v1/connectors", args)?
        }
        ConnectorCommand::List => Invocation::get("/api/v1/connectors"),
        ConnectorCommand::Show(args) => Invocation::get(id_route("/api/v1/connectors", &args.id)?),
        ConnectorCommand::Pause(args) => {
            Invocation::mutation(Method::Post, "/api/v1/connectors/pause", args)?
        }
        ConnectorCommand::Resume(args) => {
            Invocation::mutation(Method::Post, "/api/v1/connectors/resume", args)?
        }
        ConnectorCommand::Revoke(args) => {
            Invocation::mutation(Method::Delete, "/api/v1/connectors", args)?
        }
        ConnectorCommand::Policy(args) => {
            Invocation::mutation(Method::Patch, "/api/v1/connectors/policy", args)?
        }
    })
}

fn storage(command: StorageCommand) -> Result<Invocation, CliError> {
    Ok(match command {
        StorageCommand::List => Invocation::get("storage.list").node(),
        StorageCommand::Show(args) => {
            Invocation::get(format!("storage.show/{}", safe_id(&args.id)?)).node()
        }
        StorageCommand::Configure(args) => {
            Invocation::mutation(Method::Post, "storage.configure", args)?.node()
        }
        StorageCommand::Pin(args) => {
            Invocation::mutation(Method::Post, "storage.pin", args)?.node()
        }
        StorageCommand::Unpin(args) => {
            Invocation::mutation(Method::Post, "storage.unpin", args)?.node()
        }
        StorageCommand::Move(args) => {
            Invocation::mutation(Method::Post, "storage.move", args)?.node()
        }
        StorageCommand::Restore(args) => {
            Invocation::mutation(Method::Post, "storage.restore", args)?.node()
        }
    })
}

fn backup(command: BackupCommand) -> Result<Invocation, CliError> {
    Ok(match command {
        BackupCommand::Create(args) => {
            Invocation::mutation(Method::Post, "backup.create", args)?.node()
        }
        BackupCommand::Verify(args) => {
            Invocation::mutation(Method::Post, "backup.verify", args)?.node()
        }
        BackupCommand::Restore(args) => {
            Invocation::mutation(Method::Post, "backup.restore", args)?.node()
        }
    })
}

fn id_route(base: &str, id: &str) -> Result<String, CliError> {
    Ok(format!("{base}/{}", safe_id(id)?))
}

fn safe_id(value: &str) -> Result<&str, CliError> {
    validate_segment(value)?;
    Ok(value)
}

fn validate_segment(value: &str) -> Result<(), CliError> {
    if value.is_empty()
        || value.len() > 256
        || value == "."
        || value == ".."
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(CliError::Usage(
            "ID contains unsupported characters".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    #[test]
    fn command_tree_is_internally_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn required_non_visual_command_families_parse() {
        for args in [
            ["conduit", "device", "list"].as_slice(),
            ["conduit", "project", "create"].as_slice(),
            ["conduit", "session", "list"].as_slice(),
            ["conduit", "board", "search"].as_slice(),
            ["conduit", "agent", "list"].as_slice(),
            ["conduit", "assignment", "show", "asg_abcdefgh"].as_slice(),
            ["conduit", "run", "follow", "run_abcdefgh"].as_slice(),
            ["conduit", "quick", "command"].as_slice(),
            ["conduit", "runtime", "snapshot"].as_slice(),
            ["conduit", "task", "list"].as_slice(),
            ["conduit", "logs", "search"].as_slice(),
            ["conduit", "eval", "compare"].as_slice(),
            ["conduit", "connector", "list"].as_slice(),
            ["conduit", "storage", "list"].as_slice(),
            ["conduit", "backup", "verify"].as_slice(),
            ["conduit", "doctor"].as_slice(),
        ] {
            Cli::try_parse_from(args).unwrap_or_else(|error| panic!("{args:?}: {error}"));
        }
    }

    #[test]
    fn path_injection_is_rejected_before_transport() {
        assert!(safe_id("../secret").is_err());
        assert!(safe_id("run_abcdefgh").is_ok());
    }
}
