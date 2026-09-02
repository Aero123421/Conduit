use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};
use serde_json::{Map, Value, json};

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
    Artifact {
        #[command(subcommand)]
        command: ArtifactCommand,
    },
    Storage {
        #[command(subcommand)]
        command: StorageCommand,
    },
    Backup {
        #[command(subcommand)]
        command: BackupCommand,
    },
    /// Inspect or prepare the separately installed, root-owned Full Device helper.
    Privileged {
        #[command(subcommand)]
        command: PrivilegedCommand,
    },
    Doctor,
}

#[derive(Debug, Subcommand)]
pub enum PrivilegedCommand {
    /// Report the installed helper's public state without enabling authority.
    Status,
    /// Create a disabled helper identity and root-owned policy for this Device user.
    Prepare(PrivilegedPrepareArgs),
    /// Run bounded, secret-free installation and capability diagnostics.
    Doctor,
    /// Emit the public signed registration bundle for Owner approval.
    RegistrationBundle,
}

#[derive(Debug, Args)]
pub struct PrivilegedPrepareArgs {
    #[arg(long)]
    pub device_id: String,
    #[arg(long)]
    pub public_origin: String,
    #[arg(long, value_name = "PATH")]
    pub node_public_key_file: PathBuf,
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

#[derive(Debug, Args, Clone)]
pub struct ArtifactUploadArgs {
    pub id: String,
    #[arg(long, value_name = "PATH")]
    pub file: PathBuf,
    #[arg(long, value_name = "LOWERCASE_SHA256")]
    pub sha256: String,
    #[arg(long, default_value = "application/octet-stream")]
    pub content_type: String,
    #[arg(long)]
    pub idempotency_key: Option<String>,
}

#[derive(Debug, Subcommand)]
pub enum AuthCommand {
    SetupOptions(InputArgs),
    SetupVerify(InputArgs),
    LoginOptions(InputArgs),
    Register(InputArgs),
    RegisterOptions(InputArgs),
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
    Input(MutationArgs),
    Steer(MutationArgs),
    Pause(MutationArgs),
    Resume(MutationArgs),
    Cancel(MutationArgs),
    Close(MutationArgs),
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
    Reauthorize(MutationArgs),
    Policy(MutationArgs),
}

#[derive(Debug, Subcommand)]
pub enum ArtifactCommand {
    Create(MutationArgs),
    List,
    Show(IdArgs),
    Upload(ArtifactUploadArgs),
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
    Put,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthRequirement {
    None,
    Bearer,
    OwnerBearer,
    BrowserSession,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InputDestination {
    Body,
    Query,
}

#[derive(Debug, Clone)]
pub(crate) struct JsonInput {
    pub inline: Option<String>,
    pub file: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub(crate) struct ArtifactUpload {
    pub file: PathBuf,
    pub sha256: String,
    pub content_type: String,
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
    pub input_destination: InputDestination,
    pub artifact_upload: Option<ArtifactUpload>,
    pub revision: Option<u64>,
    pub idempotency_key: Option<String>,
    pub effectful: bool,
    pub auth: AuthRequirement,
    pub mirror_idempotency_in_body: bool,
}

impl Invocation {
    fn get(route: impl Into<String>) -> Self {
        Self {
            target: Target::ControlPlane,
            method: Method::Get,
            route: route.into(),
            body: None,
            input: None,
            input_destination: InputDestination::Body,
            artifact_upload: None,
            revision: None,
            idempotency_key: None,
            effectful: false,
            auth: AuthRequirement::Bearer,
            mirror_idempotency_in_body: false,
        }
    }

    fn mutation(
        method: Method,
        route: impl Into<String>,
        args: MutationArgs,
    ) -> Result<Self, CliError> {
        if args.id.is_some() {
            return Err(CliError::Usage(
                "this canonical collection operation does not accept a positional target ID"
                    .to_owned(),
            ));
        }
        Ok(Self {
            target: Target::ControlPlane,
            method,
            route: route.into(),
            body: Some(Value::Object(Map::new())),
            input: Some(args.input.into()),
            input_destination: InputDestination::Body,
            artifact_upload: None,
            revision: args.revision,
            idempotency_key: args.idempotency_key,
            effectful: true,
            auth: AuthRequirement::Bearer,
            mirror_idempotency_in_body: false,
        })
    }

    fn input(method: Method, route: impl Into<String>, input: InputArgs) -> Self {
        Self {
            target: Target::ControlPlane,
            method,
            route: route.into(),
            body: None,
            input: Some(input.into()),
            input_destination: InputDestination::Body,
            artifact_upload: None,
            revision: None,
            idempotency_key: None,
            effectful: method != Method::Get,
            auth: AuthRequirement::Bearer,
            mirror_idempotency_in_body: false,
        }
    }

    fn node(mut self) -> Self {
        self.target = Target::Node;
        self
    }

    fn public(mut self) -> Self {
        self.auth = AuthRequirement::None;
        self
    }

    fn browser_session(mut self) -> Self {
        self.auth = AuthRequirement::BrowserSession;
        self
    }

    fn owner_bearer(mut self) -> Self {
        self.auth = AuthRequirement::OwnerBearer;
        self
    }

    fn query(mut self) -> Self {
        self.input_destination = InputDestination::Query;
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
            Self::Artifact { command } => artifact(command)?,
            Self::Storage { command } => storage(command)?,
            Self::Backup { command } => backup(command)?,
            Self::Privileged { .. } => {
                unreachable!("privileged commands are handled by the local helper dispatcher")
            }
            Self::Doctor => unreachable!("doctor is handled before routing"),
        };
        Ok(invocation)
    }
}

fn auth(command: AuthCommand) -> Result<Invocation, CliError> {
    Ok(match command {
        AuthCommand::SetupOptions(input) => {
            Invocation::input(Method::Post, "/api/v1/auth/setup/options", input).public()
        }
        AuthCommand::SetupVerify(input) => {
            Invocation::input(Method::Post, "/api/v1/auth/setup/verify", input).public()
        }
        AuthCommand::LoginOptions(input) => {
            Invocation::input(Method::Post, "/api/v1/auth/login/options", input).public()
        }
        AuthCommand::Register(input) => {
            Invocation::input(Method::Post, "/api/v1/auth/passkeys/verify", input).browser_session()
        }
        AuthCommand::RegisterOptions(input) => {
            Invocation::input(Method::Post, "/api/v1/auth/passkeys/options", input)
                .browser_session()
        }
        AuthCommand::Login(input) => {
            let mut invocation =
                Invocation::input(Method::Post, "/api/v1/auth/login/verify", input).public();
            invocation.body = Some(json!({ "issueCliToken": true }));
            invocation
        }
        AuthCommand::Logout(args) => {
            if args.id.is_some() || args.revision.is_some() {
                return Err(CliError::Usage(
                    "auth logout does not accept a target ID or revision".to_owned(),
                ));
            }
            Invocation::mutation(Method::Post, "/api/v1/auth/logout", args)?.owner_bearer()
        }
        AuthCommand::Status => Invocation::get("/api/v1/auth/status").owner_bearer(),
        AuthCommand::Recover(input) => {
            Invocation::input(Method::Post, "/api/v1/auth/recovery", input).public()
        }
        AuthCommand::RevokePasskey(args) => {
            item_mutation(Method::Post, "/api/v1/auth/passkeys", "/revoke", args)?.browser_session()
        }
    })
}

fn device(command: DeviceCommand) -> Result<Invocation, CliError> {
    Ok(match command {
        DeviceCommand::Enroll(args) => node_mutation(Method::Post, "device.enroll", args)?,
        DeviceCommand::List => Invocation::get("/api/v1/devices"),
        DeviceCommand::Show(args) => Invocation::get(id_route("/api/v1/devices", &args.id)?),
        DeviceCommand::Revoke(args) => {
            item_mutation(Method::Post, "/api/v1/devices", "/revoke", args)?.browser_session()
        }
        DeviceCommand::RotateKey(args) => node_mutation(Method::Post, "device.rotate_key", args)?,
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
            let (id, args) = take_optional_id(args)?;
            let mut invocation = Invocation::mutation(Method::Post, "/api/v1/sources", args)?;
            if let Some(project_id) = id {
                invocation.body = Some(json!({ "project_id": project_id }));
            }
            invocation
        }
        ProjectCommand::AddLocation(args) => {
            node_mutation(Method::Post, "project.add_location", args)?
        }
        ProjectCommand::Update(args) => item_mutation(Method::Patch, "/api/v1/projects", "", args)?,
    })
}

fn session(command: SessionCommand) -> Result<Invocation, CliError> {
    Ok(match command {
        SessionCommand::Create(args) => {
            Invocation::mutation(Method::Post, "/api/v1/sessions", args)?
        }
        SessionCommand::List => Invocation::get("/api/v1/sessions"),
        SessionCommand::Show(args) => Invocation::get(id_route("/api/v1/sessions", &args.id)?),
        SessionCommand::Accept(args) => item_mutation(Method::Patch, "/api/v1/sessions", "", args)?,
    })
}

fn board(command: BoardCommand) -> Result<Invocation, CliError> {
    Ok(match command {
        BoardCommand::Post(args) => Invocation::mutation(Method::Post, "/api/v1/messages", args)?,
        BoardCommand::Read(args) => Invocation::get(id_route("/api/v1/messages", &args.id)?),
        BoardCommand::Search(input) => {
            Invocation::input(Method::Get, "/api/v1/messages", input).query()
        }
        BoardCommand::Edit(args) => item_mutation(Method::Patch, "/api/v1/messages", "", args)?,
    })
}

fn agent(command: AgentCommand) -> Result<Invocation, CliError> {
    Ok(match command {
        AgentCommand::Add(args) => {
            Invocation::mutation(Method::Post, "/api/v1/project_agents", args)?
        }
        AgentCommand::List => Invocation::get("/api/v1/project_agents"),
        AgentCommand::Show(args) => Invocation::get(id_route("/api/v1/project_agents", &args.id)?),
        AgentCommand::Remove(args) => {
            let mut invocation = item_mutation(Method::Patch, "/api/v1/project_agents", "", args)?;
            invocation.body = Some(json!({ "status": "removed" }));
            invocation
        }
        AgentCommand::Probe(args) => node_mutation(Method::Post, "agent.probe", args)?,
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
            let mut invocation =
                item_mutation(Method::Post, "/api/v1/assignments", "/transitions", args)?;
            require_revision(&invocation, "assignment transition")?;
            invocation.body = Some(json!({
                "toState": "cancelled",
                "reasonCode": "owner_cli_cancel"
            }));
            invocation.owner_bearer()
        }
        AssignmentCommand::Input(args) => existing_target_control("assignments", "input", args)?,
        AssignmentCommand::Steer(args) => existing_target_control("assignments", "steer", args)?,
    })
}

fn run(command: RunCommand) -> Result<Invocation, CliError> {
    Ok(match command {
        RunCommand::List => Invocation::get("/api/v1/runs"),
        RunCommand::Show(args) => Invocation::get(id_route("/api/v1/runs", &args.id)?),
        RunCommand::Follow(args) => {
            Invocation::get(format!("/api/v1/runs/{}/events", safe_id(&args.id)?))
        }
        RunCommand::Input(args) => existing_target_control("runs", "input", args)?,
        RunCommand::Steer(args) => existing_target_control("runs", "steer", args)?,
        RunCommand::Pause(args) => existing_target_control("runs", "pause", args)?,
        RunCommand::Resume(args) => existing_target_control("runs", "resume", args)?,
        RunCommand::Cancel(args) => existing_target_control("runs", "cancel", args)?,
        RunCommand::Close(args) => existing_target_control("runs", "close", args)?,
        RunCommand::Recover(_) => {
            return Err(CliError::Usage(
                "run recovery requires an explicit runtime restore target".to_owned(),
            ));
        }
    })
}

fn quick(command: QuickCommand) -> Result<Invocation, CliError> {
    Ok(match command {
        QuickCommand::Command(args) => operation("command.start", args, OperationBinding::None)?,
        QuickCommand::Agent(args) => operation("agent.run.start", args, OperationBinding::None)?,
        QuickCommand::Vm(args) => operation("runtime.create", args, OperationBinding::None)?,
    })
}

fn runtime(command: RuntimeCommand) -> Result<Invocation, CliError> {
    Ok(match command {
        RuntimeCommand::List => Invocation::get("runtime.list").node(),
        RuntimeCommand::Show(args) => {
            Invocation::get(format!("runtime.show/{}", safe_id(&args.id)?)).node()
        }
        RuntimeCommand::Start(args) => {
            operation("runtime.create", args, OperationBinding::OptionalRun)?
        }
        RuntimeCommand::Stop(args) => existing_target_control("runtimes", "stop", args)?,
        RuntimeCommand::Pause(args) => existing_target_control("runtimes", "pause", args)?,
        RuntimeCommand::Resume(args) => existing_target_control("runtimes", "resume", args)?,
        RuntimeCommand::Snapshot(args) => existing_target_control("runtimes", "snapshot", args)?,
        RuntimeCommand::Archive(_) => {
            return Err(CliError::Usage(
                "runtime archive is not an existing-target control; use snapshot".to_owned(),
            ));
        }
        RuntimeCommand::Restore(args) => existing_target_control("runtimes", "restore", args)?,
        RuntimeCommand::Destroy(args) => existing_target_control("runtimes", "destroy", args)?,
    })
}

fn task(command: TaskCommand) -> Result<Invocation, CliError> {
    Ok(match command {
        TaskCommand::Create(args) => Invocation::mutation(Method::Post, "/api/v1/tasks", args)?,
        TaskCommand::List => Invocation::get("/api/v1/tasks"),
        TaskCommand::Show(args) => Invocation::get(id_route("/api/v1/tasks", &args.id)?),
        TaskCommand::Update(args) => item_mutation(Method::Patch, "/api/v1/tasks", "", args)?,
        TaskCommand::Link(args) => {
            let invocation = item_mutation(Method::Post, "/api/v1/tasks", "/links", args)?;
            require_revision(&invocation, "task link")?;
            invocation
        }
    })
}

fn logs(command: LogsCommand) -> Result<Invocation, CliError> {
    Ok(match command {
        LogsCommand::Search(input) => Invocation::input(Method::Get, "logs.search", input).node(),
        LogsCommand::Show(args) => {
            Invocation::get(format!("logs.show/{}", safe_id(&args.id)?)).node()
        }
        LogsCommand::Export(args) => node_mutation(Method::Post, "logs.export", args)?,
    })
}

fn eval(command: EvalCommand) -> Result<Invocation, CliError> {
    Ok(match command {
        EvalCommand::Start(args) => operation("evaluation.start", args, OperationBinding::None)?,
        EvalCommand::Show(args) => Invocation::get(id_route("/api/v1/evidence", &args.id)?),
        EvalCommand::Compare(input) => {
            Invocation::input(Method::Get, "/api/v1/evidence", input).query()
        }
    })
}

fn connector(command: ConnectorCommand) -> Result<Invocation, CliError> {
    Ok(match command {
        ConnectorCommand::Create(args) => {
            Invocation::mutation(Method::Post, "/api/v1/connector-policies", args)?
                .browser_session()
        }
        ConnectorCommand::List => Invocation::get("/api/v1/oauth/grants").browser_session(),
        ConnectorCommand::Show(args) => {
            Invocation::get(id_route("/api/v1/oauth/grants", &args.id)?).browser_session()
        }
        ConnectorCommand::Pause(args) => grant_action(args, "pause")?,
        ConnectorCommand::Resume(args) => grant_action(args, "resume")?,
        ConnectorCommand::Revoke(args) => grant_action(args, "revoke")?,
        ConnectorCommand::Reauthorize(args) => grant_action(args, "reauthorize")?,
        ConnectorCommand::Policy(args) => {
            let invocation = item_mutation(Method::Patch, "/api/v1/connector-policies", "", args)?
                .browser_session();
            require_revision(&invocation, "connector policy update")?;
            invocation
        }
    })
}

fn artifact(command: ArtifactCommand) -> Result<Invocation, CliError> {
    Ok(match command {
        ArtifactCommand::Create(args) => {
            Invocation::mutation(Method::Post, "/api/v1/artifacts", args)?
        }
        ArtifactCommand::List => Invocation::get("/api/v1/artifacts"),
        ArtifactCommand::Show(args) => Invocation::get(id_route("/api/v1/artifacts", &args.id)?),
        ArtifactCommand::Upload(args) => {
            validate_segment(&args.id)?;
            if args.sha256.len() != 64
                || !args
                    .sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            {
                return Err(CliError::Usage(
                    "artifact SHA-256 must be 64 lowercase hexadecimal characters".to_owned(),
                ));
            }
            if args.content_type.is_empty()
                || args.content_type.len() > 256
                || args.content_type.chars().any(char::is_control)
            {
                return Err(CliError::Usage(
                    "artifact content type is invalid".to_owned(),
                ));
            }
            Invocation {
                target: Target::ControlPlane,
                method: Method::Put,
                route: format!("/api/v1/artifacts/{}/content", args.id),
                body: None,
                input: None,
                input_destination: InputDestination::Body,
                artifact_upload: Some(ArtifactUpload {
                    file: args.file,
                    sha256: args.sha256,
                    content_type: args.content_type,
                }),
                revision: None,
                idempotency_key: args.idempotency_key,
                effectful: true,
                auth: AuthRequirement::Bearer,
                mirror_idempotency_in_body: false,
            }
        }
    })
}

fn storage(command: StorageCommand) -> Result<Invocation, CliError> {
    Ok(match command {
        StorageCommand::List => Invocation::get("storage.list").node(),
        StorageCommand::Show(args) => {
            Invocation::get(format!("storage.show/{}", safe_id(&args.id)?)).node()
        }
        StorageCommand::Configure(args) => node_mutation(Method::Post, "storage.configure", args)?,
        StorageCommand::Pin(args) => node_mutation(Method::Post, "storage.pin", args)?,
        StorageCommand::Unpin(args) => node_mutation(Method::Post, "storage.unpin", args)?,
        StorageCommand::Move(args) => node_mutation(Method::Post, "storage.move", args)?,
        StorageCommand::Restore(args) => node_mutation(Method::Post, "storage.restore", args)?,
    })
}

fn backup(command: BackupCommand) -> Result<Invocation, CliError> {
    Ok(match command {
        BackupCommand::Create(args) => node_mutation(Method::Post, "backup.create", args)?,
        BackupCommand::Verify(args) => node_mutation(Method::Post, "backup.verify", args)?,
        BackupCommand::Restore(args) => node_mutation(Method::Post, "backup.restore", args)?,
    })
}

#[derive(Debug, Clone, Copy)]
enum OperationBinding {
    None,
    OptionalRun,
}

fn node_mutation(
    method: Method,
    route: &str,
    mut args: MutationArgs,
) -> Result<Invocation, CliError> {
    let id = args.id.take();
    if let Some(id) = id.as_deref() {
        validate_segment(id)?;
    }
    let mut invocation = Invocation::mutation(method, route, args)?.node();
    if let Some(id) = id {
        invocation.body = Some(json!({ "targetId": id }));
    }
    Ok(invocation)
}

fn operation(
    capability: &str,
    mut args: MutationArgs,
    binding: OperationBinding,
) -> Result<Invocation, CliError> {
    if args.revision.is_some() {
        return Err(CliError::Usage(
            "--revision is not an operation If-Match; bind revisions in the typed operation payload"
                .to_owned(),
        ));
    }
    let id = args.id.take();
    if let Some(id) = id.as_deref() {
        validate_segment(id)?;
    }
    let mut protected = Map::from_iter([(
        "capability".to_owned(),
        Value::String(capability.to_owned()),
    )]);
    match binding {
        OperationBinding::None if id.is_some() => {
            return Err(CliError::Usage(
                "this quick operation does not accept a positional target ID".to_owned(),
            ));
        }
        OperationBinding::OptionalRun => {
            if let Some(id) = id {
                protected.insert("runId".to_owned(), Value::String(id));
            }
        }
        OperationBinding::None => {}
    }
    let mut invocation = Invocation::mutation(Method::Post, "/api/v1/operations", args)?;
    invocation.body = Some(Value::Object(protected));
    invocation.mirror_idempotency_in_body = true;
    Ok(invocation)
}

fn existing_target_control(
    collection: &str,
    command: &str,
    mut args: MutationArgs,
) -> Result<Invocation, CliError> {
    let target = required_id(args.id.take(), "control target")?;
    validate_segment(&target)?;
    let revision = args
        .revision
        .take()
        .ok_or_else(|| CliError::Usage("existing-target control requires --revision".to_owned()))?;
    let mut invocation = Invocation::mutation(
        Method::Post,
        format!("/api/v1/{collection}/{target}/controls"),
        args,
    )?;
    invocation.body = Some(json!({ "command": command, "expectedRevision": revision }));
    Ok(invocation)
}

fn grant_action(args: MutationArgs, action: &str) -> Result<Invocation, CliError> {
    Ok(item_mutation(
        Method::Post,
        "/api/v1/oauth/grants",
        &format!("/{action}"),
        args,
    )?
    .browser_session())
}

fn item_mutation(
    method: Method,
    base: &str,
    suffix: &str,
    mut args: MutationArgs,
) -> Result<Invocation, CliError> {
    let id = required_id(args.id.take(), "target")?;
    validate_segment(&id)?;
    let invocation = Invocation::mutation(method, format!("{base}/{id}{suffix}"), args)?;
    if method == Method::Patch {
        require_revision(&invocation, "resource update")?;
    }
    Ok(invocation)
}

fn take_optional_id(mut args: MutationArgs) -> Result<(Option<String>, MutationArgs), CliError> {
    let id = args.id.take();
    if let Some(id) = id.as_deref() {
        validate_segment(id)?;
    }
    Ok((id, args))
}

fn required_id(id: Option<String>, kind: &str) -> Result<String, CliError> {
    id.ok_or_else(|| CliError::Usage(format!("{kind} ID is required")))
}

fn require_revision(invocation: &Invocation, operation: &str) -> Result<(), CliError> {
    if invocation.revision.is_none() {
        return Err(CliError::Usage(format!(
            "{operation} requires --revision for an exact If-Match target"
        )));
    }
    Ok(())
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
    use clap::{CommandFactory, Parser};

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
            ["conduit", "privileged", "status"].as_slice(),
            ["conduit", "privileged", "doctor"].as_slice(),
            ["conduit", "privileged", "registration-bundle"].as_slice(),
            [
                "conduit",
                "privileged",
                "prepare",
                "--device-id",
                "dev_abcdefgh",
                "--public-origin",
                "https://control.example.test",
                "--node-public-key-file",
                "/tmp/node-public.key",
            ]
            .as_slice(),
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

    fn invocation(args: &[&str]) -> Invocation {
        Cli::try_parse_from(args)
            .unwrap()
            .command
            .into_invocation()
            .unwrap()
    }

    #[test]
    fn canonical_resource_routes_never_use_compatibility_aliases() {
        let cases = [
            (
                vec!["conduit", "board", "post"],
                Method::Post,
                "/api/v1/messages",
            ),
            (
                vec!["conduit", "project", "add-source", "prj_contract01"],
                Method::Post,
                "/api/v1/sources",
            ),
            (
                vec!["conduit", "agent", "list"],
                Method::Get,
                "/api/v1/project_agents",
            ),
            (
                vec!["conduit", "agent", "show", "pagent_contract01"],
                Method::Get,
                "/api/v1/project_agents/pagent_contract01",
            ),
            (
                vec!["conduit", "artifact", "list"],
                Method::Get,
                "/api/v1/artifacts",
            ),
        ];
        for (args, method, route) in cases {
            let invocation = invocation(&args);
            assert_eq!(invocation.method, method);
            assert_eq!(invocation.route, route);
            assert_eq!(invocation.auth, AuthRequirement::Bearer);
        }
        assert_eq!(
            invocation(&["conduit", "project", "add-source", "prj_contract01"]).body,
            Some(json!({ "project_id": "prj_contract01" }))
        );
    }

    #[test]
    fn item_mutations_bind_target_in_url_and_revision_in_if_match() {
        let assignment = invocation(&[
            "conduit",
            "assignment",
            "cancel",
            "asg_contract01",
            "--revision",
            "7",
        ]);
        assert_eq!(
            assignment.route,
            "/api/v1/assignments/asg_contract01/transitions"
        );
        assert_eq!(assignment.revision, Some(7));
        assert_eq!(assignment.auth, AuthRequirement::OwnerBearer);
        assert_eq!(
            assignment.body,
            Some(json!({
                "toState": "cancelled",
                "reasonCode": "owner_cli_cancel"
            }))
        );
        assert!(
            !assignment
                .body
                .as_ref()
                .unwrap()
                .as_object()
                .unwrap()
                .contains_key("targetId")
        );

        let policy = invocation(&[
            "conduit",
            "connector",
            "policy",
            "cpol_contract01",
            "--revision",
            "4",
        ]);
        assert_eq!(policy.route, "/api/v1/connector-policies/cpol_contract01");
        assert_eq!(policy.method, Method::Patch);
        assert_eq!(policy.revision, Some(4));
        assert_eq!(policy.auth, AuthRequirement::BrowserSession);
    }

    #[test]
    fn starts_and_existing_target_controls_use_separate_contracts() {
        let cases = [
            (vec!["conduit", "quick", "command"], "command.start"),
            (vec!["conduit", "quick", "agent"], "agent.run.start"),
            (vec!["conduit", "quick", "vm"], "runtime.create"),
        ];
        for (args, capability) in cases {
            let invocation = invocation(&args);
            assert_eq!(invocation.route, "/api/v1/operations");
            assert_eq!(invocation.method, Method::Post);
            assert!(invocation.mirror_idempotency_in_body);
            assert_eq!(invocation.body.as_ref().unwrap()["capability"], capability);
        }

        for (args, route, command) in [
            (
                vec![
                    "conduit",
                    "assignment",
                    "input",
                    "asg_contract01",
                    "--revision",
                    "2",
                ],
                "/api/v1/assignments/asg_contract01/controls",
                "input",
            ),
            (
                vec![
                    "conduit",
                    "run",
                    "pause",
                    "run_contract01",
                    "--revision",
                    "3",
                ],
                "/api/v1/runs/run_contract01/controls",
                "pause",
            ),
            (
                vec![
                    "conduit",
                    "runtime",
                    "destroy",
                    "rt_contract01",
                    "--revision",
                    "4",
                ],
                "/api/v1/runtimes/rt_contract01/controls",
                "destroy",
            ),
        ] {
            let invocation = invocation(&args);
            assert_eq!(invocation.route, route);
            assert!(!invocation.mirror_idempotency_in_body);
            assert_eq!(invocation.body.as_ref().unwrap()["command"], command);
            assert!(invocation.body.as_ref().unwrap()["expectedRevision"].is_number());
        }
    }

    #[test]
    fn oauth_grant_lifecycle_uses_item_action_routes_and_browser_auth() {
        for action in ["pause", "resume", "revoke", "reauthorize"] {
            let invocation = invocation(&["conduit", "connector", action, "grant_contract01"]);
            assert_eq!(
                invocation.route,
                format!("/api/v1/oauth/grants/grant_contract01/{action}")
            );
            assert_eq!(invocation.auth, AuthRequirement::BrowserSession);
        }
    }

    #[test]
    fn owner_cli_login_requests_a_bounded_owner_bearer() {
        let login = invocation(&["conduit", "auth", "login"]);
        assert_eq!(login.route, "/api/v1/auth/login/verify");
        assert_eq!(login.auth, AuthRequirement::None);
        assert_eq!(login.body, Some(json!({ "issueCliToken": true })));
        assert_eq!(
            invocation(&["conduit", "project", "list"]).auth,
            AuthRequirement::Bearer
        );
    }

    #[test]
    fn complete_non_visual_commands_use_canonical_routes() {
        let status = invocation(&["conduit", "auth", "status"]);
        assert_eq!(status.route, "/api/v1/auth/status");
        assert_eq!(status.auth, AuthRequirement::OwnerBearer);

        let logout = invocation(&["conduit", "auth", "logout"]);
        assert_eq!(logout.route, "/api/v1/auth/logout");
        assert_eq!(logout.auth, AuthRequirement::OwnerBearer);

        let link = invocation(&[
            "conduit",
            "task",
            "link",
            "task_contract01",
            "--revision",
            "3",
        ]);
        assert_eq!(link.route, "/api/v1/tasks/task_contract01/links");
        assert_eq!(link.revision, Some(3));

        let evaluation = invocation(&["conduit", "eval", "start"]);
        assert_eq!(evaluation.route, "/api/v1/operations");
        assert_eq!(evaluation.body.unwrap()["capability"], "evaluation.start");

        let grants = invocation(&["conduit", "connector", "list"]);
        assert_eq!(grants.route, "/api/v1/oauth/grants");
        assert_eq!(grants.auth, AuthRequirement::BrowserSession);
        assert_eq!(
            invocation(&["conduit", "connector", "show", "grant_contract01"]).route,
            "/api/v1/oauth/grants/grant_contract01"
        );
    }

    #[test]
    fn local_node_target_binding_is_unchanged() {
        let invocation = invocation(&["conduit", "storage", "pin", "store_contract01"]);
        assert_eq!(invocation.target, Target::Node);
        assert_eq!(invocation.route, "storage.pin");
        assert_eq!(
            invocation.body,
            Some(json!({ "targetId": "store_contract01" }))
        );
    }
}
