use conduit_domain::DeviceId;
use conduit_node::{
    Node,
    ipc::IpcServer,
    local::LocalServices,
    local_ipc::LocalIpcService,
    service::{NodeService, load_launch_profiles},
    startup::{open_store_with_pending_restore, prepare_data_root},
};
use conduit_node_store::{CredentialStore, DeviceIdentity};
use conduit_runtime::{
    ContainerBackend, ContainerProvider, IncusProvider, NativeProvider, ProcessSupervisor,
    RestrictedNativeProvider, RuntimeProvider,
};
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

struct Options {
    data: PathBuf,
    socket: PathBuf,
    launch_profiles: PathBuf,
    control_url: Option<String>,
    device_id: Option<String>,
}
fn main() {
    if let Err(e) = run() {
        eprintln!("conduit-node: {e}");
        std::process::exit(1)
    }
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1);
    let Some(command) = args.next() else {
        print_help();
        return Ok(());
    };
    if command == "--help" || command == "-h" {
        print_help();
        return Ok(());
    }
    if command != "serve" {
        return Err("expected `conduit-node serve`".into());
    }
    let mut data = None;
    let mut socket = None;
    let mut profiles = None;
    let mut control = None;
    let mut device = None;
    while let Some(a) = args.next() {
        match a.to_str() {
            Some("--data-dir") => data = args.next().map(PathBuf::from),
            Some("--socket") => socket = args.next().map(PathBuf::from),
            Some("--launch-profiles") => profiles = args.next().map(PathBuf::from),
            Some("--control-url") => control = args.next().and_then(|v| v.into_string().ok()),
            Some("--device-id") => device = args.next().and_then(|v| v.into_string().ok()),
            Some("--help") => {
                print_help();
                return Ok(());
            }
            _ => return Err("unknown or incomplete serve argument".into()),
        }
    }
    let opts = defaults(data, socket, profiles, control, device)?;
    serve(opts)
}
fn defaults(
    data: Option<PathBuf>,
    socket: Option<PathBuf>,
    profiles: Option<PathBuf>,
    control: Option<String>,
    device: Option<String>,
) -> Result<Options, Box<dyn std::error::Error>> {
    let data = data
        .unwrap_or_else(|| xdg("XDG_DATA_HOME", Some(("HOME", ".local/share"))).join("conduit"));
    let runtime = xdg("XDG_RUNTIME_DIR", None);
    if runtime.as_os_str().is_empty() && socket.is_none() {
        return Err("XDG_RUNTIME_DIR or --socket is required".into());
    }
    let socket = socket.unwrap_or_else(|| runtime.join("conduit/node.sock"));
    let config = xdg("XDG_CONFIG_HOME", Some(("HOME", ".config")));
    let launch_profiles = profiles.unwrap_or_else(|| config.join("conduit/launch-profiles.json"));
    let control_url = control.or_else(|| std::env::var("CONDUIT_CONTROL_URL").ok());
    let device_id = device.or_else(|| std::env::var("CONDUIT_DEVICE_ID").ok());
    if control_url.is_some() != device_id.is_some() {
        return Err("control URL and Device ID must be configured together".into());
    }
    Ok(Options {
        data,
        socket,
        launch_profiles,
        control_url,
        device_id,
    })
}
fn xdg(primary: &str, fallback: Option<(&str, &str)>) -> PathBuf {
    std::env::var_os(primary)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            fallback.and_then(|(base, suffix)| {
                std::env::var_os(base).map(|v| PathBuf::from(v).join(suffix))
            })
        })
        .unwrap_or_default()
}
fn serve(opts: Options) -> Result<(), Box<dyn std::error::Error>> {
    let data_root = prepare_data_root(&opts.data)?;
    let identity = Arc::new(DeviceIdentity::load_or_create(
        data_root.join("identity/device.ed25519"),
    )?);
    let store = open_store_with_pending_restore(&data_root, &identity)?;
    let cursor_key: [u8; 32] =
        Sha256::digest(identity.sign(b"conduit.trace.cursor.v1").as_bytes()).into();
    let local = Arc::new(LocalServices::open(
        data_root.join("local-services"),
        cursor_key,
    )?);
    if let Some(device_id) = opts.device_id.as_ref() {
        local.bind_device(DeviceId::parse(device_id.clone())?)?;
    }
    let _credentials = CredentialStore::open(
        store.clone(),
        data_root.join("credentials/master.dek"),
        data_root.join("credentials/projections"),
    )?;
    let supervisor = ProcessSupervisor::open(data_root.join("supervisor"))?;
    let native: Arc<dyn RuntimeProvider> = Arc::new(NativeProvider::new(supervisor.clone()));
    let restricted: Arc<dyn RuntimeProvider> = Arc::new(RestrictedNativeProvider::new(
        supervisor.clone(),
        true,
        false,
    ));
    let docker: Arc<dyn RuntimeProvider> = Arc::new(ContainerProvider::with_state_root(
        ContainerBackend::Docker,
        data_root.join("runtime/docker"),
    )?);
    let podman: Arc<dyn RuntimeProvider> = Arc::new(ContainerProvider::with_state_root(
        ContainerBackend::Podman,
        data_root.join("runtime/podman"),
    )?);
    let incus: Arc<dyn RuntimeProvider> = Arc::new(IncusProvider::with_state_root(
        "conduit",
        data_root.join("runtime/incus"),
    )?);
    let providers = vec![native, restricted, docker, podman, incus];
    let mut node = Node::new(store.clone());
    for p in &providers {
        node.register_provider(p.clone())
    }
    let node = Arc::new(node);
    if let (Some(url), Some(device_id)) = (opts.control_url, opts.device_id) {
        let config = load_launch_profiles(&opts.launch_profiles)?;
        let receipts = providers.iter().map(|p| p.probe().ok()).collect::<Vec<_>>();
        let capability_digest = hex::encode(Sha256::digest(serde_jcs::to_vec(&receipts)?));
        let boot = fs_text("/proc/sys/kernel/random/boot_id")
            .unwrap_or_else(|| format!("node-{}-{}", std::process::id(), capability_digest));
        let service = NodeService::new(
            node.clone(),
            identity.clone(),
            url,
            device_id,
            capability_digest,
            boot,
            config,
            local.clone(),
            supervisor.clone(),
        )?;
        std::thread::spawn(move || service.run_forever());
    }
    let server = IpcServer::bind(opts.socket)?;
    server.serve(Arc::new(LocalIpcService::new(
        providers,
        store.clone(),
        identity,
        node,
        local,
        data_root,
    )?))?;
    Ok(())
}
fn fs_text(path: impl AsRef<Path>) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty())
}
fn print_help() {
    println!(
        "usage: conduit-node serve [--data-dir PATH] [--socket PATH] [--launch-profiles PATH] [--control-url WSS_URL --device-id DEVICE_ID]"
    )
}
