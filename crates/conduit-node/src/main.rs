use conduit_node::{
    Node,
    ipc::{IpcHandler, IpcRequest, IpcServer},
};
use conduit_node_store::{DeviceIdentity, NodeStore};
use conduit_runtime::{
    ContainerBackend, ContainerProvider, IncusProvider, NativeProvider, ProcessSupervisor,
    RestrictedNativeProvider, RuntimeProvider,
};
use serde_json::{Value, json};
use std::{path::PathBuf, sync::Arc};

struct ServiceHandler {
    providers: Vec<Arc<dyn RuntimeProvider>>,
    store: NodeStore,
    identity: Arc<DeviceIdentity>,
}
impl IpcHandler for ServiceHandler {
    fn handle(&self, r: &IpcRequest) -> Result<Value, String> {
        match r.method.as_str(){"health"=>{self.store.integrity_check().map_err(|e|e.to_string())?;Ok(json!({"status":"ready","keyId":self.identity.key_id(),"connectionEpoch":self.store.connection_epoch().map_err(|e|e.to_string())?.to_string()}))},"doctor"=>Ok(Value::Array(self.providers.iter().map(|p|p.probe().map(|v|serde_json::to_value(v).unwrap_or_else(|_|json!({"providerId":p.provider_id(),"error":"receipt_encoding_failed"}))).unwrap_or_else(|e|json!({"providerId":p.provider_id(),"capabilities":[],"error":e.to_string()}))).collect())),_=>Err("unknown IPC method".into())}
    }
}

fn main() {
    if let Err(e) = run() {
        eprintln!("conduit-node: {e}");
        std::process::exit(1)
    }
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1);
    let mut data = None;
    let mut socket = None;
    while let Some(a) = args.next() {
        match a.to_str() {
            Some("--data-dir") => data = args.next().map(PathBuf::from),
            Some("--socket") => socket = args.next().map(PathBuf::from),
            Some("--help") => {
                println!("usage: conduit-node --data-dir PATH --socket PATH");
                return Ok(());
            }
            _ => return Err("unknown or incomplete argument".into()),
        }
    }
    let data = data.ok_or("--data-dir is required")?;
    let socket = socket.unwrap_or_else(|| data.join("node.sock"));
    let store = NodeStore::open(&data)?;
    let identity = Arc::new(DeviceIdentity::load_or_create(
        data.join("identity/device.ed25519"),
    )?);
    let supervisor = ProcessSupervisor::open(data.join("supervisor"))?;
    let native: Arc<dyn RuntimeProvider> = Arc::new(NativeProvider::new(supervisor.clone()));
    let restricted: Arc<dyn RuntimeProvider> =
        Arc::new(RestrictedNativeProvider::new(supervisor, true, false));
    let docker: Arc<dyn RuntimeProvider> =
        Arc::new(ContainerProvider::new(ContainerBackend::Docker));
    let podman: Arc<dyn RuntimeProvider> =
        Arc::new(ContainerProvider::new(ContainerBackend::Podman));
    let incus: Arc<dyn RuntimeProvider> = Arc::new(IncusProvider::new("conduit")?);
    let providers = vec![native, restricted, docker, podman, incus];
    let mut node = Node::new(store.clone());
    for p in &providers {
        node.register_provider(p.clone())
    }
    drop(node);
    let server = IpcServer::bind(socket)?;
    server.serve(Arc::new(ServiceHandler {
        providers,
        store,
        identity,
    }))?;
    Ok(())
}
