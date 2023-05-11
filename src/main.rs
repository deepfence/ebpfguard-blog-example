use anyhow::Context;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    let mut policy_manager = ebpfguard::PolicyManager::with_default_path()
        .context("kernel verifier rejected eBPF hooks object file")?;

    let mut socket_bind: ebpfguard::hooks::socket_bind::SocketBind = policy_manager
        .attach_socket_bind()
        .context("couldn't attach socket_bind hook")?;

    let mut rx: tokio::sync::mpsc::Receiver<ebpfguard::alerts::SocketBind> = socket_bind
        .alerts()
        .await
        .context("couldn't get alerts channel for bind events")?;

    let policy = ebpfguard::policy::SocketBind {
        subject: ebpfguard::policy::PolicySubject::All,
        allow: ebpfguard::policy::Ports::All,
        deny: ebpfguard::policy::Ports::Ports(vec![22]),
    };

    socket_bind
        .add_policy(policy)
        .await
        .context("failed to add policy")?;

    if let Some(alert) = rx.recv().await {
        log::info!(
            "socket_bind: pid={} subject={} port={}",
            alert.pid,
            alert.subject,
            alert.port,
        );
    }

    Ok(())
}
