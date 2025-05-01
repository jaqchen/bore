//! Server implementation for the `bore` service.

use std::net::{IpAddr, Ipv4Addr};
use std::{io, ops::RangeInclusive, sync::Arc, time::Duration};
use std::collections::HashMap;

use anyhow::Result;
use dashmap::DashMap;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, timeout};
use tokio::sync::Mutex;
use tracing::{info, info_span, warn, Instrument};
use uuid::Uuid;

use crate::auth::Authenticator;
use crate::shared::{proxy, ClientMessage, Delimited, ServerMessage, CONTROL_PORT,
    BORE_KEEPINTERVAL, tcp_keepalive, parse_envvar_u64,
};

/// Client information structure
struct ClientInfo {
    /// Port number previously used for the `hostid.
    port_no: u16,

    /// Whether the client is online.
    online: bool,

    /// UTC epoch time when the client connects or disconnects.
    last_dance: u64,

    /// Number of times the client disconnects.
    num_discon: u64,
}

/// State structure for the server.
pub struct Server {
    /// Range of TCP ports that can be forwarded.
    port_range: RangeInclusive<u16>,

    /// Optional secret used to authenticate clients.
    auth: Option<Authenticator>,

    /// Concurrent map of IDs to incoming connections.
    conns: Arc<DashMap<Uuid, TcpStream>>,

    /// IP address where the control server will bind to.
    bind_addr: IpAddr,

    /// IP address where tunnels will listen on.
    bind_tunnels: IpAddr,

    /// HashMap-ped client information
    clients: Arc<Mutex<HashMap<String, ClientInfo>>>,
}

impl ClientInfo {
    fn new(pno: u16, online: bool) -> Self {
        ClientInfo {
            port_no: pno,
            online,
            last_dance: ClientInfo::dance_utc(),
            num_discon: 0u64,
        }
    }

    fn dance_utc() -> u64 {
        match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            Ok(utc) => utc.as_secs(),
            Err(_) => 0u64,
        }
    }

    /// This is an rudimentary implementation. When `bore server is handling
    /// an enormous number of remote clients, leaking clients information
    /// with this simple function is not recommended, as it might incur serious
    /// performance penalty due to holding the hashmap `Mutex for quite a long time.
    async fn leak_clients_info(mut tcp: TcpStream, clients: Arc<Mutex<HashMap<String, ClientInfo>>>) -> usize {
        let mut cnum: usize = 0;
        let ctable = clients.lock().await;
        for (hostid, cinfo) in ctable.iter() {
            let oneline = format!("client[{}] => hostid: {}, online: {}, portno: {}, last_dance: {}, discon: {}\n",
                cnum, hostid, cinfo.online, cinfo.port_no, cinfo.last_dance, cinfo.num_discon);
            if let Err(err) = tcp.write(oneline.as_bytes()).await {
                warn!(%err, "Failed to leak clients information");
                break;
            }
            cnum += 1;
        }
        // drop the mutex lock explicitly
        drop(ctable);
        cnum
    }
}

impl Server {
    /// Create a new server with a specified minimum port number.
    pub fn new(port_range: RangeInclusive<u16>, secret: Option<&str>) -> Self {
        assert!(!port_range.is_empty(), "must provide at least one port");
        Server {
            port_range,
            conns: Arc::new(DashMap::new()),
            auth: secret.map(Authenticator::new),
            bind_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            bind_tunnels: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            clients: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Set the IP address where tunnels will listen on.
    pub fn set_bind_addr(&mut self, bind_addr: IpAddr) {
        self.bind_addr = bind_addr;
    }

    /// Set the IP address where the control server will bind to.
    pub fn set_bind_tunnels(&mut self, bind_tunnels: IpAddr) {
        self.bind_tunnels = bind_tunnels;
    }

    /// Start the server, listening for new connections.
    pub async fn listen(self) -> Result<()> {
        let this = Arc::new(self);
        let listener = TcpListener::bind((this.bind_addr, CONTROL_PORT)).await?;
        info!(addr = ?this.bind_addr, "server listening");

        // Create a listening socket for the query of existing clients.
        let insider = TcpListener::bind("127.0.0.1:10088").await?;

        // TCP connection keep-alive interval.
        let kval = parse_envvar_u64(BORE_KEEPINTERVAL, 55);

        // Heartbeat interval in seconds. For large number of devices,
        // the frequency of heartbeat from server should be decreased.
        let hbeat = parse_envvar_u64("BORE_HEARTBEAT_INTERVAL", 180);
        let hbeat = if hbeat < 15 { 15u64 } else { hbeat };

        loop {
            tokio::select! {
                Ok((stream, addr)) = listener.accept() => {
                    let this = Arc::clone(&this);
                    tokio::spawn(async move {
                        info!("incoming connection");
                        if let Err(err) = this.handle_connection(stream, kval, hbeat).await {
                            warn!(%err, "connection exited with error");
                        } else {
                            info!("connection exited");
                        }
                    }
                    .instrument(info_span!("control", ?addr)),
                    );
                },
                Ok((spy, addr)) = insider.accept() => {
                    info!(%addr, "clients information leakage");
                    let clients = Arc::clone(&this.clients);
                    tokio::spawn(async move {
                        let _ = ClientInfo::leak_clients_info(spy, clients).await;
                    });
                },
            }
        }
    }

    async fn create_listener(&self, port: u16) -> Result<TcpListener, &'static str> {
        let try_bind = |port: u16| async move {
            TcpListener::bind((self.bind_tunnels, port))
                .await
                .map_err(|err| match err.kind() {
                    io::ErrorKind::AddrInUse => "port already in use",
                    io::ErrorKind::PermissionDenied => "permission denied",
                    _ => "failed to bind to port",
                })
        };
        if port > 0 {
            // Client requests a specific port number.
            if !self.port_range.contains(&port) {
                return Err("client port number not in allowed range");
            }
            try_bind(port).await
        } else {
            // Client requests any available port in range.
            //
            // In this case, we bind to 150 random port numbers. We choose this value because in
            // order to find a free port with probability at least 1-δ, when ε proportion of the
            // ports are currently available, it suffices to check approximately -2 ln(δ) / ε
            // independently and uniformly chosen ports (up to a second-order term in ε).
            //
            // Checking 150 times gives us 99.999% success at utilizing 85% of ports under these
            // conditions, when ε=0.15 and δ=0.00001.
            for _ in 0..150 {
                let port = fastrand::u16(self.port_range.clone());
                match try_bind(port).await {
                    Ok(listener) => return Ok(listener),
                    Err(_) => continue,
                }
            }
            Err("failed to find an available port")
        }
    }

    async fn find_client_port(&self, hostid: &str) -> u16 {
        if hostid.is_empty() {
            return 0;
        }
        // Lock client hashmap table:
        let ctable = self.clients.lock().await;
        if let Some(client) = ctable.get(hostid) { client.port_no } else { 0u16 }
    }

    // insert the hostid into `self.clients hashmap
    async fn update_client_port(&self, hostid: &str, pno: u16, online: bool) {
        if hostid.is_empty() {
            return;
        }

        let hostid = hostid.to_string();
        // Lock client hashmap table:
        let mut ctable = self.clients.lock().await;
        if let Some(cli) = ctable.get_mut(&hostid) {
            // Do not update `port_no when a lingering task has figured
            // out that a previously established client has closed connection.
            if online || pno == cli.port_no {
                cli.port_no = pno;
                cli.online = online;
                cli.last_dance = ClientInfo::dance_utc();
            }
            if !online {
                cli.num_discon += 1;
            }
        } else {
            let newcli = ClientInfo::new(pno, online);
            ctable.insert(hostid, newcli);
        }
    }

    async fn handle_connection(&self, stream: TcpStream, keepival: u64, bhval: u64) -> Result<()> {
        let stream = tcp_keepalive(stream, 3, keepival);
        let mut stream = Delimited::new(stream);
        if let Some(auth) = &self.auth {
            if let Err(err) = auth.server_handshake(&mut stream).await {
                warn!(%err, "server handshake failed");
                stream.send(ServerMessage::Error(err.to_string())).await?;
                return Ok(());
            }
        }

        match stream.recv_timeout().await? {
            Some(ClientMessage::Authenticate(_)) => {
                warn!("unexpected authenticate");
                Ok(())
            }
            Some(ClientMessage::Hello(port, hostid)) => {
                // Try to reuse previously used port for specific `hostid
                let pno: u16 = if port != 0 { port } else { self.find_client_port(&hostid).await };
                let listener = match self.create_listener(pno).await {
                    Ok(listener) => listener,
                    Err(err) => {
                        // if previous listener uses port zero, just return an error to client.
                        if pno == 0 {
                            stream.send(ServerMessage::Error(err.into())).await?;
                            return Ok(());
                        }
                        // Try again with port number zero, as previously used port might be occupied:
                        match self.create_listener(0).await {
                            Ok(listener) => listener,
                            Err(err) => {
                                stream.send(ServerMessage::Error(err.into())).await?;
                                return Ok(());
                            }
                        }
                    }
                };
                let host = listener.local_addr()?.ip();
                let port = listener.local_addr()?.port();
                info!(?host, ?port, "new client");
                stream.send(ServerMessage::Hello(port, hostid.clone())).await?;
                self.update_client_port(&hostid, port, true).await;

                loop {
                    if stream.send(ServerMessage::Heartbeat).await.is_err() {
                        // Assume that the TCP connection has been dropped.
                        self.update_client_port(&hostid, port, false).await;
                        return Ok(());
                    }
                    // The timeout interval has been modified from 500 milliseconds, to
                    // at least 15 seconds, for the purpose of reducing server overhead,
                    // and reducing TCP/IP traffic for large number of IoT devices.
                    let timeo: Duration = Duration::from_secs(bhval);
                    if let Ok(result) = timeout(timeo, listener.accept()).await {
                        if let Err(err) = result {
                            self.update_client_port(&hostid, port, false).await;
                            warn!(%err, "failed to parse incomming proxy request.");
                            return Err(err.into());
                        }
                        let (stream2, addr) = result.unwrap();
                        let stream2 = tcp_keepalive(stream2, 3, keepival);
                        info!(?addr, ?port, "new connection");

                        let id = Uuid::new_v4();
                        let conns = Arc::clone(&self.conns);

                        conns.insert(id, stream2);
                        tokio::spawn(async move {
                            // Remove stale entries to avoid memory leaks.
                            sleep(Duration::from_secs(10)).await;
                            if conns.remove(&id).is_some() {
                                warn!(%id, "removed stale connection");
                            }
                        });
                        if let Err(err) = stream.send(ServerMessage::Connection(id)).await {
                            self.update_client_port(&hostid, port, false).await;
                            return Err(err);
                        }
                    }
                }
            }
            Some(ClientMessage::Accept(id)) => {
                info!(%id, "forwarding connection");
                match self.conns.remove(&id) {
                    Some((_, mut stream2)) => {
                        let parts = stream.into_parts();
                        debug_assert!(parts.write_buf.is_empty(), "framed write buffer not empty");
                        stream2.write_all(&parts.read_buf).await?;
                        proxy(parts.io, stream2).await?
                    }
                    None => warn!(%id, "missing connection"),
                }
                Ok(())
            }
            None => Ok(()),
        }
    }
}
