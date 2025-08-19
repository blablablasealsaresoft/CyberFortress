mod modules;
use axum::{routing::{get, post}, Router, Json, extract::{Path, State}, response::IntoResponse};
use axum::extract::ws::{WebSocketUpgrade, Message, WebSocket};
use axum::response::Response;
use serde::{Serialize, Deserialize};
use std::{net::SocketAddr, sync::Arc, process::Command, collections::HashMap};
use parking_lot::RwLock;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use tokio::sync::{oneshot, mpsc};
use tokio::time::{sleep, Duration};
use axum::middleware::{from_fn, Next};
use axum::http::{Request, StatusCode};
use axum::body::Body;
use futures_util::{StreamExt, SinkExt};
use std::fs::OpenOptions;
use std::io::Write as IoWrite;

#[derive(Clone, Default)]
struct MessagingState {
	sessions: Arc<RwLock<HashMap<String, mpsc::UnboundedSender<Message>>>>,
	public_keys: Arc<RwLock<HashMap<String, String>>>,
	pending: Arc<RwLock<HashMap<String, Vec<serde_json::Value>>>>,
}

#[derive(Clone, Default)]
struct UserRecord { id: String, email: String, password_hash: String, mfa_secret_b32: Option<String>, roles: Vec<String>, api_keys: Vec<String> }
#[derive(Clone, Default)]
struct IamState { users: Arc<RwLock<HashMap<String, UserRecord>>>, email_to_id: Arc<RwLock<HashMap<String, String>>> }

#[derive(Clone, Default)]
struct AppState {
	threats: Arc<RwLock<Vec<Threat>>>,
	monitor_ctrl: Arc<RwLock<Option<oneshot::Sender<()>>>>,
	messaging: MessagingState,
	playbooks: Arc<RwLock<HashMap<String, modules::Playbook>>>,
	iam: IamState,
}

#[derive(Serialize, Deserialize, Clone)]
struct Threat { id: String, ip_address: String, threat_score: i32, threat_level: String }

#[tokio::main]
async fn main() {
	tracing_subscriber::registry()
		.with(tracing_subscriber::EnvFilter::new("info"))
		.with(tracing_subscriber::fmt::layer())
		.init();

	let state = AppState::default();
	let app = Router::new()
		// IAM
		.route("/api/auth/register", post(auth_register))
		.route("/api/auth/login", post(auth_login))
		.route("/api/auth/enable-mfa", post(auth_enable_mfa))
		.route("/api/auth/verify-mfa", post(auth_verify_mfa))
		.route("/api/auth/refresh", post(auth_refresh))
		.route("/api/auth/me", get(auth_me))
		.route("/api/auth/assign-role", post(auth_assign_role))
		.route("/api/auth/api-key", post(auth_create_api_key))
		// Protected action execution
		.route("/api/action", post(exec_action).route_layer(from_fn(jwt_auth)))
		// Threat monitoring + DB
		.route("/api/threats", get(list_threats).post(report_threat))
		.route("/api/threats/:id", get(get_threat))
		.route("/api/monitoring/status", get(monitoring_status))
		.route("/api/monitoring/mode", post(set_mode))
		.route("/api/monitoring/start", post(start_monitoring))
		.route("/api/monitoring/stop", post(stop_monitoring))
		// Identity
		.route("/api/identity/scan", post(identity_scan))
		.route("/api/identity/databrokers/plan", post(identity_broker_plan))
		// OSINT
		.route("/api/osint/case", post(osint_case))
		.route("/api/osint/link-analysis", post(osint_link))
		// Crypto / PQC
		.route("/api/crypto/encrypt", post(crypto_encrypt))
		.route("/api/crypto/decrypt", post(crypto_decrypt))
		// Score
		.route("/api/score", get(get_score))
		// Secure storage and messaging
		.route("/api/storage/upload", post(storage_upload))
		.route("/api/storage/download/:id", get(storage_download))
		.route("/api/storage/list", get(storage_list))
		.route("/ws/secure", get(ws_secure))
		// SOAR playbooks
		.route("/api/soar/playbooks/load", post(soar_load))
		.route("/api/soar/playbooks", get(soar_list))
		.route("/api/soar/execute", post(soar_execute))
		.with_state(state.clone());

	let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
	tracing::info!("listening on {}", addr);
	let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
	axum::serve(listener, app).await.unwrap();
}

async fn list_threats(state: axum::extract::State<AppState>) -> Json<Vec<Threat>> {
	Json(state.threats.read().clone())
}

#[derive(Deserialize)]
struct NewThreat { ip_address: String, threat_score: i32 }

async fn report_threat(state: axum::extract::State<AppState>, Json(payload): Json<NewThreat>) -> Json<Threat> {
	let t = Threat { id: uuid(), ip_address: payload.ip_address, threat_score: payload.threat_score, threat_level: level(payload.threat_score) };
	state.threats.write().push(t.clone());
	Json(t)
}

#[axum::debug_handler]
async fn get_threat(Path(id): Path<String>, State(state): State<AppState>) -> Result<Json<Threat>, StatusCode> {
	if let Some(t) = state.threats.read().iter().find(|t| t.id == id).cloned() { Ok(Json(t)) } else { Err(StatusCode::NOT_FOUND) }
}

async fn monitoring_status(State(_state): State<AppState>) -> Json<serde_json::Value> {
	Json(serde_json::json!({ "mode": "ENTERPRISE" }))
}

#[derive(Deserialize)]
struct ModeReq { mode: String }
async fn set_mode(Json(_req): Json<ModeReq>) -> Json<serde_json::Value> { Json(serde_json::json!({"ok":true})) }

#[derive(Deserialize)]
struct IdentityReq { email: Option<String>, phone: Option<String>, name: Option<String> }
async fn identity_scan(Json(req): Json<IdentityReq>) -> Json<serde_json::Value> {
	Json(serde_json::json!({
		"exposure": {"email_provided": req.email.is_some(), "phone_provided": req.phone.is_some()},
		"recommendations": ["Enable 2FA","Freeze credit","Remove from data brokers"]
	}))
}
async fn identity_broker_plan() -> Json<serde_json::Value> { Json(serde_json::json!({"plan": modules::generate_broker_plan()})) }

#[derive(Deserialize, Serialize)]
struct OsintReq { target_ip: Option<String>, email: Option<String>, username: Option<String> }
async fn osint_case(Json(req): Json<OsintReq>) -> Json<serde_json::Value> { let c = modules::build_case(serde_json::to_value(&req).unwrap()); Json(serde_json::json!(c)) }
async fn osint_link(Json(_req): Json<OsintReq>) -> Json<serde_json::Value> { Json(serde_json::json!({"nodes":[],"edges":[]})) }

#[derive(Deserialize)]
struct CryptoReq { data: String, passphrase: String }
async fn crypto_encrypt(Json(req): Json<CryptoReq>) -> Json<serde_json::Value> { let ct = modules::aes_encrypt(req.data.as_bytes(), req.passphrase.as_bytes()).unwrap(); Json(serde_json::json!({"cipher": base64::encode(ct)})) }
async fn crypto_decrypt(Json(req): Json<CryptoReq>) -> Json<serde_json::Value> { let bytes = base64::decode(req.data).unwrap_or_default(); let pt = modules::aes_decrypt(&bytes, req.passphrase.as_bytes()).unwrap_or_default(); Json(serde_json::json!({"plain": String::from_utf8_lossy(&pt)})) }

async fn get_score() -> Json<serde_json::Value> { Json(serde_json::json!({"score": 720})) }

async fn start_monitoring(State(state): State<AppState>) -> Json<serde_json::Value> {
	let (tx, rx) = oneshot::channel();
	*state.monitor_ctrl.write() = Some(tx);
	let state_clone = state.clone();
	tokio::spawn(async move {
		monitor_loop(state_clone, rx).await;
	});
	Json(serde_json::json!({"started":true}))
}

async fn stop_monitoring(state: axum::extract::State<AppState>) -> Json<serde_json::Value> {
	if let Some(tx) = state.monitor_ctrl.write().take() { let _ = tx.send(()); }
	Json(serde_json::json!({"stopped":true}))
}

async fn monitor_loop(state: AppState, mut stop: oneshot::Receiver<()>) {
	tracing::info!("monitor loop started");
	loop {
		if let Ok(_) = stop.try_recv() { tracing::info!("monitor loop stopped"); break; }
		let output = Command::new("cmd").args(["/C", "netstat -ano | findstr ESTABLISHED"]).output();
		if let Ok(out) = output {
			let s = String::from_utf8_lossy(&out.stdout);
			for line in s.lines() {
				if let Some(ip_port) = line.split_whitespace().nth(2) {
					if let Some((ip, _port)) = ip_port.rsplit_once(':') {
						let score = heuristic_score(ip);
						if score >= 80 { let _ = block_ip(ip); }
						let t = Threat { id: uuid(), ip_address: ip.into(), threat_score: score, threat_level: level(score) };
						state.threats.write().push(t);
					}
				}
			}
		}
		sleep(Duration::from_secs(10)).await;
	}
}

fn heuristic_score(ip: &str) -> i32 {
	if ip.starts_with("10.") || ip.starts_with("192.168.") || ip == "127.0.0.1" { return 0; }
	if ip.ends_with(".255") { return 20; }
	70 + (rand::random::<u8>() % 40) as i32
}

fn block_ip(ip: &str) -> anyhow::Result<()> {
	let name = format!("CF_Block_{}", ip.replace('.', "_"));
	let _ = Command::new("cmd").args(["/C", &format!("netsh advfirewall firewall add rule name=\"{}\" dir=out action=block remoteip={}", name, ip)]).status()?;
	tracing::warn!("blocked ip {} via netsh", ip);
	Ok(())
}

fn uuid() -> String { format!("{:x}{:x}", rand::random::<u128>(), rand::random::<u128>()) }
fn level(score: i32) -> String { if score>80 {"CRITICAL".into()} else if score>60 {"HIGH".into()} else if score>40 {"MEDIUM".into()} else {"LOW".into()} }

// -------- Secure Storage (AES-GCM) ----------
#[derive(Deserialize)]
struct UploadReq { data_b64: String, passphrase: String }

async fn storage_upload(Json(req): Json<UploadReq>) -> Json<serde_json::Value> {
	let data = base64::decode(req.data_b64).unwrap_or_default();
	let ct = modules::aes_encrypt(&data, req.passphrase.as_bytes()).unwrap();
	let id = uuid();
	let p = std::path::Path::new("../../data/storage");
	let _ = std::fs::create_dir_all(p);
	std::fs::write(p.join(format!("{}.bin", id)), &ct).ok();
	Json(serde_json::json!({"id": id}))
}

async fn storage_download(Path(id): Path<String>) -> Response {
	let p = std::path::Path::new("../../data/storage").join(format!("{}.bin", id));
	if let Ok(bytes) = std::fs::read(p) { bytes.into_response() } else { (axum::http::StatusCode::NOT_FOUND, "not found").into_response() }
}

async fn storage_list() -> Json<serde_json::Value> {
	let p = std::path::Path::new("../../data/storage");
	let mut items = vec![];
	if let Ok(rd) = std::fs::read_dir(p) { for e in rd.flatten() { if let Some(n) = e.file_name().to_str() { items.push(n.to_string()) } } }
	Json(serde_json::json!({"items": items}))
}

// -------- Secure Messaging (WS relay with registration & pending) ----------
async fn ws_secure(State(state): State<AppState>, ws: WebSocketUpgrade) -> Response { ws.on_upgrade(move |socket| handle_ws(state, socket)) }

#[derive(Deserialize)]
struct RegisterMsg { user_id: String, public_key: String }
#[derive(Deserialize)]
struct Envelope { r#type: String, recipient: Option<String>, encrypted_content: Option<String>, dh_public: Option<String>, user_id: Option<String>, public_key: Option<String> }

async fn handle_ws(state: AppState, socket: WebSocket) {
	let (tx, mut rx_client) = mpsc::unbounded_channel::<Message>();
	let (mut ws_sender, mut ws_recv) = socket.split();
	// Sender task
	tokio::spawn(async move {
		while let Some(msg) = rx_client.recv().await { let _ = ws_sender.send(msg).await; }
	});

	let mut current_user: Option<String> = None;
	while let Some(msg) = ws_recv.next().await {
		let Ok(msg) = msg else { continue };
		if let Message::Text(txt) = msg {
			if let Ok(env) = serde_json::from_str::<Envelope>(&txt) {
				match env.r#type.as_str() {
					"register" => {
						if let (Some(uid), Some(pk)) = (env.user_id, env.public_key) {
							state.messaging.public_keys.write().insert(uid.clone(), pk);
							state.messaging.sessions.write().insert(uid.clone(), tx.clone());
							current_user = Some(uid.clone());
							// deliver pending
							if let Some(mut pending) = state.messaging.pending.write().remove(&uid) {
								for p in pending.drain(..) {
									let _ = tx.send(Message::Text(p.to_string()));
								}
							}
							let _ = tx.send(Message::Text(serde_json::json!({"type":"registered","user_id": uid}).to_string()));
						}
					}
					"message" => {
						if let (Some(rcpt), Some(content)) = (env.recipient, env.encrypted_content) {
							let payload = serde_json::json!({"type":"message","sender": current_user.clone().unwrap_or_default(),"content":content});
							deliver_or_queue(&state, &rcpt, payload).await;
						}
					}
					"key_exchange" => {
						if let (Some(rcpt), Some(dh)) = (env.recipient, env.dh_public) {
							let payload = serde_json::json!({"type":"key_exchange","sender": current_user.clone().unwrap_or_default(),"dh_public":dh});
							deliver_or_queue(&state, &rcpt, payload).await;
						}
					}
					"heartbeat" => { let _ = tx.send(Message::Text(serde_json::json!({"type":"heartbeat_ack"}).to_string())); }
					_ => {}
				}
			}
		}
	}
	// cleanup on disconnect
	if let Some(uid) = current_user { state.messaging.sessions.write().remove(&uid); }
}

async fn deliver_or_queue(state: &AppState, recipient: &str, payload: serde_json::Value) {
	if let Some(sender) = state.messaging.sessions.read().get(recipient) { let _ = sender.send(Message::Text(payload.to_string())); }
	else { state.messaging.pending.write().entry(recipient.to_string()).or_default().push(payload); }
}

// -------- SOAR Endpoints ----------
#[derive(Deserialize)]
struct SoarLoadReq { name: String, yaml: String }
async fn soar_load(State(state): State<AppState>, Json(req): Json<SoarLoadReq>) -> Json<serde_json::Value> {
	match serde_yaml::from_str::<modules::Playbook>(&req.yaml) {
		Ok(pb) => { state.playbooks.write().insert(req.name.clone(), pb); Json(serde_json::json!({"loaded": req.name})) },
		Err(e) => Json(serde_json::json!({"error": e.to_string()})),
	}
}

async fn soar_list(State(state): State<AppState>) -> Json<serde_json::Value> {
	let names: Vec<String> = state.playbooks.read().keys().cloned().collect();
	Json(serde_json::json!({"playbooks": names}))
}

#[derive(Deserialize)]
struct SoarExecReq { name: String }
#[axum::debug_handler]
async fn soar_execute(State(state): State<AppState>, Json(req): Json<SoarExecReq>) -> Json<serde_json::Value> {
	let exec_id = uuid();
	let pb_opt = { state.playbooks.read().get(&req.name).cloned() };
	let mut report = serde_json::json!({"exec_id": exec_id, "playbook": req.name, "results": []});
	let result_json = if let Some(pb) = pb_opt {
		match modules::execute_playbook(&pb).await {
			Ok(results) => {
				let vals: Vec<serde_json::Value> = results.iter().map(|r| serde_json::json!({"step": &r.step, "success": r.success, "output": r.output})).collect();
				// write evidence report
				use std::fs; use std::path::Path;
				let vault = Path::new("../../data/forensics"); let _ = fs::create_dir_all(vault);
				let report_path = vault.join(format!("{}_playbook.json", exec_id));
				report["results"] = serde_json::Value::from(vals.clone());
				let _ = fs::write(&report_path, report.to_string());
				// also drop into any storage_path produced by steps
				for r in results.iter() {
					if let Some(sp) = r.output.get("storage_path").and_then(|v| v.as_str()) {
						let _ = fs::write(std::path::Path::new(sp).join("playbook_execution.json"), report.to_string());
					}
				}
				serde_json::json!({"ok": true, "exec_id": exec_id})
			},
			Err(e) => serde_json::json!({"error": e.to_string()}),
		}
	} else { serde_json::json!({"error":"playbook not found"}) };
	Json(result_json)
} 

// -------- IAM Helpers and Endpoints -------------------------------------------
#[derive(Deserialize)]
struct RegisterReq { email: String, password: String }
#[derive(Deserialize)]
struct LoginReq { email: String, password: String, totp: Option<String> }
#[derive(Serialize)]
struct TokenPair { access_token: String, refresh_token: String }

#[derive(Clone, Debug)]
struct JwtCtx { user_id: String, roles: Vec<String> }

fn hash_password(password: &str) -> String { use argon2::{Argon2, PasswordHasher}; use argon2::password_hash::{SaltString, PasswordHash, rand_core::OsRng}; let salt = SaltString::generate(&mut OsRng); Argon2::default().hash_password(password.as_bytes(), &salt).unwrap().to_string() }
fn verify_password(hash: &str, password: &str) -> bool { use argon2::{Argon2, PasswordVerifier}; use argon2::password_hash::PasswordHash; if let Ok(parsed) = PasswordHash::new(hash) { Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok() } else { false } }

fn issue_tokens(user_id: &str, roles: &[String]) -> TokenPair { use jsonwebtoken::{encode, Header, EncodingKey}; use chrono::{Utc, Duration}; #[derive(Serialize)] struct Claims{ sub:String, exp:usize, roles:Vec<String>, typ:String } let secret = std::env::var("CF_JWT_SECRET").unwrap_or_else(|_| "development_secret_change_me".into()); let now = Utc::now(); let access = Claims{ sub:user_id.into(), exp:(now+Duration::minutes(30)).timestamp() as usize, roles:roles.to_vec(), typ:"access".into()}; let refresh = Claims{ sub:user_id.into(), exp:(now+Duration::days(7)).timestamp() as usize, roles:vec![], typ:"refresh".into()}; let access_token = encode(&Header::default(), &access, &EncodingKey::from_secret(secret.as_bytes())).unwrap(); let refresh_token = encode(&Header::default(), &refresh, &EncodingKey::from_secret(secret.as_bytes())).unwrap(); TokenPair{ access_token, refresh_token } }

fn gen_totp_secret_b32() -> String { use rand::RngCore; let mut bytes = [0u8;20]; rand::thread_rng().fill_bytes(&mut bytes); data_encoding::BASE32_NOPAD.encode(&bytes) }
fn verify_totp(secret_b32: &str, code: &str) -> bool {
	use totp_rs::{Algorithm, TOTP};
	let totp = match TOTP::new(Algorithm::SHA1, 6, 1, 30, secret_b32.as_bytes().to_vec()) { Ok(t)=>t, Err(_)=> return false };
	totp.check_current(code).unwrap_or(false)
}

async fn auth_register(State(state): State<AppState>, Json(req): Json<RegisterReq>) -> Json<serde_json::Value> {
	let id = uuid(); let email_lc = req.email.to_lowercase(); let hash = hash_password(&req.password);
	let rec = UserRecord{ id: id.clone(), email: email_lc.clone(), password_hash: hash, mfa_secret_b32: None, roles: vec!["user".into()], api_keys: vec![] };
	state.iam.users.write().insert(id.clone(), rec);
	state.iam.email_to_id.write().insert(email_lc, id.clone());
	Json(serde_json::json!({"user_id": id}))
}

async fn auth_login(State(state): State<AppState>, Json(req): Json<LoginReq>) -> Json<serde_json::Value> {
	if let Some(uid) = state.iam.email_to_id.read().get(&req.email.to_lowercase()).cloned() {
		if let Some(user) = state.iam.users.read().get(&uid).cloned() {
			if verify_password(&user.password_hash, &req.password) {
				if let Some(secret) = &user.mfa_secret_b32 { // MFA enforced
					if req.totp.as_deref().map(|c| verify_totp(secret, c)).unwrap_or(false) == false { return Json(serde_json::json!({"error":"mfa_required_or_invalid"})); }
				}
				let tokens = issue_tokens(&user.id, &user.roles);
				return Json(serde_json::json!({"access_token": tokens.access_token, "refresh_token": tokens.refresh_token}));
			}
		}
	}
	Json(serde_json::json!({"error":"invalid_credentials"}))
}

#[derive(Deserialize)] struct EnableMfaReq { email: String }
async fn auth_enable_mfa(State(state): State<AppState>, Json(req): Json<EnableMfaReq>) -> Json<serde_json::Value> {
	if let Some(uid) = state.iam.email_to_id.read().get(&req.email.to_lowercase()).cloned() {
		let secret = gen_totp_secret_b32();
		if let Some(user) = state.iam.users.write().get_mut(&uid) { user.mfa_secret_b32 = Some(secret.clone()); }
		return Json(serde_json::json!({"secret_b32": secret}));
	}
	Json(serde_json::json!({"error":"not_found"}))
}

#[derive(Deserialize)] struct VerifyMfaReq { email: String, code: String }
async fn auth_verify_mfa(State(state): State<AppState>, Json(req): Json<VerifyMfaReq>) -> Json<serde_json::Value> {
	if let Some(uid) = state.iam.email_to_id.read().get(&req.email.to_lowercase()).cloned() {
		if let Some(user) = state.iam.users.read().get(&uid) { if let Some(sec) = &user.mfa_secret_b32 { return Json(serde_json::json!({"valid": verify_totp(sec, &req.code)})); } }
	}
	Json(serde_json::json!({"valid": false}))
}

#[derive(Deserialize)] struct RefreshReq { refresh_token: String }
async fn auth_refresh(Json(req): Json<RefreshReq>) -> Json<serde_json::Value> {
	use jsonwebtoken::{decode, DecodingKey, Validation}; let secret = std::env::var("CF_JWT_SECRET").unwrap_or_else(|_| "development_secret_change_me".into()); #[derive(Deserialize)] struct Claims{ sub:String, exp:usize, roles:Option<Vec<String>>, typ:String }
	if let Ok(data) = decode::<Claims>(&req.refresh_token, &DecodingKey::from_secret(secret.as_bytes()), &Validation::default()) { if data.claims.typ=="refresh" { let roles:Vec<String>=vec!["user".into()]; let tokens = issue_tokens(&data.claims.sub, &roles); return Json(serde_json::json!({"access_token": tokens.access_token})); } }
	Json(serde_json::json!({"error":"invalid_refresh"}))
}

async fn auth_me(headers: axum::http::HeaderMap) -> Json<serde_json::Value> {
	let auth = headers.get(axum::http::header::AUTHORIZATION).and_then(|v| v.to_str().ok()).unwrap_or("").strip_prefix("Bearer ").unwrap_or("").to_string();
	let valid = modules::validate_jwt(&auth);
	Json(serde_json::json!({"valid": valid}))
}

#[derive(Deserialize)] struct AssignRoleReq { email: String, role: String }
async fn auth_assign_role(State(state): State<AppState>, Json(req): Json<AssignRoleReq>) -> Json<serde_json::Value> {
	if let Some(uid) = state.iam.email_to_id.read().get(&req.email.to_lowercase()).cloned() {
		if let Some(user) = state.iam.users.write().get_mut(&uid) { if !user.roles.contains(&req.role) { user.roles.push(req.role.clone()); } return Json(serde_json::json!({"ok": true, "roles": user.roles})); }
	}
	Json(serde_json::json!({"ok": false}))
}

#[derive(Deserialize)] struct ApiKeyReq { email: String, name: Option<String> }
async fn auth_create_api_key(State(state): State<AppState>, Json(req): Json<ApiKeyReq>) -> Json<serde_json::Value> {
	if let Some(uid) = state.iam.email_to_id.read().get(&req.email.to_lowercase()).cloned() {
		let key = format!("cfk_{}", uuid());
		if let Some(user) = state.iam.users.write().get_mut(&uid) { user.api_keys.push(key.clone()); return Json(serde_json::json!({"api_key": key})); }
	}
	Json(serde_json::json!({"error":"not_found"}))
} 

async fn jwt_auth(mut req: Request<Body>, next: Next) -> Result<Response, StatusCode> {
	let auth = req.headers().get(axum::http::header::AUTHORIZATION).and_then(|v| v.to_str().ok()).unwrap_or("");
	let token = auth.strip_prefix("Bearer ").unwrap_or("");
	if token.is_empty() || !modules::validate_jwt(token) { return Err(StatusCode::UNAUTHORIZED); }
	// Decode to extract roles
	#[derive(Deserialize)] struct Claims{ sub:String, exp:usize, roles:Option<Vec<String>>, typ:String }
	let secret = std::env::var("CF_JWT_SECRET").unwrap_or_else(|_| "development_secret_change_me".into());
	let ctx = match jsonwebtoken::decode::<Claims>(token, &jsonwebtoken::DecodingKey::from_secret(secret.as_bytes()), &jsonwebtoken::Validation::default()) {
		Ok(data) => JwtCtx{ user_id: data.claims.sub, roles: data.claims.roles.unwrap_or_default() },
		Err(_) => return Err(StatusCode::UNAUTHORIZED),
	};
	req.extensions_mut().insert(ctx);
	Ok(next.run(req).await)
}

fn rbac_allow(action: &str, roles: &Vec<String>) -> bool {
	if roles.iter().any(|r| r=="admin") { return true; }
	let allowed_prefixes = [
		"monitor.", "osint.", "annotation.", "comms.", "storage.",
		"ml.", "crypto.", "forensics.", "identity.", "quantum.", 
		"response.", "geo.", "endpoint.", "dpi.", "privacy.",
		"soar.", "backup.", "audit.", "compliance."
	];
	allowed_prefixes.iter().any(|p| action.starts_with(p))
}

#[derive(Deserialize)]
struct ActionReq { action: String, params: serde_json::Value, timeout: Option<u64> }

fn audit_log(line: &str) {
	let path = std::path::Path::new("../../data/audit"); let _ = std::fs::create_dir_all(path);
	let file = path.join("actions.jsonl");
	if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(file) { let _ = writeln!(f, "{}", line); }
}

async fn exec_action(axum::extract::Extension(ctx): axum::extract::Extension<JwtCtx>, Json(req): Json<ActionReq>) -> Json<serde_json::Value> {
	if !rbac_allow(&req.action, &ctx.roles) { return Json(serde_json::json!({"error":"forbidden"})); }
	let when = chrono::Utc::now().to_rfc3339();
	audit_log(&serde_json::json!({"ts":when,"user":ctx.user_id,"action":req.action,"params":req.params}).to_string());
	let step = modules::PlaybookStep{ id: "ui_action".into(), action: req.action.clone(), params: req.params.clone(), timeout: req.timeout, parallel: None, on_failure: None };
	let pb = modules::Playbook{ name: "ui_action".into(), steps: vec![step] };
	let out = match modules::execute_playbook(&pb).await {
		Ok(mut results) => {
			if let Some(r) = results.pop() { serde_json::json!({"success": r.success, "output": r.output}) } else { serde_json::json!({"error":"no_result"}) }
		}
		Err(e) => serde_json::json!({"error": e.to_string()}),
	};
	audit_log(&serde_json::json!({"ts":when,"user":ctx.user_id,"action":req.action,"result":&out}).to_string());
	Json(out)
} 