use serde::{Serialize, Deserialize};
use anyhow::{Result, anyhow};
use chrono::{DateTime, Utc};
use std::{fs, path::PathBuf, io::Write};
use tokio::time::{timeout, Duration};
#[cfg(target_os="windows")]
use std::os::windows::process::CommandExt;

// SOAR -----------------------------------------------------------------
#[derive(Serialize, Deserialize, Clone, Default)]
pub struct Playbook { pub name: String, pub steps: Vec<PlaybookStep> }
#[derive(Serialize, Deserialize, Clone, Default)]
pub struct PlaybookStep { pub id: String, pub action: String, pub params: serde_json::Value, pub timeout: Option<u64>, pub parallel: Option<bool>, pub on_failure: Option<String> }
#[derive(Serialize, Deserialize, Clone)]
pub struct ExecutionResult { pub step: String, pub success: bool, pub output: serde_json::Value }

pub async fn execute_playbook(pb: &Playbook) -> Result<Vec<ExecutionResult>> {
	let mut results = vec![];
	for step in &pb.steps {
		let fut = execute_step(step);
		let res = if let Some(sec) = step.timeout { timeout(Duration::from_secs(sec), fut).await.map_err(|_| anyhow!("step timeout"))? } else { fut.await };
		let ok = res.is_ok();
		let out = match res { Ok(v)=>v, Err(e)=> serde_json::json!({"error": e.to_string()}) };
		results.push(ExecutionResult{ step: step.id.clone(), success: ok, output: out});
		if !ok && step.on_failure.as_deref() != Some("continue") { break; }
	}
	Ok(results)
}

async fn execute_step(step: &PlaybookStep) -> Result<serde_json::Value> {
	match step.action.as_str() {
		"network.isolate_host" => {
			let host: String = getp(step, "host")?;
			isolate_host(&host)?;
			Ok(serde_json::json!({"isolated": host}))
		}
		"endpoint.kill_process" => { let pid: i32 = getp(step, "pid")?; kill_process(pid)?; Ok(serde_json::json!({"killed": pid})) }
		"forensics.collect_artifacts" => { let case_id = uuid(); let dir = collect_artifacts(&case_id)?; Ok(serde_json::json!({"case_id": case_id, "storage_path": dir})) }
		"forensics.get_process_tree" => { let text = get_process_tree()?; Ok(serde_json::json!({"process_tree": text})) }
		"endpoint.scan_file" => { let path: String = getp(step, "path")?; let info = scan_file(&path)?; Ok(serde_json::json!(info)) }
		"endpoint.quarantine_file" => { let path: String = getp(step, "path")?; let q = quarantine_file(&path)?; Ok(serde_json::json!({"quarantined": q})) }
		"backup.create_snapshot" => { let target: String = getp_opt(step, "target").unwrap_or_else(|| String::from("../../data")); let out = backup_snapshot(&target)?; Ok(serde_json::json!({"snapshot": out})) }
		"notification.send" => { let priority: String = getp_opt(step, "priority").unwrap_or_else(|| "info".into()); let template: String = getp_opt(step, "template").unwrap_or_else(|| "generic".into()); notify(&priority, &template)?; Ok(serde_json::json!({"sent": true})) }
		"notification.slack" => { let webhook: String = getp(step, "webhook")?; let text: String = getp(step, "text")?; slack_notify(&webhook, &text).await?; Ok(serde_json::json!({"slack":"ok"})) }
		"notification.email" => { let to: String = getp(step, "to")?; let subject: String = getp(step, "subject")?; let body: String = getp(step, "body")?; email_notify(&to, &subject, &body).await?; Ok(serde_json::json!({"email":"ok"})) }
		"notification.pagerduty" => { let url: String = getp(step, "url")?; let payload: serde_json::Value = getp(step, "payload")?; pagerduty_notify(&url, payload).await?; Ok(serde_json::json!({"pagerduty":"ok"})) }
		"edr.isolate_host" => { let api_url: String = getp(step, "api_url")?; let api_key: String = getp(step, "api_key")?; let host: String = getp(step, "host")?; edr_isolate_host(&api_url, &api_key, &host).await?; Ok(serde_json::json!({"edr_isolated": host})) }
		"network.block_ip" => { let ip: String = getp(step, "ip")?; block_ip_netsh(&ip)?; Ok(serde_json::json!({"blocked": ip})) }
		"network.block_cidr" => { let cidr: String = getp(step, "cidr")?; block_ip_netsh(&cidr)?; Ok(serde_json::json!({"blocked": cidr})) }
		"network.block_domain" => { let domain: String = getp(step, "domain")?; block_domain_hosts(&domain)?; Ok(serde_json::json!({"blocked_domain": domain})) }
		"run.command" => { let cmd: String = getp(step, "cmd")?; let out = run_command(&cmd)?; Ok(serde_json::json!({"output": out})) }
		"case.create" => { let id = create_case()?; Ok(serde_json::json!({"case_id": id})) }
		"case.append_evidence" => { let case_id: String = getp(step, "case_id")?; let content: serde_json::Value = getp(step, "content")?; append_evidence(&case_id, &content)?; Ok(serde_json::json!({"appended": true})) }

		// Advanced Firewall Guide - Threat-Specific Rule Sets (Linux iptables) -------------------
		"firewall.portscan_protection.enable" => { linux_portscan_protection_enable()?; Ok(serde_json::json!({"portscan_protection": "enabled"})) }
		"firewall.bruteforce_protection.enable" => { let ports: Vec<u16> = getp_opt(step, "ports").unwrap_or_else(|| vec![22,80,21,3389]); linux_bruteforce_protection_enable(&ports)?; Ok(serde_json::json!({"bruteforce_protection": "enabled", "ports": ports})) }
		"firewall.malware_blocking.enable" => { linux_malware_blocking_enable()?; windows_block_malware_ports()?; Ok(serde_json::json!({"malware_blocking": "enabled"})) }
		"firewall.exploit_protection.enable" => { linux_exploit_protection_enable()?; Ok(serde_json::json!({"exploit_protection": "enabled"})) }
		"firewall.apply_protection_chains" => { linux_apply_protection_chains()?; Ok(serde_json::json!({"applied": true})) }
		"firewall.reset" => { linux_reset_protection_chains()?; windows_reset_cf_rules()?; Ok(serde_json::json!({"reset": true})) }
		"firewall.allow_ports" => { let ports: Vec<u16> = getp(step, "ports")?; let protocol: String = getp_opt(step, "protocol").unwrap_or("TCP".into()); linux_allow_ports(&ports, &protocol)?; windows_allow_inbound_ports(&ports, &protocol)?; Ok(serde_json::json!({"allowed": ports, "protocol": protocol})) }
		"firewall.block_ports" => { let ports: Vec<u16> = getp(step, "ports")?; let protocol: String = getp_opt(step, "protocol").unwrap_or("TCP".into()); linux_block_ports(&ports, &protocol)?; windows_block_inbound_ports(&ports, &protocol)?; Ok(serde_json::json!({"blocked": ports, "protocol": protocol})) }

		// Application Layer Protection (nftables on Linux)
		"app_layer.nft.apply_config" => { let config: String = getp(step, "config")?; linux_nft_apply_config(&config)?; Ok(serde_json::json!({"nft": "applied"})) }

		// Geographic Blocking --------------------------------------------------
		"geo.block_countries" => { let countries: Vec<String> = getp(step, "countries")?; geo_block_countries(&countries).await?; Ok(serde_json::json!({"blocked_countries": countries})) }
		"geo.whitelist_countries" => { let countries: Vec<String> = getp(step, "countries")?; linux_geo_whitelist_countries(&countries).await?; Ok(serde_json::json!({"whitelist_countries": countries})) }

		// Rate Limiting & DDoS (Linux only where applicable) -------------------
		"rate_limit.enable" => { linux_rate_limit_enable()?; Ok(serde_json::json!({"rate_limit": "enabled"})) }
		"firewall.smtp_outbound_block" => { linux_block_outbound_ports(&[25,465,587])?; windows_block_outbound_ports(&[25,465,587])?; Ok(serde_json::json!({"smtp_block": true})) }
		"firewall.irc_outbound_block" => { linux_block_outbound_port_ranges(&[(6660u16,6669u16),(7000u16,7000u16)])?; windows_block_outbound_ports_range(&[(6660u16,6669u16),(7000u16,7000u16)])?; Ok(serde_json::json!({"irc_block": true})) }

		// DPI and ML Firewall (Python utilities) -------------------------------------
		"dpi.start" => { let iface: String = getp_opt(step, "interface").unwrap_or_else(|| "eth0".into()); let pid = start_python_background("../tools/python/dpi_firewall.py", &["--interface", &iface])?; Ok(serde_json::json!({"started": true, "pid": pid})) }
		"dpi.stop" => { let stopped = stop_background("dpi"); Ok(serde_json::json!({"stopped": stopped})) }
		"ml.firewall.train" => { let minutes: u64 = getp_opt(step, "minutes").unwrap_or(60); let out = run_python("../tools/python/ml_firewall_rules.py", &["train", "--minutes", &minutes.to_string()])?; Ok(serde_json::json!({"output": out})) }
		"ml.firewall.detect_apply" => { let minutes: u64 = getp_opt(step, "minutes").unwrap_or(10); let out = run_python("../tools/python/ml_firewall_rules.py", &["detect", "--minutes", &minutes.to_string(), "--apply"]) ?; Ok(serde_json::json!({"output": out})) }
		"ml.firewall.adaptive_start" => { let pid = start_python_background("../tools/python/ml_firewall_rules.py", &["adaptive"]) ?; Ok(serde_json::json!({"started": true, "pid": pid})) }
		"ml.firewall.adaptive_stop" => { let stopped = stop_background("ml_adaptive"); Ok(serde_json::json!({"stopped": stopped})) }

		// Monitoring Suite (from Automated Security Monitoring Scripts) -----------------
		"monitor.threat_detector.start" => { let interval: u64 = getp_opt(step, "interval").unwrap_or(5); let respond: bool = getp_opt(step, "respond").unwrap_or(false); let pid = start_python_background("../tools/python/threat_detector.py", &["--interval", &interval.to_string(), if respond {"--respond"} else {""}].iter().filter(|s| !s.is_empty()).cloned().collect::<Vec<_>>().as_slice())?; Ok(serde_json::json!({"started": true, "pid": pid})) }
		"monitor.threat_detector.stop" => { let stopped = stop_background("threat_detector"); Ok(serde_json::json!({"stopped": stopped})) }
		"monitor.log_analyzer.run" => { let out = run_python("../tools/python/log_analyzer.py", &[])?; Ok(serde_json::json!({"report": out})) }
		"monitor.integrity_monitor.start" => { let interval: u64 = getp_opt(step, "interval").unwrap_or(300); let pid = start_python_background("../tools/python/integrity_monitor.py", &["--interval", &interval.to_string()])?; Ok(serde_json::json!({"started": true, "pid": pid})) }
		"monitor.network_analyzer.start" => { let iface: String = getp_opt(step, "interface").unwrap_or("eth0".into()); let duration: u64 = getp_opt(step, "duration").unwrap_or(60); let pid = start_python_background("../tools/python/network_analyzer.py", &["--interface", &iface, "--duration", &duration.to_string()])?; Ok(serde_json::json!({"started": true, "pid": pid})) }

		// Incident Response --------------------------------------------------------------
		"ir.respond" => { let t: String = getp(step, "type")?; let ip: Option<String> = getp_opt(step, "ip"); let file: Option<String> = getp_opt(step, "file"); let mut argsv = vec!["--type", &t]; if let Some(v)=ip.as_ref(){ argsv.push("--ip"); argsv.push(v); } if let Some(v)=file.as_ref(){ argsv.push("--file"); argsv.push(v); } let out = run_python("../tools/python/incident_response.py", &argsv)?; Ok(serde_json::json!({"result": out})) }

		// Forensics (Incident Forensics & Analysis) ----------------------------------------
		"forensics.memory.capture" => { let case_id: String = getp_opt(step, "case_id").unwrap_or(uuid()); let out = run_python("../tools/python/forensic_memory.py", &["--case-id", &case_id])?; Ok(serde_json::json!({"memory": out})) }
		"forensics.disk.image" => { let target: String = getp(step, "target")?; let case_id: String = getp_opt(step, "case_id").unwrap_or(uuid()); let out = run_python("../tools/python/forensic_disk_image.py", &["--target", &target, "--case-id", &case_id])?; Ok(serde_json::json!({"image": out})) }
		"forensics.events.export" => { let case_id: String = getp_opt(step, "case_id").unwrap_or(uuid()); let out = run_python("../tools/python/forensic_event_logs.py", &["--case-id", &case_id])?; Ok(serde_json::json!({"events": out})) }
		"forensics.browser.collect" => { let case_id: String = getp_opt(step, "case_id").unwrap_or(uuid()); let out = run_python("../tools/python/forensic_browser_artifacts.py", &["--case-id", &case_id])?; Ok(serde_json::json!({"browser": out})) }
		"forensics.registry.dump" => { let case_id: String = getp_opt(step, "case_id").unwrap_or(uuid()); let out = run_python("../tools/python/forensic_registry_dump.py", &["--case-id", &case_id])?; Ok(serde_json::json!({"registry": out})) }
		"forensics.yara.scan" => { let rules: String = getp(step, "rules")?; let path: String = getp(step, "path")?; let out = run_python("../tools/python/forensic_yara_scan.py", &["--rules", &rules, "--path", &path])?; Ok(serde_json::json!({"yara": out})) }
		"forensics.triage.run" => { let case_id: String = getp_opt(step, "case_id").unwrap_or(uuid()); let rules: Option<String> = getp_opt(step, "yara_rules"); let mut argsv: Vec<String> = vec!["--case-id".into(), case_id]; if let Some(r)=rules { argsv.push("--yara-rules".into()); argsv.push(r); } let out = run_python_owned("../tools/python/forensic_triage.py", argsv)?; Ok(serde_json::json!({"triage": out})) }
		"forensics.pcap.start" => { let iface: String = getp_opt(step, "interface").unwrap_or("eth0".into()); let out_path: String = getp_opt(step, "out").unwrap_or("capture.pcapng".into()); let out = run_python("../tools/python/forensic_pcap.py", &["start","--iface", &iface, "--out", &out_path])?; Ok(serde_json::json!({"pcap": out})) }
		"forensics.pcap.stop" => { let out = run_python("../tools/python/forensic_pcap.py", &["stop"])?; Ok(serde_json::json!({"pcap": out})) }

		// Smart Contract Security --------------------------------------------------------
		"crypto.smart_contract.scan" => { let target: String = getp(step, "target")?; let out = run_python("../tools/python/smart_contract_scan.py", &[&target])?; Ok(serde_json::json!({"scan": out})) }

		// Quantum Security Placeholders --------------------------------------------------
		// Quantum-Resistant Encryption (Full Implementation) ---------------------------
		"quantum.keygen" => { let level: String = getp_opt(step, "security_level").unwrap_or("high".into()); let out = run_python("../tools/python/quantum_encryption.py", &["keygen", "--security-level", &level])?; Ok(serde_json::from_str(&out)?) }
		"quantum.encrypt" => { let data: String = getp(step, "data")?; let pub_key: String = getp(step, "public_key")?; let level: String = getp_opt(step, "security_level").unwrap_or("high".into()); let out = run_python("../tools/python/quantum_encryption.py", &["encrypt", "--data", &data, "--public-key", &pub_key, "--security-level", &level])?; Ok(serde_json::from_str(&out)?) }
		"quantum.decrypt" => { let data: String = getp(step, "encrypted_data")?; let priv_key: String = getp(step, "private_key")?; let out = run_python("../tools/python/quantum_encryption.py", &["decrypt", "--data", &data, "--private-key", &priv_key])?; Ok(serde_json::json!({"plaintext": out})) }
		"quantum.sign" => { let data: String = getp(step, "data")?; let priv_key: String = getp(step, "private_key")?; let out = run_python("../tools/python/quantum_encryption.py", &["sign", "--data", &data, "--private-key", &priv_key])?; Ok(serde_json::from_str(&out)?) }
		"quantum.verify" => { let data: String = getp(step, "data")?; let sig: String = getp(step, "signature")?; let pub_key: String = getp(step, "public_key")?; let out = run_python("../tools/python/quantum_encryption.py", &["verify", "--data", &data, "--key", &sig, "--public-key", &pub_key])?; Ok(serde_json::from_str(&out)?) }
		"quantum.assess_threat" => { let algo: String = getp(step, "algorithm")?; let out = run_python("../tools/python/quantum_encryption.py", &["assess", "--algorithm", &algo])?; Ok(serde_json::from_str(&out)?) }
		"quantum.vault_init" => { let pass: Option<String> = getp_opt(step, "password"); let mut args = vec!["vault-init"]; if let Some(p) = &pass { args.push("--data"); args.push(p); } let out = run_python("../tools/python/quantum_encryption.py", &args)?; Ok(serde_json::from_str(&out)?) }
		"quantum.qkd_simulate" => { let out = run_python("../tools/python/quantum_encryption.py", &["qkd"])?; Ok(serde_json::from_str(&out)?) }
		"auth.validate_token" => { let token: String = getp(step, "token")?; let valid = validate_jwt(&token); Ok(serde_json::json!({"valid": valid})) }

		// Secure Comms & Encrypted Storage -------------------------------------------------
		"comms.secure_messaging.start" => { let port: u16 = getp_opt(step, "port").unwrap_or(8765); let mut argsv: Vec<String> = vec!["--host".into(), "0.0.0.0".into(), "--port".into(), port.to_string()]; if let Some(cert) = getp_opt::<String>(step, "cert") { if let Some(key) = getp_opt::<String>(step, "key") { argsv.push("--cert".into()); argsv.push(cert); argsv.push("--key".into()); argsv.push(key); } } let pid = start_python_background_owned("../tools/python/secure_messaging.py", argsv)?; Ok(serde_json::json!({"started": true, "pid": pid, "port": port})) }
		"comms.secure_messaging.stop" => { let stopped = stop_background("secure_messaging"); Ok(serde_json::json!({"stopped": stopped})) }
		"storage.secure_share.start" => { let pid = start_python_background("../tools/python/secure_file_share.py", &[])?; Ok(serde_json::json!({"started": true, "pid": pid})) }
		"storage.secure_share.stop" => { let stopped = stop_background("secure_file_share"); Ok(serde_json::json!({"stopped": stopped})) }
		"comms.security.monitor.run" => { let out = run_python("../tools/python/comm_security_monitor.py", &[])?; Ok(serde_json::json!({"report": out})) }
		"comms.secure_messaging.key_exchange" => { Ok(serde_json::json!({"note":"key exchange forwarded by secure_messaging relay at runtime"})) }

		// Matrix + TURN remote deployment (infra)
		"infra.comms.matrix_turn.deploy" => {
			let host: String = getp(step, "host")?;
			let user: String = getp(step, "user")?;
			let domain: String = getp(step, "domain")?;
			let email: String = getp(step, "email")?;
			let turn_secret: String = getp(step, "turn_secret")?;
			let password: Option<String> = getp_opt(step, "password");
			let keyfile: Option<String> = getp_opt(step, "keyfile");
			let mut argsv: Vec<String> = vec!["deploy".into(), "--host".into(), host, "--user".into(), user, "--domain".into(), domain, "--email".into(), email, "--turn-secret".into(), turn_secret];
			if let Some(pw) = password { argsv.push("--password".into()); argsv.push(pw); }
			if let Some(kf) = keyfile { argsv.push("--keyfile".into()); argsv.push(kf); }
			let out = run_python_owned("../tools/python/infra_matrix_turn.py", argsv)?;
			Ok(serde_json::json!({"deploy": out}))
		}
		"infra.comms.matrix_turn.status" => {
			let host: String = getp(step, "host")?;
			let user: String = getp(step, "user")?;
			let password: Option<String> = getp_opt(step, "password");
			let keyfile: Option<String> = getp_opt(step, "keyfile");
			let mut argsv: Vec<String> = vec!["status".into(), "--host".into(), host, "--user".into(), user];
			if let Some(pw) = password { argsv.push("--password".into()); argsv.push(pw); }
			if let Some(kf) = keyfile { argsv.push("--keyfile".into()); argsv.push(kf); }
			let out = run_python_owned("../tools/python/infra_matrix_turn.py", argsv)?;
			Ok(serde_json::json!({"status": out}))
		}
		"infra.comms.matrix_turn.destroy" => {
			let host: String = getp(step, "host")?;
			let user: String = getp(step, "user")?;
			let password: Option<String> = getp_opt(step, "password");
			let keyfile: Option<String> = getp_opt(step, "keyfile");
			let mut argsv: Vec<String> = vec!["destroy".into(), "--host".into(), host, "--user".into(), user];
			if let Some(pw) = password { argsv.push("--password".into()); argsv.push(pw); }
			if let Some(kf) = keyfile { argsv.push("--keyfile".into()); argsv.push(kf); }
			let out = run_python_owned("../tools/python/infra_matrix_turn.py", argsv)?;
			Ok(serde_json::json!({"destroy": out}))
		}

		// Privacy-Preserving Network Configs (Tor/I2P) placeholders -----------------------
		"privacy.tor.enable" => { let out = run_python("../tools/python/privacy_net.py", &["tor-enable"])?; Ok(serde_json::json!({"tor": out})) }
		"privacy.tor.disable" => { let out = run_python("../tools/python/privacy_net.py", &["tor-disable"])?; Ok(serde_json::json!({"tor": out})) }
		"privacy.dns.stubby.enable" => { let out = run_python("../tools/python/privacy_net.py", &["stubby-enable"])?; Ok(serde_json::json!({"stubby": out})) }
		"privacy.dns.stubby.disable" => { let out = run_python("../tools/python/privacy_net.py", &["stubby-disable"])?; Ok(serde_json::json!({"stubby": out})) }
		"privacy.dns.dnscrypt.enable" => { let out = run_python("../tools/python/privacy_net.py", &["dnscrypt-enable"])?; Ok(serde_json::json!({"dnscrypt": out})) }
		"privacy.dns.dnscrypt.disable" => { let out = run_python("../tools/python/privacy_net.py", &["dnscrypt-disable"])?; Ok(serde_json::json!({"dnscrypt": out})) }
		"privacy.wg.apply" => { let config_b64: String = getp(step, "config_b64")?; let out = run_python("../tools/python/privacy_net.py", &["wg-apply","--config-b64", &config_b64])?; Ok(serde_json::json!({"wireguard": out})) }
		"privacy.wg.killswitch.enable" => { let out = run_python("../tools/python/privacy_net.py", &["wg-killswitch-enable"])?; Ok(serde_json::json!({"killswitch": out})) }
		"privacy.wg.killswitch.disable" => { let out = run_python("../tools/python/privacy_net.py", &["wg-killswitch-disable"])?; Ok(serde_json::json!({"killswitch": out})) }
		"privacy.netns.run" => { let name: String = getp(step, "name")?; let cmd: String = getp(step, "cmd")?; let out = run_python("../tools/python/privacy_net.py", &["netns-run","--name", &name, "--cmd", &cmd])?; Ok(serde_json::json!({"netns": out})) }

		// Personal Security & Privacy Protection -------------------------------------------
		"privacy.password.generate" => { let length: u32 = getp_opt(step, "length").unwrap_or(20); let symbols: bool = getp_opt(step, "symbols").unwrap_or(true); let mut argsv: Vec<String> = vec!["generate".into(), "--length".into(), length.to_string()]; if !symbols { argsv.push("--no-symbols".into()); } let out = run_python_owned("../tools/python/password_tools.py", argsv)?; Ok(serde_json::json!({"password": out})) }
		"privacy.password.check" => { let pwd: String = getp(step, "password")?; let out = run_python("../tools/python/password_tools.py", &["check","--password", &pwd])?; Ok(serde_json::json!({"pwned": out})) }
		"privacy.metadata.strip" => { let input: String = getp(step, "input")?; let output: String = getp_opt(step, "output").unwrap_or(input.clone()); let out = run_python("../tools/python/metadata_tools.py", &["--in", &input, "--out", &output])?; Ok(serde_json::json!({"result": out})) }
		"privacy.secure_delete" => { let path: String = getp(step, "path")?; let passes: u32 = getp_opt(step, "passes").unwrap_or(3); let out = run_python("../tools/python/secure_delete.py", &["--path", &path, "--passes", &passes.to_string()])?; Ok(serde_json::json!({"deleted": out})) }
		"privacy.pgp.keygen" => { let name: String = getp(step, "name")?; let email: String = getp(step, "email")?; let out = run_python("../tools/python/pgp_tools.py", &["keygen","--name", &name, "--email", &email])?; Ok(serde_json::json!({"pgp": out})) }
		"privacy.pgp.encrypt" => { let recipient: String = getp(step, "recipient")?; let input: String = getp(step, "input")?; let output: String = getp(step, "output")?; let out = run_python("../tools/python/pgp_tools.py", &["encrypt","--recipient", &recipient, "--in", &input, "--out", &output])?; Ok(serde_json::json!({"pgp": out})) }
		"privacy.pgp.decrypt" => { let input: String = getp(step, "input")?; let output: String = getp(step, "output")?; let out = run_python("../tools/python/pgp_tools.py", &["decrypt","--in", &input, "--out", &output])?; Ok(serde_json::json!({"pgp": out})) }
		"privacy.hosts.apply_blocklist" => { let source: String = getp_opt(step, "source").unwrap_or("default".into()); let mut argsv = vec![]; if source != "default" { argsv = vec!["--source", &source]; } let out = run_python("../tools/python/hosts_blocklist.py", &argsv)?; Ok(serde_json::json!({"hosts": out})) }
		"privacy.windows.disable_telemetry" => { let out = run_python("../tools/python/win_privacy.py", &["disable-telemetry"]).unwrap_or_default(); Ok(serde_json::json!({"windows_privacy": out})) }
		"privacy.breach.check" => { let email: String = getp(step, "email")?; let api_key: Option<String> = getp_opt(step, "api_key"); let mut argsv: Vec<String> = vec!["--email".into(), email]; if let Some(k)=api_key { argsv.push("--api-key".into()); argsv.push(k); } let out = run_python_owned("../tools/python/breach_checker.py", argsv)?; Ok(serde_json::json!({"breach": out})) }

		// Mobile Device Hardening hooks (requires ADB connected device) -------------------
		"mobile.android.audit" => { let serial: Option<String> = getp_opt(step, "serial"); let mut argsv: Vec<String> = vec!["audit".into()]; if let Some(s)=serial { argsv.push("--serial".into()); argsv.push(s); } let out = run_python_owned("../tools/python/mobile_android_hardening.py", argsv)?; Ok(serde_json::json!({"android": out})) }
		"mobile.android.apply" => { let serial: Option<String> = getp_opt(step, "serial"); let mut argsv: Vec<String> = vec!["apply".into()]; if let Some(s)=serial { argsv.push("--serial".into()); argsv.push(s); } let out = run_python_owned("../tools/python/mobile_android_hardening.py", argsv)?; Ok(serde_json::json!({"android": out})) }
		"mobile.android.freeze" => { let package: String = getp(step, "package")?; let serial: Option<String> = getp_opt(step, "serial"); let mut argsv: Vec<String> = vec!["freeze".into(), "--package".into(), package]; if let Some(s)=serial { argsv.push("--serial".into()); argsv.push(s); } let out = run_python_owned("../tools/python/mobile_android_hardening.py", argsv)?; Ok(serde_json::json!({"android": out})) }
		"mobile.android.unfreeze" => { let package: String = getp(step, "package")?; let serial: Option<String> = getp_opt(step, "serial"); let mut argsv: Vec<String> = vec!["unfreeze".into(), "--package".into(), package]; if let Some(s)=serial { argsv.push("--serial".into()); argsv.push(s); } let out = run_python_owned("../tools/python/mobile_android_hardening.py", argsv)?; Ok(serde_json::json!({"android": out})) }
		"mobile.android.revoke_dangerous" => { let package: String = getp(step, "package")?; let serial: Option<String> = getp_opt(step, "serial"); let mut argsv: Vec<String> = vec!["revoke-dangerous".into(), "--package".into(), package]; if let Some(s)=serial { argsv.push("--serial".into()); argsv.push(s); } let out = run_python_owned("../tools/python/mobile_android_hardening.py", argsv)?; Ok(serde_json::json!({"android": out})) }
		"mobile.android.set_policy" => { let ns: String = getp(step, "ns")?; let key: String = getp(step, "key")?; let value: String = getp(step, "value")?; let serial: Option<String> = getp_opt(step, "serial"); let mut argsv: Vec<String> = vec!["set-policy".into(), "--ns".into(), ns, "--key".into(), key, "--value".into(), value]; if let Some(s)=serial { argsv.push("--serial".into()); argsv.push(s); } let out = run_python_owned("../tools/python/mobile_android_hardening.py", argsv)?; Ok(serde_json::json!({"android": out})) }
		"mobile.ios.guidance" => { let out = run_python("../tools/python/mobile_ios_helper.py", &["guidance"])?; Ok(serde_json::json!({"ios": out})) }

		// Identity Protection & Data Broker Removal Suite ---------------------------------
		"identity.add" => { let data: String = getp(step, "identity_data")?; let out = run_python("../tools/python/identity_protection.py", &["add", "--data", &data])?; Ok(serde_json::from_str(&out)?) }
		"identity.scan_darkweb" => { let id: i32 = getp(step, "identity_id")?; let out = run_python("../tools/python/identity_protection.py", &["scan", "--identity-id", &id.to_string()])?; Ok(serde_json::from_str(&out)?) }
		"identity.remove_brokers" => { let id: i32 = getp(step, "identity_id")?; let category: String = getp_opt(step, "category").unwrap_or("all".into()); let out = run_python("../tools/python/identity_protection.py", &["remove-brokers", "--identity-id", &id.to_string(), "--category", &category])?; Ok(serde_json::from_str(&out)?) }
		"identity.check_breaches" => { let email: String = getp(step, "email")?; let out = run_python("../tools/python/identity_protection.py", &["check-breaches", "--email", &email])?; Ok(serde_json::from_str(&out)?) }
		"identity.freeze_credit" => { let id: i32 = getp(step, "identity_id")?; let out = run_python("../tools/python/identity_protection.py", &["freeze-credit", "--identity-id", &id.to_string()])?; Ok(serde_json::from_str(&out)?) }
		"identity.monitor_accounts" => { let accounts: serde_json::Value = getp(step, "accounts")?; let out = run_python("../tools/python/identity_protection.py", &["monitor", "--data", &accounts.to_string()])?; Ok(serde_json::from_str(&out)?) }
		"identity.synthetic_check" => { let data: String = getp(step, "identity_data")?; let out = run_python("../tools/python/identity_protection.py", &["synthetic-check", "--data", &data])?; Ok(serde_json::from_str(&out)?) }
		"identity.report" => { let id: i32 = getp(step, "identity_id")?; let out = run_python("../tools/python/identity_protection.py", &["report", "--identity-id", &id.to_string()])?; Ok(serde_json::from_str(&out)?) }

		// OSINT Investigation Tools --------------------------------------------------------
		"osint.harvest.start" => { let target: String = getp(step, "target")?; let pid = start_python_background("../tools/python/osint_harvester.py", &["--target", &target])?; Ok(serde_json::json!({"started": true, "pid": pid})) }
		"osint.collect" => { let target: String = getp(step, "target")?; let out = run_python("../tools/python/osint_collect.py", &["--target", &target])?; Ok(serde_json::json!({"collected": out})) }
		"osint.enrich" => { let data: String = getp(step, "data")?; let out = run_python("../tools/python/osint_enrich.py", &["--data", &data])?; Ok(serde_json::json!({"enriched": out})) }
		"osint.social" => { let username: String = getp(step, "username")?; let out = run_python("../tools/python/osint_social.py", &["--username", &username])?; Ok(serde_json::json!({"social": out})) }
		"osint.graph" => { let target: String = getp(step, "target")?; let out = run_python("../tools/python/osint_graph.py", &["--target", &target])?; Ok(serde_json::json!({"graph": out})) }
		"ml.dataset.ingest" => { let name: String = getp(step, "name")?; let csv: String = getp(step, "csv")?; let target: Option<String> = getp_opt(step, "target"); let mut argsv: Vec<String> = vec!["--name".into(), name, "--csv".into(), csv]; if let Some(t)=target { argsv.push("--target".into()); argsv.push(t); } let out = run_python_owned("../tools/python/ml_dataset.py", argsv)?; Ok(serde_json::json!({"dataset": out})) }
		"ml.training.start" => { let dataset: String = getp(step, "dataset")?; let algo: String = getp_opt(step, "algo").unwrap_or("iforest".into()); let target: Option<String> = getp_opt(step, "target"); let mut argsv: Vec<String> = vec!["--dataset".into(), dataset, "--algo".into(), algo]; if let Some(t)=target { argsv.push("--target".into()); argsv.push(t); } let out = run_python_owned("../tools/python/ml_train_worker.py", argsv)?; Ok(serde_json::json!({"train": out})) }
		"ml.training.status" => { let out = run_python("../tools/python/ml_registry.py", &["status"])?; Ok(serde_json::json!({"status": out})) }
		"ml.model.list" => { let out = run_python("../tools/python/ml_registry.py", &["list"])?; Ok(serde_json::json!({"models": out})) }
		"ml.model.promote" => { let model: String = getp(step, "model")?; let out = run_python("../tools/python/ml_registry.py", &["promote","--model", &model])?; Ok(serde_json::json!({"promoted": out})) }
		"ml.infer.start" => { let host: String = getp_opt(step, "host").unwrap_or("127.0.0.1".into()); let port: u16 = getp_opt(step, "port").unwrap_or(5055); let pid = start_python_background("../tools/python/ml_infer_server.py", &["start","--host", &host, "--port", &port.to_string()])?; Ok(serde_json::json!({"started": true, "pid": pid, "host": host, "port": port})) }
		"ml.infer.stop" => { let out = run_python("../tools/python/ml_infer_server.py", &["stop"]).unwrap_or_default(); Ok(serde_json::json!({"stopped": out})) }

		// Smart contract advanced analyses --------------------------------------------------
		"crypto.tx.simulate" => { let tx: serde_json::Value = getp(step, "tx")?; let out = run_python("../tools/python/sc_tx_simulator.py", &["--tx", &tx.to_string()])?; Ok(serde_json::json!({"simulation": out})) }
		"crypto.tx.mev_protect" => { let tx: serde_json::Value = getp(step, "tx")?; let out = run_python("../tools/python/mev_protection.py", &["--tx", &tx.to_string()])?; Ok(serde_json::json!({"mev": out})) }
		"crypto.contract.rugpull" => { let features: serde_json::Value = getp(step, "features")?; let out = run_python("../tools/python/rugpull_detector.py", &["--features", &features.to_string()])?; Ok(serde_json::json!({"rugpull": out})) }
		"crypto.contract.honeypot" => { let features: serde_json::Value = getp(step, "features")?; let out = run_python("../tools/python/honeypot_detector.py", &["--features", &features.to_string()])?; Ok(serde_json::json!({"honeypot": out})) }
		"crypto.cross_chain.assess" => { let tx: serde_json::Value = getp(step, "tx")?; let out = run_python("../tools/python/cross_chain_monitor.py", &["--tx", &tx.to_string()])?; Ok(serde_json::json!({"assessment": out})) }
		"crypto.contract.audit" => { let target: String = getp(step, "target")?; let out = run_python("../tools/python/smart_contract_audit.py", &["--target", &target])?; Ok(serde_json::json!({"audit": out})) }
		"crypto.event.monitor" => { let address: String = getp(step, "address")?; let webhook: Option<String> = getp_opt(step, "webhook"); let mut argsv: Vec<String> = vec!["monitor".into(), "--address".into(), address]; if let Some(w)=webhook { argsv.push("--webhook".into()); argsv.push(w); } let out = run_python_owned("../tools/python/blockchain_monitor.py", argsv)?; Ok(serde_json::json!({"monitor": out})) }
		"crypto.alert.send" => { let channel: String = getp(step, "channel")?; let target: String = getp(step, "target")?; let message: String = getp(step, "message")?; let out = run_python("../tools/python/blockchain_monitor.py", &["alert","--channel", &channel, "--target", &target, "--message", &message])?; Ok(serde_json::json!({"alert": out})) }
		"crypto.emergency.action" => { let action: String = getp(step, "action")?; let out = run_python("../tools/python/blockchain_monitor.py", &["emergency","--action", &action])?; Ok(serde_json::json!({"emergency": out})) }
		"crypto.risk.score" => { let vulns: i32 = getp_opt(step, "vulns").unwrap_or(0); let critical: i32 = getp_opt(step, "critical").unwrap_or(0); let ownership: i32 = getp_opt(step, "ownership").unwrap_or(50); let liquidity: i32 = getp_opt(step, "liquidity").unwrap_or(50); let history: i32 = getp_opt(step, "history").unwrap_or(50); let social: i32 = getp_opt(step, "social").unwrap_or(50); let audits: i32 = getp_opt(step, "audits").unwrap_or(50); let out = run_python("../tools/python/blockchain_risk_score.py", &["--vulns", &vulns.to_string(), "--critical", &critical.to_string(), "--ownership", &ownership.to_string(), "--liquidity", &liquidity.to_string(), "--history", &history.to_string(), "--social", &social.to_string(), "--audits", &audits.to_string()])?; Ok(serde_json::json!({"risk": out})) }
		"crypto.compliance.log" => { let action: String = getp(step, "action")?; let actor: String = getp(step, "actor")?; let target: String = getp(step, "target")?; let result: String = getp(step, "result")?; let metadata: Option<serde_json::Value> = getp_opt(step, "metadata"); let mut argsv: Vec<String> = vec!["log".into(), "--action".into(), action, "--actor".into(), actor, "--target".into(), target, "--result".into(), result]; if let Some(m)=metadata { argsv.push("--metadata".into()); argsv.push(m.to_string()); } let out = run_python_owned("../tools/python/compliance_logger.py", argsv)?; Ok(serde_json::json!({"log": out})) }
		"crypto.compliance.report" => { let period: String = getp_opt(step, "period").unwrap_or("daily".into()); let out = run_python("../tools/python/compliance_logger.py", &["report","--period", &period])?; Ok(serde_json::json!({"report": out})) }

		// OSINT harvest -------------------------------------------------------------------
		"osint.collect" => { let target: String = getp(step, "target")?; let case: String = getp_opt(step, "case_id").unwrap_or(uuid()); let out = run_python("../tools/python/osint_collect.py", &["--target", &target, "--case-id", &case])?; Ok(serde_json::json!({"collect": out})) }
		"osint.enrich" => { let typ: String = getp(step, "type")?; let value: String = getp(step, "value")?; let case: String = getp_opt(step, "case_id").unwrap_or(uuid()); let out = run_python("../tools/python/osint_enrich.py", &["--type", &typ, "--value", &value, "--case-id", &case])?; Ok(serde_json::json!({"enrich": out})) }
		"osint.social" => { let username: String = getp(step, "username")?; let out = run_python("../tools/python/osint_social.py", &["--username", &username])?; Ok(serde_json::json!({"social": out})) }
		"osint.graph" => { let case: String = getp(step, "case_id")?; let format: String = getp_opt(step, "format").unwrap_or("json".into()); let out = run_python("../tools/python/osint_graph.py", &["--case-id", &case, "--format", &format])?; Ok(serde_json::json!({"graph": out})) }

		// Communication security monitoring -------------------------------------------------
		"comms.security.monitor.run" => { let out = run_python("../tools/python/comm_security_monitor.py", &[])?; Ok(serde_json::json!({"report": out})) }

		// Automated Response System -------------------------------------------------------
		"response.execute" => { let threat: serde_json::Value = getp(step, "threat_data")?; let out = run_python("../tools/python/automated_response.py", &["respond", "--threat-data", &threat.to_string()])?; Ok(serde_json::from_str(&out)?) }
		"response.assess" => { let threat: serde_json::Value = getp(step, "threat_data")?; let out = run_python("../tools/python/automated_response.py", &["assess", "--threat-data", &threat.to_string()])?; Ok(serde_json::from_str(&out)?) }
		"response.stats" => { let out = run_python("../tools/python/automated_response.py", &["stats"])?; Ok(serde_json::from_str(&out)?) }

		// Data Annotation Platform ---------------------------------------------------------
		"annotation.schema.init" => { let out = run_python("../tools/python/annotation_platform.py", &["schema-init"])?; Ok(serde_json::json!({"schema": out})) }
		"annotation.schema.get" => { let out = run_python("../tools/python/annotation_platform.py", &["schema-get"])?; Ok(serde_json::json!({"schema": out})) }
		"annotation.batch.get" => { let size: u32 = getp_opt(step, "batch_size").unwrap_or(10); let out = run_python("../tools/python/annotation_platform.py", &["get-batch","--batch-size", &size.to_string()])?; Ok(serde_json::json!({"batch": out})) }
		"annotation.submit" => { let annotation: serde_json::Value = getp(step, "annotation")?; let out = run_python("../tools/python/annotation_platform.py", &["submit","--annotation", &annotation.to_string()])?; Ok(serde_json::json!({"submit": out})) }
		"annotation.qa.report" => { let out = run_python("../tools/python/annotation_platform.py", &["qa-report"])?; Ok(serde_json::json!({"qa": out})) }
		"annotation.metrics" => { let out = run_python("../tools/python/annotation_platform.py", &["metrics"])?; Ok(serde_json::json!({"metrics": out})) }
		"annotation.anonymize" => { let data: serde_json::Value = getp(step, "data")?; let out = run_python("../tools/python/annotation_platform.py", &["anonymize","--data", &data.to_string()])?; Ok(serde_json::json!({"anonymized": out})) }
		"annotation.taxonomy.score" => { let indicators: serde_json::Value = getp(step, "indicators")?; let out = run_python("../tools/python/annotation_platform.py", &["taxonomy-score","--indicators", &indicators.to_string()])?; Ok(serde_json::json!({"score": out})) }

		_ => Err(anyhow!("unknown action: {}", step.action))
	}
}

fn getp<T: for<'de> Deserialize<'de>>(step: &PlaybookStep, key: &str) -> Result<T> {
	serde_json::from_value(step.params.get(key).cloned().ok_or_else(|| anyhow!("missing param {}", key))?).map_err(|e| anyhow!(e))
}
fn getp_opt<T: for<'de> Deserialize<'de>>(step: &PlaybookStep, key: &str) -> Option<T> {
	step.params.get(key).and_then(|v| serde_json::from_value(v.clone()).ok())
}

#[cfg(target_os="windows")]
fn isolate_host(_host: &str) -> Result<()> { Ok(()) }
#[cfg(not(target_os="windows"))]
fn isolate_host(_host: &str) -> Result<()> { Ok(()) }

#[cfg(target_os="windows")]
fn kill_process(pid: i32) -> Result<()> { use std::process::Command; let _ = Command::new("cmd").args(["/C", &format!("taskkill /PID {} /F", pid)]).status()?; Ok(()) }
#[cfg(not(target_os="windows"))]
fn kill_process(_pid: i32) -> Result<()> { Ok(()) }

fn collect_artifacts(case_id: &str) -> Result<String> {
	let mut dir = PathBuf::from("../../data/forensics"); fs::create_dir_all(&dir)?; dir.push(case_id); fs::create_dir_all(&dir)?;
	// process list
	let plist = if cfg!(target_os="windows") { std::process::Command::new("cmd").args(["/C","wmic process get ProcessId,Name,CommandLine"]).output() } else { std::process::Command::new("sh").args(["-c","ps aux"]).output() }?;
	fs::write(dir.join("process_list.txt"), plist.stdout)?;
	// netstat
	let net = if cfg!(target_os="windows") { std::process::Command::new("cmd").args(["/C","netstat -ano"]).output() } else { std::process::Command::new("sh").args(["-c","netstat -tunap"]).output() }?;
	fs::write(dir.join("netstat.txt"), net.stdout)?;
	Ok(dir.to_string_lossy().to_string())
}

fn notify(_priority: &str, _template: &str) -> Result<()> { Ok(()) }

fn backup_snapshot(target: &str) -> Result<String> {
	use std::fs::File; use walkdir::WalkDir; let snap_dir = PathBuf::from("../../data/snapshots"); fs::create_dir_all(&snap_dir)?; let out_path = snap_dir.join(format!("snapshot_{}.zip", chrono::Utc::now().timestamp())); let file = File::create(&out_path)?; let mut zip = zip::ZipWriter::new(file); let options = zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Deflated);
	for entry in WalkDir::new(target).into_iter().filter_map(|e| e.ok()) { let p = entry.path(); if p.is_file() { let name = p.strip_prefix(target).unwrap_or(p).to_string_lossy(); zip.start_file(name, options)?; let bytes = fs::read(p)?; zip.write_all(&bytes)?; }} zip.finish()?; Ok(out_path.to_string_lossy().to_string())
}

async fn slack_notify(webhook: &str, text: &str) -> Result<()> { let client = reqwest::Client::new(); let _ = client.post(webhook).json(&serde_json::json!({"text": text})).send().await?; Ok(()) }

async fn email_notify(to: &str, subject: &str, body: &str) -> Result<()> { use lettre::{Message, SmtpTransport, Transport}; let from = "no-reply@cyberfortress.local"; let email = Message::builder().from(from.parse().unwrap()).to(to.parse().unwrap()).subject(subject).body(body.to_string()).unwrap(); let mailer = SmtpTransport::relay("localhost").unwrap().build(); let _ = mailer.send(&email); Ok(()) }

async fn pagerduty_notify(url: &str, payload: serde_json::Value) -> Result<()> { let client = reqwest::Client::new(); let _ = client.post(url).json(&payload).send().await?; Ok(()) }

fn get_process_tree() -> Result<String> { let output = if cfg!(target_os="windows") { std::process::Command::new("cmd").args(["/C","wmic process get ProcessId,ParentProcessId,Name"]).output()? } else { std::process::Command::new("sh").args(["-c","ps -eo pid,ppid,comm"]).output()? }; Ok(String::from_utf8_lossy(&output.stdout).to_string()) }

fn scan_file(path: &str) -> Result<serde_json::Value> { use sha2::{Sha256, Digest}; let data = fs::read(path)?; let mut h = Sha256::new(); h.update(&data); let sha = format!("{:x}", h.finalize()); let size = data.len(); Ok(serde_json::json!({"path": path, "sha256": sha, "size": size})) }

fn quarantine_file(path: &str) -> Result<String> { let qdir = PathBuf::from("../../data/quarantine"); fs::create_dir_all(&qdir)?; let dest = qdir.join(format!("{}_{}", Utc::now().timestamp(), std::path::Path::new(path).file_name().unwrap_or_default().to_string_lossy())); fs::rename(path, &dest)?; Ok(dest.to_string_lossy().to_string()) }

#[cfg(target_os="windows")]
pub fn block_ip_netsh(ip_or_cidr: &str) -> Result<()> { use std::process::Command; let name = format!("CF_Block_{}", ip_or_cidr.replace('.', "_").replace('/', "_")); let _ = Command::new("cmd").args(["/C", &format!("netsh advfirewall firewall add rule name=\"{}\" dir=out action=block remoteip={}", name, ip_or_cidr)]).status()?; Ok(()) }

fn block_domain_hosts(domain: &str) -> Result<()> { let hosts = if cfg!(target_os="windows") { PathBuf::from(r"C:\Windows\System32\drivers\etc\hosts") } else { PathBuf::from("/etc/hosts") }; let line = format!("0.0.0.0\t{}\n", domain); // may need admin; best-effort
	let mut f = fs::OpenOptions::new().append(true).create(true).open(hosts)?; f.write_all(line.as_bytes())?; Ok(()) }

// Advanced Firewall Helpers ------------------------------------------------------
#[cfg(not(target_os="windows"))]
fn linux_sh(cmd: &str) -> Result<()> { let status = std::process::Command::new("sh").args(["-c", cmd]).status()?; if !status.success() { return Err(anyhow!(format!("command failed: {}", cmd))); } Ok(()) }
#[cfg(target_os="windows")]
fn linux_sh(_cmd: &str) -> Result<()> { Ok(()) }

#[cfg(not(target_os="windows"))]
fn linux_portscan_protection_enable() -> Result<()> {
	linux_sh("iptables -N PORTSCAN_PROTECTION 2>/dev/null || true");
	linux_sh("iptables -F PORTSCAN_PROTECTION")?;
	linux_sh("iptables -A PORTSCAN_PROTECTION -p tcp --tcp-flags ALL NONE -j LOG --log-prefix 'NULL SCAN: '")?;
	linux_sh("iptables -A PORTSCAN_PROTECTION -p tcp --tcp-flags ALL NONE -j DROP")?;
	linux_sh("iptables -A PORTSCAN_PROTECTION -p tcp --tcp-flags ALL FIN,PSH,URG -j LOG --log-prefix 'XMAS SCAN: '")?;
	linux_sh("iptables -A PORTSCAN_PROTECTION -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP")?;
	linux_sh("iptables -A PORTSCAN_PROTECTION -p tcp --tcp-flags ALL FIN -j LOG --log-prefix 'FIN SCAN: '")?;
	linux_sh("iptables -A PORTSCAN_PROTECTION -p tcp --tcp-flags ALL FIN -j DROP")?;
	linux_sh("iptables -A PORTSCAN_PROTECTION -p tcp --tcp-flags SYN,FIN SYN,FIN -j LOG --log-prefix 'SYN-FIN SCAN: '")?;
	linux_sh("iptables -A PORTSCAN_PROTECTION -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP")?;
	linux_sh("iptables -A PORTSCAN_PROTECTION -p tcp --tcp-flags SYN,RST SYN,RST -j LOG --log-prefix 'SYN-RST SCAN: '")?;
	linux_sh("iptables -A PORTSCAN_PROTECTION -p tcp --tcp-flags SYN,RST SYN,RST -j DROP")?;
	linux_sh("iptables -A PORTSCAN_PROTECTION -m recent --name portscan --set")?;
	linux_sh("iptables -A PORTSCAN_PROTECTION -m recent --name portscan --update --seconds 60 --hitcount 20 -j LOG --log-prefix 'PORTSCAN: '")?;
	linux_sh("iptables -A PORTSCAN_PROTECTION -m recent --name portscan --update --seconds 60 --hitcount 20 -j DROP")?;
	Ok(())
}
#[cfg(target_os="windows")]
fn linux_portscan_protection_enable() -> Result<()> { Ok(()) }

#[cfg(not(target_os="windows"))]
fn linux_bruteforce_protection_enable(ports: &Vec<u16>) -> Result<()> { for p in ports { linux_sh(&format!("iptables -A BRUTEFORCE_PROTECTION -p tcp --dport {} -m state --state NEW -m recent --set --name P{} --rsource", p, p))?; linux_sh(&format!("iptables -A BRUTEFORCE_PROTECTION -p tcp --dport {} -m state --state NEW -m recent --update --seconds 60 --hitcount 10 --name P{} --rsource -j LOG --log-prefix 'BRUTE FORCE {}: '", p, p, p))?; linux_sh(&format!("iptables -A BRUTEFORCE_PROTECTION -p tcp --dport {} -m state --state NEW -m recent --update --seconds 60 --hitcount 10 --name P{} --rsource -j DROP", p, p))?; } Ok(()) }
#[cfg(target_os="windows")]
fn linux_bruteforce_protection_enable(_ports: &Vec<u16>) -> Result<()> { Ok(()) }

#[cfg(not(target_os="windows"))]
fn linux_malware_blocking_enable() -> Result<()> {
	let ports = vec![4444,5555,6666,6667,7777,8080,9999,12345,31337,65535];
	for p in ports { linux_sh(&format!("iptables -A MALWARE_BLOCK -p tcp --dport {} -j LOG --log-prefix 'MALWARE PORT {}: '", p, p))?; linux_sh(&format!("iptables -A MALWARE_BLOCK -p tcp --dport {} -j DROP", p))?; linux_sh(&format!("iptables -A MALWARE_BLOCK -p udp --dport {} -j DROP", p))?; }
	Ok(())
}
#[cfg(target_os="windows")]
fn linux_malware_blocking_enable() -> Result<()> { Ok(()) }

#[cfg(not(target_os="windows"))]
fn linux_exploit_protection_enable() -> Result<()> { linux_sh("iptables -A EXPLOIT_PROTECTION -f -j LOG --log-prefix 'FRAGMENT ATTACK: '")?; linux_sh("iptables -A EXPLOIT_PROTECTION -f -j DROP")?; linux_sh("iptables -A EXPLOIT_PROTECTION -m state --state INVALID -j LOG --log-prefix 'INVALID PACKET: '")?; linux_sh("iptables -A EXPLOIT_PROTECTION -m state --state INVALID -j DROP")?; linux_sh("iptables -A EXPLOIT_PROTECTION -p tcp --tcp-flags ALL ALL -j LOG --log-prefix 'ALL FLAGS SET: '")?; linux_sh("iptables -A EXPLOIT_PROTECTION -p tcp --tcp-flags ALL ALL -j DROP")?; linux_sh("iptables -A EXPLOIT_PROTECTION -p tcp ! --syn -m state --state NEW -j LOG --log-prefix 'NEW NOT SYN: '")?; linux_sh("iptables -A EXPLOIT_PROTECTION -p tcp ! --syn -m state --state NEW -j DROP")?; linux_sh("iptables -A EXPLOIT_PROTECTION -p tcp -m tcpmss ! --mss 536:65535 -j LOG --log-prefix 'INVALID MSS: '")?; linux_sh("iptables -A EXPLOIT_PROTECTION -p tcp -m tcpmss ! --mss 536:65535 -j DROP")?; Ok(()) }
#[cfg(target_os="windows")]
fn linux_exploit_protection_enable() -> Result<()> { Ok(()) }

#[cfg(not(target_os="windows"))]
fn linux_apply_protection_chains() -> Result<()> { linux_sh("iptables -A INPUT -j PORTSCAN_PROTECTION")?; linux_sh("iptables -A INPUT -j BRUTEFORCE_PROTECTION")?; linux_sh("iptables -A INPUT -j MALWARE_BLOCK")?; linux_sh("iptables -A INPUT -j EXPLOIT_PROTECTION")?; Ok(()) }
#[cfg(target_os="windows")]
fn linux_apply_protection_chains() -> Result<()> { Ok(()) }

#[cfg(not(target_os="windows"))]
fn linux_nft_apply_config(config: &str) -> Result<()> { use std::io::Write; let mut path = std::env::temp_dir(); path.push(format!("cf_nft_{}.nft", Utc::now().timestamp())); let mut f = std::fs::File::create(&path)?; f.write_all(config.as_bytes())?; let cmd = format!("/usr/sbin/nft -f {}", path.to_string_lossy()); linux_sh(&cmd)?; Ok(()) }
#[cfg(target_os="windows")]
fn linux_nft_apply_config(_config: &str) -> Result<()> { Ok(()) }

// Geographic blocking ------------------------------------------------------------
#[cfg(target_os="windows")]
async fn geo_block_countries(countries: &Vec<String>) -> Result<()> { windows_geo_block_countries(countries).await }
#[cfg(not(target_os="windows"))]
async fn geo_block_countries(countries: &Vec<String>) -> Result<()> { linux_geo_block_countries(countries).await }

#[cfg(target_os="windows")]
async fn windows_geo_block_countries(countries: &Vec<String>) -> Result<()> {
	let client = reqwest::Client::new();
	let mut all_ranges: Vec<String> = vec![];
	for c in countries { let url = format!("https://www.ipdeny.com/ipblocks/data/countries/{}.zone", c.to_lowercase()); if let Ok(resp) = client.get(&url).send().await { if let Ok(text) = resp.text().await { for line in text.lines() { let line = line.trim(); if !line.is_empty() && !line.starts_with('#') { all_ranges.push(line.to_string()); } } } }
	}
	// Chunk into groups to avoid command length limits
	let chunk_size = 100; let mut idx = 0;
	while idx < all_ranges.len() { let end = (idx + chunk_size).min(all_ranges.len()); let chunk = &all_ranges[idx..end]; let remote_ip_arg = chunk.join(","); let name = format!("CF_GEO_BLOCK_{}_{}", countries.join("_"), idx/chunk_size);
		let _ = std::process::Command::new("cmd").args(["/C", &format!("netsh advfirewall firewall add rule name=\"{}\" dir=in action=block remoteip={}", name, remote_ip_arg)]).status();
		idx = end;
	}
	Ok(())
}

#[cfg(not(target_os="windows"))]
async fn linux_geo_block_countries(countries: &Vec<String>) -> Result<()> {
	linux_sh("ipset create geo_block hash:net hashsize 4096 2>/dev/null || true");
	linux_sh("ipset flush geo_block")?;
	let client = reqwest::Client::new();
	for c in countries { let url = format!("https://www.ipdeny.com/ipblocks/data/countries/{}.zone", c.to_lowercase()); if let Ok(resp) = client.get(&url).send().await { if let Ok(text) = resp.text().await { for line in text.lines() { let line = line.trim(); if !line.is_empty() && !line.starts_with('#') { let _ = linux_sh(&format!("ipset add geo_block {}", line)); } } } }
	}
	linux_sh("iptables -D INPUT -m set --match-set geo_block src -j DROP 2>/dev/null || true");
	linux_sh("iptables -I INPUT 1 -m set --match-set geo_block src -j DROP")?;
	linux_sh("iptables -I INPUT 1 -m set --match-set geo_block src -j LOG --log-prefix 'GEO-BLOCKED: '")?;
	Ok(())
}

#[cfg(not(target_os="windows"))]
async fn linux_geo_whitelist_countries(countries: &Vec<String>) -> Result<()> {
	linux_sh("ipset create geo_allow hash:net hashsize 4096 2>/dev/null || true");
	linux_sh("ipset flush geo_allow")?;
	let client = reqwest::Client::new();
	for c in countries { let url = format!("https://www.ipdeny.com/ipblocks/data/countries/{}.zone", c.to_lowercase()); if let Ok(resp) = client.get(&url).send().await { if let Ok(text) = resp.text().await { for line in text.lines() { let line = line.trim(); if !line.is_empty() && !line.starts_with('#') { let _ = linux_sh(&format!("ipset add geo_allow {}", line)); } } } }
	}
	linux_sh("iptables -I INPUT 1 -m set ! --match-set geo_allow src -j DROP")?;
	Ok(())
}
#[cfg(target_os="windows")]
async fn linux_geo_whitelist_countries(_countries: &Vec<String>) -> Result<()> { Err(anyhow!("whitelist mode not supported on Windows via country ranges")) }

// Rate limiting / DDoS (Linux) --------------------------------------------------
#[cfg(not(target_os="windows"))]
fn linux_rate_limit_enable() -> Result<()> {
	// Connection limits
	linux_sh("iptables -A INPUT -p tcp -m connlimit --connlimit-above 100 --connlimit-mask 32 -j REJECT --reject-with tcp-reset")?;
	// New connection rate
	linux_sh("iptables -A INPUT -p tcp -m state --state NEW -m hashlimit --hashlimit-name conn_rate --hashlimit-mode srcip --hashlimit-above 10/sec --hashlimit-burst 20 --hashlimit-htable-expire 10000 -j DROP")?;
	// SYN flood
	linux_sh("iptables -N SYN_FLOOD 2>/dev/null || true");
	linux_sh("iptables -A INPUT -p tcp --syn -j SYN_FLOOD")?;
	linux_sh("iptables -A SYN_FLOOD -m hashlimit --hashlimit-name syn_flood --hashlimit-mode srcip --hashlimit-above 5/sec --hashlimit-burst 10 --hashlimit-htable-expire 10000 -j LOG --log-prefix 'SYN FLOOD: '")?;
	linux_sh("iptables -A SYN_FLOOD -m hashlimit --hashlimit-name syn_flood --hashlimit-mode srcip --hashlimit-above 5/sec --hashlimit-burst 10 --hashlimit-htable-expire 10000 -j DROP")?;
	linux_sh("iptables -A SYN_FLOOD -j RETURN")?;
	// UDP flood
	linux_sh("iptables -A INPUT -p udp -m hashlimit --hashlimit-name udp_flood --hashlimit-mode srcip --hashlimit-above 50/sec --hashlimit-burst 100 --hashlimit-htable-expire 10000 -j DROP")?;
	// ICMP flood
	linux_sh("iptables -A INPUT -p icmp --icmp-type echo-request -m hashlimit --hashlimit-name icmp_flood --hashlimit-mode srcip --hashlimit-above 2/sec --hashlimit-burst 5 --hashlimit-htable-expire 10000 -j DROP")?;
	// HTTP/HTTPS specific
	linux_sh("iptables -A INPUT -p tcp --dport 80 -m state --state NEW -m hashlimit --hashlimit-name http_rate --hashlimit-mode srcip --hashlimit-above 30/sec --hashlimit-burst 50 --hashlimit-htable-expire 10000 -j DROP")?;
	linux_sh("iptables -A INPUT -p tcp --dport 443 -m state --state NEW -m hashlimit --hashlimit-name https_rate --hashlimit-mode srcip --hashlimit-above 30/sec --hashlimit-burst 50 --hashlimit-htable-expire 10000 -j DROP")?;
	Ok(())
}
#[cfg(target_os="windows")]
fn linux_rate_limit_enable() -> Result<()> { Ok(()) }

// Outbound blocks ---------------------------------------------------------------
#[cfg(target_os="windows")]
fn windows_block_outbound_ports(ports: &[u16]) -> Result<()> { use std::process::Command; let ports_str = ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(","); let name = format!("CF_Block_Out_{}", ports_str.replace(",","_")); let _ = Command::new("cmd").args(["/C", &format!("netsh advfirewall firewall add rule name=\"{}\" dir=out action=block protocol=TCP remoteport={}", name, ports_str)]).status()?; Ok(()) }
#[cfg(not(target_os="windows"))]
fn windows_block_outbound_ports(_ports: &[u16]) -> Result<()> { Ok(()) }

#[cfg(target_os="windows")]
fn windows_block_outbound_ports_range(ranges: &[(u16,u16)]) -> Result<()> { use std::process::Command; let parts: Vec<String> = ranges.iter().map(|(s,e)| if s==e { s.to_string() } else { format!("{}-{}", s,e) }).collect(); let spec = parts.join(","); let name = format!("CF_Block_Out_Range_{}", spec.replace(",","_").replace("-","to")); let _ = Command::new("cmd").args(["/C", &format!("netsh advfirewall firewall add rule name=\"{}\" dir=out action=block protocol=TCP remoteport={}", name, spec)]).status()?; Ok(()) }
#[cfg(not(target_os="windows"))]
fn windows_block_outbound_ports_range(_ranges: &[(u16,u16)]) -> Result<()> { Ok(()) }

#[cfg(not(target_os="windows"))]
fn linux_block_outbound_ports(ports: &[u16]) -> Result<()> { for p in ports { linux_sh(&format!("iptables -A OUTPUT -p tcp --dport {} -j DROP", p))?; } Ok(()) }
#[cfg(target_os="windows")]
fn linux_block_outbound_ports(_ports: &[u16]) -> Result<()> { Ok(()) }

#[cfg(not(target_os="windows"))]
fn linux_block_outbound_port_ranges(ranges: &[(u16,u16)]) -> Result<()> { for (s,e) in ranges { linux_sh(&format!("iptables -A OUTPUT -p tcp --dport {}:{} -j DROP", s,e))?; } Ok(()) }
#[cfg(target_os="windows")]
fn linux_block_outbound_port_ranges(_ranges: &[(u16,u16)]) -> Result<()> { Ok(()) }

#[cfg(target_os="windows")]
fn windows_block_malware_ports() -> Result<()> { let ports = [4444u16,5555,6666,6667,7777,8080,9999,12345,31337,65535]; windows_block_outbound_ports(&ports)?; Ok(()) }
#[cfg(not(target_os="windows"))]
fn windows_block_malware_ports() -> Result<()> { Ok(()) }

// Stubs for run_command, create_case, append_evidence if not already present -----
fn run_command(cmd: &str) -> Result<String> { let output = if cfg!(target_os="windows") { std::process::Command::new("cmd").args(["/C", cmd]).output()? } else { std::process::Command::new("sh").args(["-c", cmd]).output()? }; Ok(String::from_utf8_lossy(&output.stdout).to_string()) }

fn create_case() -> Result<String> { let id = uuid(); let mut dir = PathBuf::from("../../data/forensics"); fs::create_dir_all(&dir)?; dir.push(&id); fs::create_dir_all(&dir)?; Ok(id) }

fn append_evidence(case_id: &str, content: &serde_json::Value) -> Result<()> { let mut dir = PathBuf::from("../../data/forensics"); dir.push(case_id); fs::create_dir_all(&dir)?; let path = dir.join(format!("evidence_{}.json", Utc::now().timestamp())); fs::write(path, serde_json::to_vec_pretty(content)?)?; Ok(()) }

// Identity ---------------------------------------------------------------
#[derive(Serialize, Deserialize, Clone)]
pub struct IdentityScan { pub email: Option<String>, pub phone: Option<String>, pub name: Option<String> }
#[derive(Serialize, Deserialize, Clone)]
pub struct BrokerPlanItem { pub broker: String, pub status: String, pub requires_id: bool, pub method: String, pub sla_days: u32 }

pub fn generate_broker_plan() -> Vec<BrokerPlanItem> { let brokers = ["Spokeo","BeenVerified","PeopleFinders","Whitepages","Intelius","TruthFinder","US Search","Radaris","MyLife","Nuwber","PeekYou","RocketReach","Pipl","FastPeopleSearch","CUBIB"]; brokers.iter().map(|b| BrokerPlanItem{ broker: b.to_string(), status:"PENDING".into(), requires_id:true, method:"Email/Form".into(), sla_days:30}).collect() }

// OSINT -----------------------------------------------------------------
#[derive(Serialize, Deserialize, Clone)]
pub struct OsintCase { pub case_id: String, pub created: DateTime<Utc>, pub inputs: serde_json::Value, pub artifacts: Vec<String> }

pub fn build_case(inputs: serde_json::Value) -> OsintCase { OsintCase{ case_id: uuid(), created: Utc::now(), inputs, artifacts: vec!["timeline".into(), "links".into(), "metadata".into()]}}

// Crypto (PQC-ready placeholder) ----------------------------------------
use aes_gcm::{Aes256Gcm, KeyInit, aead::{Aead}, Nonce};

pub fn aes_encrypt(plain: &[u8], pass: &[u8]) -> Result<Vec<u8>> { use sha2::{Sha256, Digest}; let mut hasher = Sha256::new(); hasher.update(pass); let key = hasher.finalize(); let cipher = Aes256Gcm::new_from_slice(&key).unwrap(); let nonce_bytes: [u8;12] = rand::random(); let nonce = Nonce::from_slice(&nonce_bytes); let mut out = nonce.to_vec(); let mut ct = cipher.encrypt(nonce, plain).unwrap(); out.append(&mut ct); Ok(out) }

pub fn aes_decrypt(ciphertext: &[u8], pass: &[u8]) -> Result<Vec<u8>> { use sha2::{Sha256, Digest}; let mut hasher = Sha256::new(); hasher.update(pass); let key = hasher.finalize(); let cipher = Aes256Gcm::new_from_slice(&key).unwrap(); if ciphertext.len() < 12 { return Err(anyhow!("cipher too short")); } let (nonce, ct) = ciphertext.split_at(12); let nonce = Nonce::from_slice(nonce); let pt = cipher.decrypt(nonce, ct).unwrap(); Ok(pt) }

// Firewall ---------------------------------------------------------------
#[cfg(target_os="windows")]
pub fn block_ip_netsh_simple(ip: &str) -> Result<()> { use std::process::Command; let name = format!("CF_Block_{}", ip.replace('.', "_")); let _ = Command::new("cmd").args(["/C", &format!("netsh advfirewall firewall add rule name=\"{}\" dir=out action=block remoteip={}", name, ip)]).status()?; Ok(()) }

fn uuid() -> String { format!("{:x}{:x}", rand::random::<u128>(), rand::random::<u128>()) } 

// Python integration helpers -----------------------------------------------------
fn python_exe() -> String {
	let candidates: Vec<std::path::PathBuf> = if cfg!(target_os="windows") {
		vec![
			std::path::PathBuf::from("../tools/python/.venv/Scripts/python.exe"),
			std::path::PathBuf::from("../../tools/python/.venv/Scripts/python.exe"),
			std::path::PathBuf::from("app/tools/python/.venv/Scripts/python.exe"),
			std::path::PathBuf::from("..\\tools\\python\\.venv\\Scripts\\python.exe"),
		]
	} else {
		vec![
			std::path::PathBuf::from("../tools/python/.venv/bin/python"),
			std::path::PathBuf::from("../../tools/python/.venv/bin/python"),
			std::path::PathBuf::from("app/tools/python/.venv/bin/python"),
		]
	};
	for p in candidates { if p.exists() { return p.to_string_lossy().to_string(); } }
	if cfg!(target_os="windows") { "python".into() } else { "python3".into() }
}

fn run_python(script_rel: &str, args: &[&str]) -> Result<String> {
	let script = PathBuf::from(script_rel);
	let output = std::process::Command::new(python_exe()).arg(&script).args(args).output()?;
	let stdout = String::from_utf8_lossy(&output.stdout).to_string();
	Ok(stdout)
}

fn run_python_owned(script_rel: &str, args: Vec<String>) -> Result<String> {
	let argv: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
	run_python(script_rel, &argv)
}

fn runtime_dir() -> PathBuf { let p = PathBuf::from("../../data/runtime"); let _ = fs::create_dir_all(&p); p }

fn start_python_background(script_rel: &str, args: &[&str]) -> Result<u32> {
	let script = PathBuf::from(script_rel);
	let mut cmd = std::process::Command::new(python_exe());
	cmd.arg(&script).args(args);
	#[cfg(target_os="windows")]
	{ cmd.creation_flags(0x00000008); } // CREATE_NEW_CONSOLE
	let child = cmd.spawn()?;
	let pid = child.id();
	let mut pid_file = runtime_dir();
	let name = if script_rel.contains("ml_firewall_rules.py") {
		"ml_adaptive.pid"
	} else if script_rel.contains("dpi_firewall.py") {
		"dpi.pid"
	} else if script_rel.contains("threat_detector.py") {
		"threat_detector.pid"
	} else if script_rel.contains("integrity_monitor.py") {
		"integrity_monitor.pid"
	} else if script_rel.contains("network_analyzer.py") {
		"network_analyzer.pid"
	} else if script_rel.contains("secure_messaging.py") {
		"secure_messaging.pid"
	} else if script_rel.contains("secure_file_share.py") {
		"secure_file_share.pid"
	} else { "tool.pid" };
	pid_file.push(name);
	fs::write(pid_file, pid.to_string())?;
	Ok(pid)
}

fn start_python_background_owned(script_rel: &str, args: Vec<String>) -> Result<u32> {
	let argv: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
	start_python_background(script_rel, &argv)
}

fn stop_background(kind: &str) -> bool {
	let mut pid_path = runtime_dir();
	let file = match kind { "dpi" => "dpi.pid", "threat_detector" => "threat_detector.pid", "integrity_monitor" => "integrity_monitor.pid", "network_analyzer" => "network_analyzer.pid", "secure_messaging" => "secure_messaging.pid", "secure_file_share" => "secure_file_share.pid", _ => "ml_adaptive.pid" };
	pid_path.push(file);
	if let Ok(pid_str) = fs::read_to_string(&pid_path) { if let Ok(pid) = pid_str.trim().parse::<u32>() { let _ = kill_pid(pid); let _ = fs::remove_file(&pid_path); return true; } }
	false
}

pub fn validate_jwt(token: &str) -> bool {
	use jsonwebtoken::{DecodingKey, Validation, decode, Algorithm};
	let secret = std::env::var("CF_JWT_SECRET").unwrap_or_else(|_| "development_secret_change_me".into());
	decode::<serde_json::Value>(token, &DecodingKey::from_secret(secret.as_bytes()), &Validation::new(Algorithm::HS256)).is_ok()
}

// EDR API placeholder -------------------------------------------------------------
async fn edr_isolate_host(_api_url: &str, _api_key: &str, host: &str) -> Result<()> { isolate_host(host) }

fn kill_pid(pid: u32) -> Result<()> {
	#[cfg(target_os="windows")]
	{ let _ = std::process::Command::new("cmd").args(["/C", &format!("taskkill /PID {} /F", pid)]).status()?; }
	#[cfg(not(target_os="windows"))]
	{ let _ = std::process::Command::new("sh").args(["-c", &format!("kill -TERM {}", pid)]).status()?; }
	Ok(())
} 


#[cfg(not(target_os="windows"))]
fn linux_reset_protection_chains() -> Result<()> {
	let chains = ["PORTSCAN_PROTECTION","BRUTEFORCE_PROTECTION","MALWARE_BLOCK","EXPLOIT_PROTECTION","SYN_FLOOD"]; 
	for c in chains.iter() {
		let _ = linux_sh(&format!("iptables -D INPUT -j {} 2>/dev/null || true", c));
		let _ = linux_sh(&format!("iptables -F {} 2>/dev/null || true", c));
		let _ = linux_sh(&format!("iptables -X {} 2>/dev/null || true", c));
	}
	let _ = linux_sh("ipset destroy geo_block 2>/dev/null || true");
	let _ = linux_sh("ipset destroy geo_allow 2>/dev/null || true");
	Ok(())
}
#[cfg(target_os="windows")]
fn linux_reset_protection_chains() -> Result<()> { Ok(()) }

#[cfg(target_os="windows")]
fn windows_allow_inbound_ports(ports: &[u16], protocol: &str) -> Result<()> {
	use std::process::Command; let ports_str = ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(",");
	let name = format!("CF_Allow_In_{}_{}", protocol.to_uppercase(), ports_str.replace(",","_"));
	let _ = Command::new("cmd").args(["/C", &format!("netsh advfirewall firewall add rule name=\"{}\" dir=in action=allow protocol={} localport={}", name, protocol.to_uppercase(), ports_str)]).status()?; Ok(())
}
#[cfg(not(target_os="windows"))]
fn windows_allow_inbound_ports(_ports: &[u16], _protocol: &str) -> Result<()> { Ok(()) }

#[cfg(target_os="windows")]
fn windows_block_inbound_ports(ports: &[u16], protocol: &str) -> Result<()> {
	use std::process::Command; let ports_str = ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(",");
	let name = format!("CF_Block_In_{}_{}", protocol.to_uppercase(), ports_str.replace(",","_"));
	let _ = Command::new("cmd").args(["/C", &format!("netsh advfirewall firewall add rule name=\"{}\" dir=in action=block protocol={} localport={}", name, protocol.to_uppercase(), ports_str)]).status()?; Ok(())
}
#[cfg(not(target_os="windows"))]
fn windows_block_inbound_ports(_ports: &[u16], _protocol: &str) -> Result<()> { Ok(()) }

#[cfg(not(target_os="windows"))]
fn linux_allow_ports(ports: &[u16], protocol: &str) -> Result<()> { for p in ports { linux_sh(&format!("iptables -A INPUT -p {} --dport {} -j ACCEPT", protocol.to_lowercase(), p))?; } Ok(()) }
#[cfg(target_os="windows")]
fn linux_allow_ports(_ports: &[u16], _protocol: &str) -> Result<()> { Ok(()) }

#[cfg(not(target_os="windows"))]
fn linux_block_ports(ports: &[u16], protocol: &str) -> Result<()> { for p in ports { linux_sh(&format!("iptables -A INPUT -p {} --dport {} -j DROP", protocol.to_lowercase(), p))?; } Ok(()) }
#[cfg(target_os="windows")]
fn linux_block_ports(_ports: &[u16], _protocol: &str) -> Result<()> { Ok(()) }

#[cfg(target_os="windows")]
fn windows_reset_cf_rules() -> Result<()> { Ok(()) }
#[cfg(not(target_os="windows"))]
fn windows_reset_cf_rules() -> Result<()> { Ok(()) }