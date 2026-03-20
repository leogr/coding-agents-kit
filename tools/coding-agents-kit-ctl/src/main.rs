use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::{self, Command};

#[cfg(target_os = "linux")]
const SERVICE_NAME: &str = "coding-agents-kit";

fn default_prefix() -> PathBuf {
    let home = env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(home).join(".coding-agents-kit")
}

fn plugin_config_path(prefix: &PathBuf) -> PathBuf {
    prefix.join("config/falco.coding_agents_plugin.yaml")
}

fn claude_settings_path() -> PathBuf {
    let home = env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(home).join(".claude/settings.json")
}

fn interceptor_command(prefix: &PathBuf) -> String {
    let home = env::var("HOME").unwrap_or_default();
    let prefix_str = prefix.to_string_lossy();
    let default = format!("{home}/.coding-agents-kit");
    if prefix_str == default {
        // Use $HOME for portability in settings.json.
        "$HOME/.coding-agents-kit/bin/claude-interceptor".to_string()
    } else {
        format!("{}/bin/claude-interceptor", prefix_str)
    }
}

// ---------------------------------------------------------------------------
// Warnings
// ---------------------------------------------------------------------------

fn print_hook_warning() {
    eprintln!();
    eprintln!("  WARNING: The interceptor runs in fail-closed mode. When the hook is");
    eprintln!("  registered, ALL Claude Code tool calls will be BLOCKED if the");
    eprintln!("  coding-agents-kit service is not running or is temporarily unavailable");
    eprintln!("  (e.g., during config hot-reload or service restart).");
    eprintln!();
    eprintln!("  To unblock Claude Code, remove the hook:");
    eprintln!("    coding-agents-kit-ctl hook remove");
}

fn print_restart_warning() {
    eprintln!();
    eprintln!("  WARNING: Changing the config triggers a full Falco restart. During the");
    eprintln!("  restart (a few seconds), the broker is unavailable and ALL Claude Code");
    eprintln!("  tool calls will be BLOCKED (fail-closed). This is expected and temporary.");
}

// ---------------------------------------------------------------------------
// Hook management
// ---------------------------------------------------------------------------

fn hook_add(prefix: &PathBuf) {
    let path = claude_settings_path();
    let mut settings: serde_json::Value = if path.exists() {
        let data = fs::read_to_string(&path).unwrap_or_else(|e| {
            eprintln!("error reading {}: {e}", path.display());
            process::exit(1);
        });
        serde_json::from_str(&data).unwrap_or_else(|e| {
            eprintln!("error parsing {}: {e}", path.display());
            process::exit(1);
        })
    } else {
        serde_json::json!({})
    };

    let hook_cmd = interceptor_command(prefix);
    let hooks = settings
        .as_object_mut()
        .unwrap()
        .entry("hooks")
        .or_insert_with(|| serde_json::json!({}));
    let pre_tool = hooks
        .as_object_mut()
        .unwrap()
        .entry("PreToolUse")
        .or_insert_with(|| serde_json::json!([]));

    // Check if already registered.
    if let Some(arr) = pre_tool.as_array() {
        for group in arr {
            if let Some(group_hooks) = group.get("hooks").and_then(|h| h.as_array()) {
                for h in group_hooks {
                    if h.get("command")
                        .and_then(|c| c.as_str())
                        .map_or(false, |c| c.contains("claude-interceptor"))
                    {
                        println!("Hook already registered.");
                        return;
                    }
                }
            }
        }
    }

    pre_tool.as_array_mut().unwrap().push(serde_json::json!({
        "matcher": "",
        "hooks": [{"type": "command", "command": hook_cmd}]
    }));

    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let output = serde_json::to_string_pretty(&settings).unwrap();
    fs::write(&path, format!("{output}\n")).unwrap_or_else(|e| {
        eprintln!("error writing {}: {e}", path.display());
        process::exit(1);
    });
    println!("Hook registered in {}", path.display());
    print_hook_warning();
}

fn hook_remove() {
    let path = claude_settings_path();
    if !path.exists() {
        println!("No settings file found.");
        return;
    }

    let data = fs::read_to_string(&path).unwrap_or_else(|e| {
        eprintln!("error reading {}: {e}", path.display());
        process::exit(1);
    });
    let mut settings: serde_json::Value = serde_json::from_str(&data).unwrap_or_else(|e| {
        eprintln!("error parsing {}: {e}", path.display());
        process::exit(1);
    });

    let mut removed = false;
    if let Some(hooks) = settings.get_mut("hooks").and_then(|h| h.as_object_mut()) {
        if let Some(pre_tool) = hooks.get_mut("PreToolUse").and_then(|p| p.as_array_mut()) {
            pre_tool.retain(|group| {
                let dominated = group
                    .get("hooks")
                    .and_then(|h| h.as_array())
                    .map_or(false, |group_hooks| {
                        group_hooks.iter().any(|h| {
                            h.get("command")
                                .and_then(|c| c.as_str())
                                .map_or(false, |c| c.contains("claude-interceptor"))
                        })
                    });
                if dominated {
                    removed = true;
                }
                !dominated
            });
            // Clean up empty structures.
            if pre_tool.is_empty() {
                hooks.remove("PreToolUse");
            }
        }
        if hooks.is_empty() {
            settings.as_object_mut().unwrap().remove("hooks");
        }
    }

    if removed {
        let output = serde_json::to_string_pretty(&settings).unwrap();
        fs::write(&path, format!("{output}\n")).unwrap_or_else(|e| {
            eprintln!("error writing {}: {e}", path.display());
            process::exit(1);
        });
        println!("Hook removed from {}", path.display());
    } else {
        println!("No hook found to remove.");
    }
}

fn hook_status() {
    let path = claude_settings_path();
    if !path.exists() {
        println!("Not registered (no settings file).");
        return;
    }

    let data = fs::read_to_string(&path).unwrap_or_default();
    if data.contains("claude-interceptor") {
        println!("Registered.");
    } else {
        println!("Not registered.");
    }
}

// ---------------------------------------------------------------------------
// Mode management
// ---------------------------------------------------------------------------

fn mode_get(prefix: &PathBuf) {
    let config_path = plugin_config_path(prefix);
    let data = fs::read_to_string(&config_path).unwrap_or_else(|e| {
        eprintln!("error reading {}: {e}", config_path.display());
        process::exit(1);
    });

    // Simple YAML parsing: find the mode line under init_config.
    for line in data.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("mode:") {
            let mode = trimmed.trim_start_matches("mode:").trim();
            println!("{mode}");
            return;
        }
    }
    println!("enforcement");
}

fn mode_set(prefix: &PathBuf, mode: &str) {
    if mode != "enforcement" && mode != "monitor" {
        eprintln!("error: mode must be 'enforcement' or 'monitor'");
        process::exit(1);
    }

    let config_path = plugin_config_path(prefix);
    let data = fs::read_to_string(&config_path).unwrap_or_else(|e| {
        eprintln!("error reading {}: {e}", config_path.display());
        process::exit(1);
    });

    // Replace the mode line in the YAML. This preserves formatting and comments.
    let mut found = false;
    let new_data: String = data
        .lines()
        .map(|line| {
            let trimmed = line.trim();
            if trimmed.starts_with("mode:") {
                found = true;
                line.replace(trimmed, &format!("mode: {mode}"))
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";

    if !found {
        eprintln!("error: 'mode:' not found in {}", config_path.display());
        process::exit(1);
    }

    fs::write(&config_path, new_data).unwrap_or_else(|e| {
        eprintln!("error writing {}: {e}", config_path.display());
        process::exit(1);
    });

    println!("Mode set to: {mode}");
    println!("Falco will detect the config change and restart automatically.");
    print_restart_warning();
}

// ---------------------------------------------------------------------------
// Service management
// ---------------------------------------------------------------------------

fn warn_hook_still_registered() {
    let path = claude_settings_path();
    if path.exists() {
        let data = fs::read_to_string(&path).unwrap_or_default();
        if data.contains("claude-interceptor") {
            eprintln!();
            eprintln!("  WARNING: The interceptor hook is still registered in Claude Code.");
            eprintln!("  With the service stopped, ALL tool calls will be BLOCKED.");
            eprintln!("  Remove the hook manually if needed:");
            eprintln!("    coding-agents-kit-ctl hook remove");
        }
    }
}

#[cfg(target_os = "linux")]
fn systemctl(args: &[&str]) -> bool {
    Command::new("systemctl")
        .arg("--user")
        .args(args)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn service_start() {
    if systemctl(&["start", SERVICE_NAME]) {
        println!("Service started.");
    } else {
        eprintln!("Failed to start service.");
        process::exit(1);
    }
}

#[cfg(target_os = "linux")]
fn service_stop() {
    if systemctl(&["stop", SERVICE_NAME]) {
        println!("Service stopped.");
        warn_hook_still_registered();
    } else {
        eprintln!("Failed to stop service.");
        process::exit(1);
    }
}

#[cfg(target_os = "linux")]
fn service_enable() {
    if systemctl(&["enable", SERVICE_NAME]) {
        println!("Service enabled (auto-start on login).");
    } else {
        eprintln!("Failed to enable service.");
        process::exit(1);
    }
}

#[cfg(target_os = "linux")]
fn service_disable() {
    if systemctl(&["disable", SERVICE_NAME]) {
        println!("Service disabled.");
    } else {
        eprintln!("Failed to disable service.");
        process::exit(1);
    }
}

#[cfg(target_os = "linux")]
fn service_status() {
    let _ = Command::new("systemctl")
        .args(["--user", "status", SERVICE_NAME, "--no-pager"])
        .status();
}

#[cfg(target_os = "macos")]
const PLIST_LABEL: &str = "dev.falcosecurity.coding-agents-kit";

#[cfg(target_os = "macos")]
fn plist_path() -> PathBuf {
    let home = env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(home)
        .join("Library/LaunchAgents")
        .join(format!("{PLIST_LABEL}.plist"))
}

#[cfg(target_os = "macos")]
fn is_service_loaded() -> bool {
    Command::new("launchctl")
        .args(["list", PLIST_LABEL])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(target_os = "macos")]
fn service_start() {
    let plist = plist_path();
    if !plist.exists() {
        eprintln!("Plist not found: {}", plist.display());
        eprintln!("Is coding-agents-kit installed?");
        process::exit(1);
    }
    if is_service_loaded() {
        println!("Service already running.");
        return;
    }
    let ok = Command::new("launchctl")
        .args(["load", &plist.to_string_lossy()])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if ok {
        println!("Service started.");
    } else {
        eprintln!("Failed to start service.");
        process::exit(1);
    }
}

#[cfg(target_os = "macos")]
fn service_stop() {
    if !is_service_loaded() {
        println!("Service not running.");
        return;
    }
    let plist = plist_path();
    // launchctl unload stops the process and removes it from launchd.
    // This is the only reliable way to stop with KeepAlive enabled.
    let ok = Command::new("launchctl")
        .args(["unload", &plist.to_string_lossy()])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if ok {
        println!("Service stopped.");
        warn_hook_still_registered();
    } else {
        eprintln!("Failed to stop service.");
        process::exit(1);
    }
}

#[cfg(target_os = "macos")]
fn service_enable() {
    let plist = plist_path();
    if !plist.exists() {
        eprintln!("Plist not found: {}", plist.display());
        eprintln!("Is coding-agents-kit installed?");
        process::exit(1);
    }
    // On macOS, the plist has RunAtLoad=true, so loading it both
    // enables auto-start and starts the service immediately.
    if !is_service_loaded() {
        let ok = Command::new("launchctl")
            .args(["load", &plist.to_string_lossy()])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok {
            eprintln!("Failed to enable service.");
            process::exit(1);
        }
    }
    println!("Service enabled (auto-start on login).");
}

#[cfg(target_os = "macos")]
fn service_disable() {
    let plist = plist_path();
    // -w writes a persistent override to not load at login.
    let ok = Command::new("launchctl")
        .args(["unload", "-w", &plist.to_string_lossy()])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if ok {
        println!("Service disabled.");
    } else {
        eprintln!("Failed to disable service.");
        process::exit(1);
    }
}

#[cfg(target_os = "macos")]
fn service_status() {
    if is_service_loaded() {
        println!("Service running.");
        let _ = Command::new("launchctl")
            .args(["list", PLIST_LABEL])
            .status();
    } else {
        println!("Service not running.");
    }
}

// ---------------------------------------------------------------------------
// Uninstall
// ---------------------------------------------------------------------------

fn uninstall(prefix: &PathBuf, keep_user_rules: bool) {
    println!("=== Uninstalling coding-agents-kit ===");
    println!("  Prefix: {}", prefix.display());
    println!();

    // 1. Stop the service.
    #[cfg(target_os = "linux")]
    {
        let _ = Command::new("systemctl")
            .args(["--user", "stop", SERVICE_NAME])
            .status();
        let _ = Command::new("systemctl")
            .args(["--user", "disable", SERVICE_NAME])
            .status();
        let service_file = PathBuf::from(env::var("HOME").unwrap_or_default())
            .join(".config/systemd/user/coding-agents-kit.service");
        if service_file.exists() {
            println!("Removing systemd service...");
            let _ = fs::remove_file(&service_file);
            let _ = Command::new("systemctl")
                .args(["--user", "daemon-reload"])
                .status();
        }
    }
    #[cfg(target_os = "macos")]
    {
        let plist = plist_path();
        if is_service_loaded() {
            println!("Stopping service...");
            let _ = Command::new("launchctl")
                .args(["unload", &plist.to_string_lossy()])
                .status();
        }
        if plist.exists() {
            println!("Removing launchd plist...");
            let _ = fs::remove_file(&plist);
        }
    }

    // 2. Remove the hook.
    println!("Removing Claude Code hook...");
    hook_remove();

    // 3. Remove the installation directory.
    if prefix.exists() {
        if keep_user_rules {
            let user_rules = prefix.join("rules/user");
            if user_rules.is_dir() {
                println!("Preserving user rules: {}", user_rules.display());
                // Remove everything except rules/user/.
                if let Ok(entries) = fs::read_dir(prefix) {
                    for entry in entries.flatten() {
                        let name = entry.file_name();
                        if name != "rules" {
                            let _ = fs::remove_dir_all(entry.path());
                        }
                    }
                }
                // Inside rules/, remove everything except user/.
                let rules_dir = prefix.join("rules");
                if let Ok(entries) = fs::read_dir(&rules_dir) {
                    for entry in entries.flatten() {
                        let name = entry.file_name();
                        if name != "user" {
                            let _ = fs::remove_dir_all(entry.path());
                        }
                    }
                }
            }
        } else {
            println!("Removing {}...", prefix.display());
            let _ = fs::remove_dir_all(prefix);
        }
    }

    println!();
    println!("=== Uninstall complete ===");
}

// ---------------------------------------------------------------------------
// Logs
// ---------------------------------------------------------------------------

fn logs(prefix: &PathBuf, stderr: bool) {
    let file = if stderr { "falco.err" } else { "falco.log" };
    let path = prefix.join("log").join(file);
    if !path.exists() {
        eprintln!("Log file not found: {}", path.display());
        eprintln!("Is the service running?");
        process::exit(1);
    }
    let status = Command::new("tail")
        .args(["-f", &path.to_string_lossy()])
        .status();
    if let Err(e) = status {
        eprintln!("Failed to tail log: {e}");
        process::exit(1);
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn print_usage() {
    eprintln!("coding-agents-kit-ctl — manage the coding-agents-kit service");
    eprintln!();
    eprintln!("Usage: coding-agents-kit-ctl [--prefix=PATH] <command>");
    eprintln!();
    eprintln!("Commands:");
    eprintln!("  hook add         Register the interceptor hook in Claude Code");
    eprintln!("  hook remove      Remove the interceptor hook from Claude Code");
    eprintln!("  hook status      Check if the hook is registered");
    eprintln!();
    eprintln!("  mode             Show current operational mode");
    eprintln!("  mode enforcement Switch to enforcement mode (deny/ask enforced)");
    eprintln!("  mode monitor     Switch to monitor mode (all verdicts allow, alerts logged)");
    eprintln!();
    eprintln!("  start            Start the service");
    eprintln!("  stop             Stop the service");
    eprintln!("  enable           Enable service auto-start on login");
    eprintln!("  disable          Disable service auto-start");
    eprintln!("  status           Show service status");
    eprintln!("  logs             Follow Falco stdout logs (tail -f)");
    eprintln!("  logs --err       Follow Falco stderr logs");
    eprintln!();
    eprintln!("  uninstall        Remove coding-agents-kit completely");
    eprintln!("  uninstall --keep-user-rules  Uninstall but preserve custom rules");
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut prefix = default_prefix();
    let mut cmd_args: Vec<&str> = Vec::new();

    // Parse global flags.
    for arg in &args[1..] {
        if let Some(p) = arg.strip_prefix("--prefix=") {
            prefix = PathBuf::from(p);
        } else if arg == "--help" || arg == "-h" {
            print_usage();
            process::exit(0);
        } else {
            cmd_args.push(arg);
        }
    }

    if cmd_args.is_empty() {
        print_usage();
        process::exit(1);
    }

    match cmd_args.as_slice() {
        ["hook", "add"] => hook_add(&prefix),
        ["hook", "remove"] => hook_remove(),
        ["hook", "status"] => hook_status(),
        ["mode"] => mode_get(&prefix),
        ["mode", mode] => mode_set(&prefix, mode),
        ["start"] => service_start(),
        ["stop"] => service_stop(),
        ["enable"] => service_enable(),
        ["disable"] => service_disable(),
        ["status"] => service_status(),
        ["logs"] => logs(&prefix, false),
        ["logs", "--err"] => logs(&prefix, true),
        ["uninstall"] => uninstall(&prefix, false),
        ["uninstall", "--keep-user-rules"] => uninstall(&prefix, true),
        _ => {
            eprintln!("Unknown command: {}", cmd_args.join(" "));
            eprintln!();
            print_usage();
            process::exit(1);
        }
    }
}
