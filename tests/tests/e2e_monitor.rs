use std::sync::OnceLock;

use cak_tests::e2e::E2eHarness;
use cak_tests::interceptor::assert_decision;

static HARNESS: OnceLock<Option<E2eHarness>> = OnceLock::new();

fn harness() -> &'static E2eHarness {
    let opt = HARNESS.get_or_init(|| E2eHarness::start("monitor"));
    opt.as_ref().expect("falco + plugin required for e2e monitor tests")
}

fn falco_available() -> bool {
    HARNESS.get_or_init(|| E2eHarness::start("monitor")).is_some()
}

macro_rules! require_falco {
    () => {
        if !falco_available() {
            eprintln!("SKIP: falco or plugin not available");
            return;
        }
    };
}

fn cwd() -> &'static str {
    if cfg!(windows) {
        "C:/Users/test/project"
    } else {
        "/tmp/myproject"
    }
}

#[test]
fn monitor_rm_rf_allowed() {
    require_falco!();
    let h = harness();
    let input = E2eHarness::make_input("Bash", r#"{"command":"rm -rf /"}"#, cwd(), "mon-rm");
    let r = h.run_hook(&input);
    assert_decision(&r, "allow");
}

#[test]
fn monitor_write_sensitive_allowed() {
    require_falco!();
    let h = harness();
    let path = if cfg!(windows) {
        "C:/Windows/system.ini"
    } else {
        "/etc/passwd"
    };
    let input = E2eHarness::make_input(
        "Write",
        &format!(r#"{{"file_path":"{}","content":"x"}}"#, path),
        cwd(),
        "mon-wsen",
    );
    let r = h.run_hook(&input);
    assert_decision(&r, "allow");
}

#[test]
fn monitor_write_outside_cwd_allowed() {
    require_falco!();
    let h = harness();
    let path = if cfg!(windows) {
        "C:/Users/other/file.txt"
    } else {
        "/home/other/file.txt"
    };
    let input = E2eHarness::make_input(
        "Write",
        &format!(r#"{{"file_path":"{}","content":"x"}}"#, path),
        cwd(),
        "mon-wout",
    );
    let r = h.run_hook(&input);
    assert_decision(&r, "allow");
}

#[test]
fn monitor_safe_command_allowed() {
    require_falco!();
    let h = harness();
    let input = E2eHarness::make_input("Bash", r#"{"command":"ls -la"}"#, cwd(), "mon-ls");
    let r = h.run_hook(&input);
    assert_decision(&r, "allow");
}
