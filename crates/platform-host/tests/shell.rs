//! Maintenance › Shell's host side: whose shell opens, and whom the
//! journal names. The spawn itself is checked in the lab.

use std::cell::RefCell;

use platform_host::{
    Host, Privileged, Secret,
    native::Native,
    runner::{Output, Program, Runner},
    shell::{operator, operator_of, shell_argv, valid_user},
};

/// Every call succeeds with `done<TAB>opened`; records every call.
struct FakeRunner {
    calls: RefCell<Vec<Vec<String>>>,
}

impl Runner for FakeRunner {
    fn run(&self, program: Program, args: &[&str]) -> std::io::Result<Output> {
        let mut call = vec![program.path().to_owned()];
        call.extend(args.iter().map(|a| (*a).to_owned()));
        self.calls.borrow_mut().push(call);
        Ok(Output {
            status: 0,
            stdout: "done\topened\n".into(),
            stderr: String::new(),
        })
    }

    fn run_with_input(&self, program: Program, args: &[&str], _: &[u8]) -> std::io::Result<Output> {
        self.run(program, args)
    }
}

const PASSWD: &str = "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/zsh\n";

#[test]
fn shell_runs_the_sudo_users_login_shell() {
    let argv = |uid, sudo, shell| shell_argv(uid, sudo, shell).unwrap();
    assert_eq!(
        argv(0, Some("alice"), ""),
        ["/usr/sbin/runuser", "-l", "alice"]
    );
    assert_eq!(argv(1000, None, "/bin/zsh"), ["/bin/zsh", "-l"]);
    // A user that has used sudo still gets their own shell, not runuser.
    assert_eq!(argv(1000, Some("alice"), "/bin/zsh"), ["/bin/zsh", "-l"]);
    // Root logged in directly, or sudo run by root: root's own shell.
    assert_eq!(argv(0, None, "/bin/bash"), ["/bin/bash", "-l"]);
    assert_eq!(argv(0, Some("root"), "/bin/bash"), ["/bin/bash", "-l"]);
    assert_eq!(argv(1000, None, ""), ["/bin/sh", "-l"]);
}

#[test]
fn a_malformed_sudo_user_opens_no_shell() {
    // Under sudo it is never root's shell instead (ruling 5).
    for bad in ["-c", "", "Bob", "a b", &"a".repeat(33)] {
        let error = shell_argv(0, Some(bad), "/bin/bash").unwrap_err();
        assert!(
            error
                .to_string()
                .contains("cannot tell whose shell to open"),
            "{bad:?}: {error}"
        );
    }
}

#[test]
fn names_are_checked_like_setups_operator() {
    for good in ["alice", "_svc", "a.b-c9"] {
        assert!(valid_user(good), "{good}");
    }
    for bad in ["", "root", "-c", "9a", "Alice", "a b", &"a".repeat(33)] {
        assert!(!valid_user(bad), "{bad:?}");
    }
}

#[test]
fn the_journal_trusts_sudo_user_only_as_root() {
    // alice runs `SUDO_USER=bob openvibes-admin`: not root, so not bob.
    assert_eq!(
        operator_of(Some(1000), Some(1000), Some("bob"), PASSWD),
        "alice"
    );
    // Under sudo, the person who ran it.
    assert_eq!(
        operator_of(Some(0), Some(0), Some("alice"), PASSWD),
        "alice"
    );
    // A malformed name is not trusted: the real uid's name.
    assert_eq!(operator_of(Some(0), Some(0), Some("-c"), PASSWD), "root");
    // A uid without a passwd line (a directory user): its number.
    assert_eq!(
        operator_of(Some(1234), Some(1234), None, PASSWD),
        "uid=1234"
    );
    assert_eq!(operator_of(None, None, Some("bob"), PASSWD), "unknown");
}

#[test]
fn the_shell_open_verb_is_journalled_with_the_operator() {
    let host = Native {
        runner: FakeRunner {
            calls: RefCell::new(Vec::new()),
        },
    };
    let operator = operator();
    assert!(
        !operator.is_empty() && !operator.contains(' '),
        "{operator}"
    );
    assert_eq!(Privileged::ShellOpen.args(), ["shell-open"]);
    assert_eq!(
        Privileged::ShellOpen.journal(),
        format!("shell-open {operator}")
    );
    host.privileged(Privileged::ShellOpen, &Secret::new("pw".into()))
        .unwrap();
    let calls = host.runner.calls.borrow();
    let journal = calls
        .iter()
        .find(|call| call[0] == "/usr/bin/logger")
        .unwrap();
    assert!(
        journal[3].ends_with(&format!(" shell-open {operator} ok")),
        "{journal:?}"
    );
    assert!(
        calls.iter().any(|call| call
            .ends_with(&["audit", "note", "shell-open", &operator, "ok"].map(String::from))),
        "{calls:?}"
    );
}
