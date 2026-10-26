//! `ca-import` through sudo: the bundle follows the password line on stdin.

use std::cell::RefCell;

use platform_host::{
    Host, Privileged, Secret,
    native::Native,
    runner::{Output, Program, Runner},
};

/// Records each call and its stdin; every call succeeds.
#[derive(Default)]
struct Recording {
    calls: RefCell<Vec<Vec<String>>>,
    inputs: RefCell<Vec<Vec<u8>>>,
}

impl Runner for Recording {
    fn run(&self, program: Program, args: &[&str]) -> std::io::Result<Output> {
        let mut call = vec![program.path().to_owned()];
        call.extend(args.iter().map(|a| (*a).to_owned()));
        self.calls.borrow_mut().push(call);
        Ok(Output::default())
    }

    fn run_with_input(
        &self,
        program: Program,
        args: &[&str],
        input: &[u8],
    ) -> std::io::Result<Output> {
        self.inputs.borrow_mut().push(input.to_vec());
        self.run(program, args)
    }
}

#[test]
fn ca_import_sends_the_bundle_after_the_password_line() {
    let host = Native {
        runner: Recording::default(),
    };
    let bundle = Secret::new("CERT\n-----BEGIN PRIVATE KEY-----\nK\n".into());
    host.privileged(Privileged::CaImport(&bundle), &Secret::new("pw".into()))
        .unwrap();
    assert_eq!(
        *host.runner.inputs.borrow(),
        [b"pw\nCERT\n-----BEGIN PRIVATE KEY-----\nK\n".to_vec()]
    );
    let calls = host.runner.calls.borrow();
    assert_eq!(
        calls[0][1..],
        [
            "-S",
            "-k",
            "-p",
            "",
            "/usr/bin/openvibes-admin",
            "helper",
            "ca-import"
        ]
    );
    assert!(
        calls.iter().flatten().all(|arg| !arg.contains("PRIVATE")),
        "{calls:?}"
    );
}
