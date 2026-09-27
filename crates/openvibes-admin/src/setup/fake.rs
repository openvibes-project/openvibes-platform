//! A scripted `Runner` and a temp root directory for the step tests.

use std::{
    cell::RefCell,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    time::Duration,
};

use platform_host::runner::{Output, Program, Runner};

use super::{
    Ctx,
    plan::{CaMode, Component, Plan},
};

type Effect = Box<dyn Fn(&Path)>;
/// (argv prefix, output, side effect on the root).
type Answer = (Vec<String>, Output, Option<Effect>);

pub struct Fake {
    pub root: PathBuf,
    pub calls: RefCell<Vec<Vec<String>>>,
    pub inputs: RefCell<Vec<String>>,
    answers: RefCell<Vec<Answer>>,
}

/// Users and groups the steps look up; all map to the test's own ids, so
/// chown succeeds without root.
const ACCOUNTS: [&str; 9] = [
    "root",
    "postgres",
    "alice",
    "openvibes-admin",
    "openvibes-ingest",
    "openvibes-distribution",
    "openvibes-console",
    "openvibes_agent",
    "openvibes-operators",
];

impl Fake {
    pub fn new(test: &str) -> Fake {
        let root = std::env::temp_dir().join(format!("ov-setup-{}-{test}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("etc")).unwrap();
        let meta = std::fs::metadata(&root).unwrap();
        let (uid, gid) = (meta.uid(), meta.gid());
        let passwd: String = ACCOUNTS
            .iter()
            .map(|n| format!("{n}:x:{uid}:{gid}::/:/sbin/nologin\n"))
            .collect();
        let group: String = ACCOUNTS.iter().map(|n| format!("{n}:x:{gid}:\n")).collect();
        std::fs::write(root.join("etc/passwd"), passwd).unwrap();
        std::fs::write(root.join("etc/group"), group).unwrap();
        Fake {
            root,
            calls: RefCell::new(Vec::new()),
            inputs: RefCell::new(Vec::new()),
            answers: RefCell::new(Vec::new()),
        }
    }

    /// Calls starting with `prefix` exit with `status` and print `stdout`.
    /// The first matching answer wins, so add specific ones first.
    pub fn answer(&self, prefix: &[&str], status: i32, stdout: &str) {
        self.answers.borrow_mut().push((
            prefix.iter().map(|s| (*s).to_owned()).collect(),
            Output {
                status,
                stdout: stdout.into(),
                stderr: if status == 0 {
                    String::new()
                } else {
                    format!("{} failed", prefix.join(" "))
                },
            },
            None,
        ));
    }

    /// Calls starting with `prefix` succeed and run `effect` on the root.
    pub fn effect(&self, prefix: &[&str], effect: impl Fn(&Path) + 'static) {
        self.answers.borrow_mut().push((
            prefix.iter().map(|s| (*s).to_owned()).collect(),
            Output::default(),
            Some(Box::new(effect)),
        ));
    }

    pub fn file(&self, abs: &str, text: &str) {
        let path = self.root.join(abs.trim_start_matches('/'));
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    pub fn text(&self, abs: &str) -> String {
        std::fs::read_to_string(self.root.join(abs.trim_start_matches('/'))).unwrap()
    }

    pub fn called(&self, prefix: &[&str]) -> bool {
        self.calls.borrow().iter().any(|call| starts(call, prefix))
    }

    /// The first call starting with `prefix`.
    pub fn call(&self, prefix: &[&str]) -> Vec<String> {
        let calls = self.calls.borrow();
        calls
            .iter()
            .find(|call| starts(call, prefix))
            .cloned()
            .unwrap_or_else(|| panic!("no call {prefix:?} in {calls:?}"))
    }

    pub fn ctx<'a>(&'a self, plan: &'a Plan) -> Ctx<'a, Fake> {
        Ctx {
            runner: self,
            plan,
            root: &self.root,
            pause: Duration::ZERO,
            repair: false,
        }
    }
}

fn starts<S: AsRef<str>>(call: &[String], prefix: &[S]) -> bool {
    call.len() >= prefix.len() && call.iter().zip(prefix).all(|(a, b)| a == b.as_ref())
}

impl Runner for Fake {
    fn run(&self, program: Program, args: &[&str]) -> std::io::Result<Output> {
        let mut call = vec![program.path().to_owned()];
        call.extend(args.iter().map(|a| (*a).to_owned()));
        self.calls.borrow_mut().push(call.clone());
        for (prefix, out, effect) in self.answers.borrow().iter() {
            if starts(&call, prefix) {
                if let Some(effect) = effect {
                    effect(&self.root);
                }
                return Ok(out.clone());
            }
        }
        Ok(Output {
            status: 1,
            stdout: String::new(),
            stderr: "unexpected call".into(),
        })
    }

    fn run_with_input(
        &self,
        program: Program,
        args: &[&str],
        input: &[u8],
    ) -> std::io::Result<Output> {
        self.inputs
            .borrow_mut()
            .push(String::from_utf8_lossy(input).into_owned());
        self.run(program, args)
    }
}

/// A plan for tests: platform.example.com, 10.0.0.5, quick CA, run by alice.
pub fn plan(components: &[Component]) -> Plan {
    let mut components = components.to_vec();
    components.sort();
    Plan {
        components,
        hostname: "platform.example.com".into(),
        sans: vec!["10.0.0.5".into()],
        ca: CaMode::Quick,
        root_key_out: None,
        admin_password_file: None,
        repo_dir: None,
        allow_unsigned_local: false,
        operator: Some("alice".into()),
    }
}
