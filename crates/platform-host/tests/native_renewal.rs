//! The certificate timer's service: a failed renewal run reads as the
//! timer failed, though the timer itself keeps going.

use platform_host::{
    Host, Unit,
    native::Native,
    runner::{Output, Program, Runner},
};

/// Answers `systemctl show` with `show`.
struct Show(&'static str);

impl Runner for Show {
    fn run(&self, _program: Program, args: &[&str]) -> std::io::Result<Output> {
        assert_eq!(args.last(), Some(&"openvibes-certificates.service"), "{args:?}");
        Ok(Output {
            status: 0,
            stdout: self.0.into(),
            stderr: String::new(),
        })
    }

    fn run_with_input(&self, program: Program, args: &[&str], _: &[u8]) -> std::io::Result<Output> {
        self.run(program, args)
    }
}

const TIMER: &str = "Id=openvibes-certificates.timer\nLoadState=loaded\nActiveState=active\n\
                     UnitFileState=enabled\nActiveEnterTimestamp=Sun 2026-09-27 09:00:00 UTC\n\n";

fn renewal(state: &'static str) -> String {
    let show = format!(
        "{TIMER}Id=openvibes-certificates.service\nLoadState=loaded\nActiveState={state}\n\
         UnitFileState=static\nActiveEnterTimestamp=\n"
    );
    let host = Native {
        runner: Show(Box::leak(show.into_boxed_str())),
    };
    let services = host.services().unwrap();
    assert_eq!(services.len(), 1, "the service is not a unit of its own");
    assert_eq!(services[0].unit, Unit::Certificates);
    services[0].active.clone()
}

#[test]
fn a_failed_renewal_run_shows_as_failed() {
    assert_eq!(renewal("failed"), "failed");
    assert_eq!(renewal("inactive"), "active");
}
