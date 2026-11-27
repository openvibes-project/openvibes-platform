//! Update OpenVIBES on the appliance (#674; updates.py, approved.md 61):
//! the release comes from GitHub as one signed update file, not from dnf.
//! Opening the page (and Check again) asks the helper's `update-check`;
//! Update now downloads the file and checks its signature first, then the
//! usual six steps.

use chrono::Local;
use platform_host::{Host, StepState};
use ratatui::text::{Line, Span};

use crate::tui::{
    app::App,
    run::{Call, Kind, Run, Work},
};

/// The first steps of an update on the appliance.
pub const FETCH_STEPS: [&str; 2] = ["Download the update file", "Check its signature"];

/// The latest release's update file, as `update-check` said it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Release {
    pub version: String,
    pub published: String,
    pub size: u64,
    pub new: String,
}

/// What the last check found, and when.
#[derive(Clone, Debug, Default)]
pub struct Checked {
    /// `None` while it runs; `Ok(None)`: no update file in the latest release.
    pub found: Option<Result<Option<Release>, String>>,
    /// `HH:MM` of the last answer.
    pub at: String,
}

/// `VERSION<TAB>DATE<TAB>BYTES<TAB>NEW`, or `none`.
pub fn parse(detail: &str) -> Option<Option<Release>> {
    if detail == "none" {
        return Some(None);
    }
    let mut parts = detail.splitn(4, '\t');
    let version = parts.next()?.to_owned();
    crate::setup::appliance_update::check_version(&version).ok()?;
    Some(Some(Release {
        version,
        published: parts.next()?.to_owned(),
        size: parts.next()?.parse().ok()?,
        new: parts.next().unwrap_or_default().to_owned(),
    }))
}

/// `0.3.3` newer than `0.3.2`: numeric parts first, then the text.
// ponytail: a pre-release suffix compares as text; enough for our tags.
pub fn newer(candidate: &str, installed: &str) -> bool {
    let key = |v: &str| -> Vec<u64> {
        v.split(['.', '-'])
            .map(|p| p.parse().unwrap_or(0))
            .collect()
    };
    key(candidate) > key(installed)
}

pub fn check_work() -> Work {
    Work::new(Kind::Release, vec![Call::UpdateCheck])
}

/// The two calls an appliance update starts with.
pub fn fetch_calls(release: &Release) -> Vec<Call> {
    vec![
        Call::UpdateFetch(release.version.clone(), Some(release.size)),
        Call::UpdateUse(release.version.clone()),
    ]
}

/// How many calls of `run` are the download and its check.
pub fn fetched(run: &Run) -> usize {
    run.work
        .calls
        .iter()
        .take_while(|c| matches!(c, Call::UpdateFetch(..) | Call::UpdateUse(_)))
        .count()
}

fn megabytes(bytes: u64) -> u64 {
    bytes.div_ceil(1_000_000)
}

impl<H: Host> App<H> {
    /// The release the page offers, when newer than this one.
    pub(super) fn release(&self) -> Option<&Release> {
        match &self.maint.release.found {
            Some(Ok(Some(release))) if newer(&release.version, env!("CARGO_PKG_VERSION")) => {
                Some(release)
            }
            _ => None,
        }
    }

    /// Asks GitHub again (opening the page, Check again).
    pub(super) fn check_release(&mut self) {
        if self.run.as_ref().is_some_and(Run::running) {
            return;
        }
        self.maint.release.found = None;
        self.begin(check_work(), 0);
    }

    /// A finished check becomes the page's lines; its run goes. It is a
    /// background read: its run is in `load`, not `run`.
    pub(super) fn release_ended(&mut self) {
        let Some(run) = self.load.as_ref().filter(|r| r.work.kind == Kind::Release) else {
            return;
        };
        if run.running() {
            return;
        }
        let state = run.states.first().and_then(Option::as_ref);
        let found = match state {
            Some(StepState::Done(detail)) => {
                parse(detail).ok_or_else(|| format!("unexpected answer: {detail}"))
            }
            Some(state) => Err(state.detail().trim_start_matches("failed: ").to_owned()),
            None => Err("no answer".into()),
        };
        self.update = match &found {
            Ok(Some(r)) if newer(&r.version, env!("CARGO_PKG_VERSION")) => Some(r.version.clone()),
            _ => None,
        };
        self.maint.release = Checked {
            found: Some(found),
            at: Local::now().format("%H:%M").to_string(),
        };
        self.load = None;
    }

    /// The page's two lines on the appliance (updates.py #7, #11).
    pub(super) fn release_info(&self) -> Vec<Line<'static>> {
        let t = &self.theme;
        let installed = Span::raw(format!("    v{} installed · ", env!("CARGO_PKG_VERSION")));
        let checked = Span::styled(format!(" · checked {}", self.maint.release.at), t.dim());
        let (first, second) = match (&self.maint.release.found, self.release()) {
            (None, _) => (
                vec![
                    installed,
                    Span::styled("asking GitHub for the newest release…", t.dim()),
                ],
                String::new(),
            ),
            (Some(Err(_)), _) => (
                vec![
                    installed,
                    Span::styled("GitHub cannot be reached", t.red()),
                    checked,
                ],
                "No network, or it blocks github.com. Appliance settings › Network shows it."
                    .into(),
            ),
            (Some(Ok(_)), Some(r)) => (
                vec![
                    installed,
                    Span::styled(format!("{} available", r.version), t.yellow()),
                    Span::styled(format!(" · released {}", r.published), t.dim()),
                    checked,
                ],
                if r.new.is_empty() {
                    String::new()
                } else {
                    format!("New: {}", r.new)
                },
            ),
            (Some(Ok(_)), None) => (
                vec![installed, Span::raw("up to date"), checked],
                String::new(),
            ),
        };
        vec![
            Line::from(first),
            Line::styled(format!("    {second}"), t.dim()),
        ]
    }

    /// Update now's value on the appliance.
    pub(super) fn release_value(&self) -> String {
        match self.release() {
            Some(r) => format!("downloads {} MB, checks its signature", megabytes(r.size)),
            None => "once GitHub can be reached".into(),
        }
    }
}
