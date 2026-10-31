//! The Network page's keys, its questions and what a finished run does.

use std::time::Instant;

use platform_host::{
    Host,
    network::{self, Method},
};

use super::{At, Net, draw::net_run};
use crate::tui::{
    app::{App, Key, Question},
    kind::{Kind, NetAction},
    maint::Then,
    run::{Call, Work},
};

impl<H: Host> App<H> {
    /// Opens the page: reads the connection again.
    pub(in crate::tui) fn open_network(&mut self) {
        self.nav.row = 0;
        // A finished run is not news the next time.
        if net_run(self).is_some_and(|r| !r.running()) {
            self.run = None;
        }
        self.maint.net = Net::from_info(self.host.network_info());
        // A change still waiting to be kept stays on offer, with the time
        // that is really left on the helper's clock.
        self.maint.net.keep = self
            .maint
            .net
            .info
            .as_ref()
            .and_then(|i| i.pending_since)
            .map(Net::pending_instant);
    }

    fn net_at(&self) -> Option<At> {
        self.maint.net.rows().get(self.nav.row).copied()
    }

    fn net_check(&mut self) {
        let net = &self.maint.net;
        let (Some(at), Some(typed)) = (self.net_at(), &net.typing) else {
            return;
        };
        self.maint.net.note = net.note_for(at, typed);
    }

    fn net_typed(&mut self, key: Key) {
        let at = self.net_at();
        let net = &mut self.maint.net;
        let Some(text) = net.typing.as_mut() else {
            return;
        };
        match key {
            Key::Char(c) if !c.is_control() && text.len() < 253 => text.push(c),
            Key::Backspace => {
                text.pop();
            }
            Key::ClearLine => text.clear(),
            Key::Enter => {
                let typed = std::mem::take(text).trim().to_owned();
                let ok = matches!(net.note, Some(Ok(_)))
                    || (typed.is_empty() && matches!(at, Some(At::Search | At::Dns)));
                if !ok {
                    net.typing = Some(typed);
                    return;
                }
                match at {
                    Some(At::Address) => net.address = typed,
                    Some(At::Gateway) => net.gateway = typed,
                    Some(At::Dns) => net.dns = typed,
                    Some(At::Search) => net.search = typed,
                    Some(At::Host) => net.host = typed,
                    _ => {}
                }
                net.typing = None;
                net.note = None;
                let last = net.rows().len().saturating_sub(1);
                self.nav.row = self.nav.row.min(last);
                return;
            }
            Key::Esc => {
                net.typing = None;
                net.note = None;
                return;
            }
            _ => return,
        }
        self.net_check();
    }

    pub(in crate::tui) fn network_key(&mut self, key: Key) {
        if self.maint.net.typing() {
            return self.net_typed(key);
        }
        if let Some(run) = net_run(self) {
            if run.running() || key != Key::Enter {
                return;
            }
            if run.ok() {
                self.run = None;
                self.maint.net.said = None;
                let keep = self.maint.net.keep;
                self.maint.net = Net::from_info(self.host.network_info());
                self.maint.net.keep = keep;
                self.nav.row = 0;
            } else if let Some(at) = run.stopped_at() {
                let work = run.work.clone();
                self.begin(work, at);
            }
            return;
        }
        self.maint.net.said = None;
        let count = self.maint.net.rows().len();
        let space = key == Key::Char(' ');
        if count == 0 || self.move_row(&key, count) || !(key == Key::Enter || space) {
            return;
        }
        let Some(at) = self.net_at() else { return };
        let net = &mut self.maint.net;
        match at {
            At::Dhcp => net.choose_dhcp(),
            At::Fixed => net.choose_fixed(),
            At::DnsAuto => net.own_dns = !net.own_dns,
            At::Address => net.typing = Some(net.address.clone()),
            At::Gateway => net.typing = Some(net.gateway.clone()),
            At::Dns => net.typing = Some(net.dns_text()),
            At::Search => net.typing = Some(net.search.clone()),
            At::Host => net.typing = Some(net.host.clone()),
            At::Apply if key == Key::Enter => return self.ask_net_apply(),
            At::Keep if key == Key::Enter => {
                return self.begin(
                    Work::new(Kind::Net(NetAction::Keep), vec![Call::NetKeep]),
                    0,
                );
            }
            At::Revert if key == Key::Enter => {
                return self.begin(
                    Work::new(Kind::Net(NetAction::Revert), vec![Call::NetRevert]),
                    0,
                );
            }
            At::Apply | At::Keep | At::Revert => return,
        }
        if self.maint.net.typing.is_some() {
            self.net_check();
        }
        let last = self.maint.net.rows().len().saturating_sub(1);
        self.nav.row = self.nav.row.min(last);
    }

    /// The `net-apply` arguments for the page, or why they will not do.
    fn net_args(&self) -> Result<(Vec<String>, Vec<String>), String> {
        let net = &self.maint.net;
        let fixed = net.mode == Some(Method::Fixed);
        let dns = if fixed || net.own_dns {
            net.dns_text().replace(", ", ",")
        } else {
            String::new()
        };
        let (address, gateway) = if fixed {
            (net.address.as_str(), net.gateway.as_str())
        } else {
            ("", "")
        };
        let mode = if fixed { "fixed" } else { "dhcp" };
        network::change(mode, address, gateway, &dns, &net.search)?;
        let servers = dns
            .split(',')
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect();
        let args = vec![
            "--mode".into(),
            mode.into(),
            "--address".into(),
            address.into(),
            "--gateway".into(),
            gateway.into(),
            "--dns".into(),
            dns,
            "--search".into(),
            net.search.clone(),
        ];
        Ok((args, servers))
    }

    fn ask_net_apply(&mut self) {
        if let Some(why) = super::super::maint::busy(self) {
            self.outcome = Some((false, why));
            return;
        }
        let net = &self.maint.net;
        let mut silent = Vec::new();
        if net.net_changed() {
            let servers = match self.net_args() {
                Ok((_, servers)) => servers,
                Err(why) => {
                    self.outcome = Some((false, format!("✗ {why}")));
                    return;
                }
            };
            // Each own DNS server is asked first. One that is silent is a
            // warning, not a stop: DNS matters less than the rest, and a new
            // network's server is often out of reach until the change is made.
            silent = servers
                .into_iter()
                .filter(|s| !self.host.dns_answers(s))
                .collect();
        }
        let (text, detail) = if net.net_changed() {
            let mut detail = String::from("undone in a minute unless kept");
            if net.host_changed() {
                detail.push_str("; the host name stays");
            }
            if !silent.is_empty() {
                detail = format!(
                    "{} does not answer from here, so feeds may fail; {detail}",
                    silent.join(", ")
                );
            }
            ("Apply the network settings?", detail)
        } else {
            (
                "Change the host name?",
                "agents need the new install line".to_owned(),
            )
        };
        self.question = Some((
            Question::Maint {
                text: text.into(),
                detail,
                then: Then::NetApply,
            },
            true,
        ));
    }

    pub(in crate::tui) fn net_apply_yes(&mut self) {
        let net = &self.maint.net;
        let (host, name) = (net.host_changed(), net.host.clone());
        let mut calls = Vec::new();
        if host {
            calls.push(Call::HostnameSet(name));
        }
        if net.net_changed() {
            match self.net_args() {
                Ok((args, _)) => calls.push(Call::NetApply(args)),
                Err(why) => {
                    self.outcome = Some((false, format!("✗ {why}")));
                    return;
                }
            }
        }
        if calls.is_empty() {
            return;
        }
        self.begin(Work::new(Kind::Net(NetAction::Apply { host }), calls), 0);
    }

    /// A run ended: a change that is waiting starts the minute to keep it;
    /// a keep or put back ends it.
    pub(in crate::tui) fn net_ended(&mut self) {
        let Some(run) = net_run(self) else { return };
        if run.running() || !run.ok() {
            return;
        }
        let pending = run
            .states
            .iter()
            .flatten()
            .any(|s| s.detail().starts_with("pending"));
        let kind = run.work.kind.clone();
        match kind {
            Kind::Net(NetAction::Apply { .. }) if pending => {
                self.run = None;
                let host = self.maint.net.host.clone();
                self.maint.net = Net::from_info(self.host.network_info());
                self.maint.net.host = host;
                self.maint.net.keep = Some(
                    self.maint
                        .net
                        .info
                        .as_ref()
                        .and_then(|i| i.pending_since)
                        .map_or_else(Instant::now, Net::pending_instant),
                );
                self.nav.row = 0;
            }
            Kind::Net(NetAction::Keep) => {
                // `nothing pending`: the timer got there first.
                let late = run
                    .states
                    .iter()
                    .flatten()
                    .any(|s| s.detail().starts_with("nothing pending"));
                self.run = None;
                self.maint.net = Net::from_info(self.host.network_info());
                self.maint.net.said = Some(if late {
                    Err("Too late: the old settings came back by themselves.".into())
                } else {
                    Ok("The new settings are kept.".into())
                });
                self.nav.row = 0;
            }
            Kind::Net(NetAction::Revert) => {
                self.run = None;
                self.maint.net = Net::from_info(self.host.network_info());
                self.maint.net.said = Some(Ok("The old settings are back.".into()));
                self.nav.row = 0;
            }
            _ => {}
        }
    }

    /// Past the minute with nobody answering: the helper's timer has put
    /// the old settings back, so the page reads the host again.
    pub(in crate::tui) fn net_tick(&mut self) {
        let Some(since) = self.maint.net.keep else {
            return;
        };
        let idle = net_run(self).is_none() && self.asking.is_none() && self.question.is_none();
        if idle && !self.maint.net.lapsed && since.elapsed().as_secs() > network::KEEP_SECONDS + 6 {
            self.maint.net = Net::from_info(self.host.network_info());
            self.nav.row = 0;
            if self
                .maint
                .net
                .info
                .as_ref()
                .is_some_and(|i| i.pending_since.is_some())
            {
                // The helper's revert did not take: still waiting on an answer.
                self.maint.net.keep = Some(since);
                self.maint.net.lapsed = true;
                self.maint.net.said = Some(Err(
                    "The old settings could not be put back by themselves. Keep the new ones or put the old ones back."
                        .into(),
                ));
            } else {
                self.maint.net.said =
                    Some(Err("Nobody answered, so the old settings are back.".into()));
            }
        }
    }
}
