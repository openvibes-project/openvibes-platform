//! The Maintenance pages: their titles and Help lines. Split from
//! `mod.rs` (size).

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Page {
    Database,
    SignIn,
    Backup,
    Update,
    Os,
    Repair,
    Parts,
    Ports,
    Certificates,
    Names,
    /// Replace the intermediate (certs2.py, certs4a.py).
    Replace,
    /// The console's certificate, once yours is in (certs4c.py #10).
    Console,
    /// Use your own certificate for the console (certs4c.py #2-#8).
    ConsoleUse,
    Uninstall,
    WhatsNew,
    /// The folder browser, reached with Tab from a typed folder.
    Folder,
}

impl Page {
    pub fn title(self) -> &'static str {
        match self {
            Page::Database => "Database",
            Page::SignIn => "Console sign-in",
            Page::Backup => "Back up",
            Page::Update => "Update OpenVIBES",
            Page::Os => "Operating system",
            Page::Repair => "Repair",
            Page::Parts => "Optional parts",
            Page::Ports => "Ports and addresses",
            Page::Certificates => "Certificates",
            Page::Names => "Certificates › Names",
            Page::Replace => "Certificates › Replace",
            Page::Console | Page::ConsoleUse => "Certificates › Console",
            Page::Uninstall => "Uninstall",
            Page::WhatsNew => "What's new",
            Page::Folder => "Choose a folder",
        }
    }
    /// What the keys do here, for Help.
    pub fn help(self) -> &'static str {
        match self {
            Page::Database => "A report: the clean-up runs by itself every night.",
            Page::SignIn => "Enter resets the admin password; the new one is shown once.",
            Page::Backup => {
                "Enter on Save in folder types or browses a folder; Back up now writes a new file there."
            }
            Page::Update => {
                "Space ticks Back up first; Enter on Update now updates; What's new lists the packages."
            }
            Page::Os => {
                "Update everything installs every package dnf has; Check again asks dnf what is waiting."
            }
            Page::Repair => {
                "It checks every step first; Fix N problems repairs, then checks again."
            }
            Page::Parts => {
                "Space ticks the agent or the assistant; Apply installs or removes what changed."
            }
            Page::Ports => {
                "Enter on a port types a new one; Apply moves it and opens the new port."
            }
            Page::Certificates => {
                "Renewal is automatic. Names sets their names; Replace the intermediate makes a new one; Console certificate uses your own."
            }
            Page::Replace => {
                "A new intermediate, trusted beside the old one until agents move over."
            }
            Page::Console => {
                "Use a new one adds another; Go back to the platform's issues the platform's again."
            }
            Page::ConsoleUse => {
                "Paste or pick the certificate and its key, or a .p12; Use it restarts the console with them."
            }
            Page::Names => {
                "Enter on a name types it; Add a name adds one; Apply issues new certificates."
            }
            Page::Uninstall => {
                "Space chooses Keep the data or Remove everything; Uninstall asks first."
            }
            Page::WhatsNew => "A list: every package's version and the release notes' address.",
            Page::Folder => "Enter opens a folder; Use this folder picks the one shown.",
        }
    }
}
