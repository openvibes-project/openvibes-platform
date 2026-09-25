//! Fedora `updateinfo.xml` (repository advisory metadata): streaming parse
//! of security advisories only.

use std::{
    cell::Cell,
    collections::BTreeSet,
    io::{self, BufRead, BufReader, Read},
    rc::Rc,
};

use quick_xml::{
    Reader, XmlVersion,
    events::{BytesStart, Event},
};

/// Advisory severity as Fedora rates it.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Severity {
    /// `None` in the feed.
    Unrated,
    /// `Low`.
    Low,
    /// `Moderate`.
    Moderate,
    /// `Important`.
    Important,
    /// `Critical`.
    Critical,
}

/// A package version that fixes the advisory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FixedPackage {
    /// Package name.
    pub name: String,
    /// Epoch.
    pub epoch: u32,
    /// Version.
    pub version: String,
    /// Release.
    pub release: String,
    /// Architecture (`noarch` fixes every architecture).
    pub arch: String,
}

/// One security advisory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Advisory {
    /// `FEDORA-YYYY-…`.
    pub id: String,
    /// Severity.
    pub severity: Severity,
    /// Title (the updated builds).
    pub title: String,
    /// Issue time as the feed writes it (`YYYY-MM-DD HH:MM:SS`, UTC).
    pub issued: String,
    /// Last update time, same format; the issue time when absent.
    pub updated: String,
    /// CVE ids named in references or the description, sorted, unique.
    pub cves: Vec<String>,
    /// Fixed binary packages (`src` excluded).
    pub packages: Vec<FixedPackage>,
}

impl Advisory {
    /// The advisory's page in Fedora's update system.
    #[must_use]
    pub fn url(&self) -> String {
        format!("https://bodhi.fedoraproject.org/updates/{}", self.id)
    }
}

/// Why a feed could not be read. Messages never include feed content.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseError {
    /// More than the allowed bytes after decompression.
    TooLarge,
    /// Not well-formed updateinfo XML, or a bad compressed stream.
    Malformed,
}

/// Reads uncompressed updateinfo XML, at most `max_bytes`.
pub fn read(input: impl BufRead, max_bytes: u64) -> Result<Vec<Advisory>, ParseError> {
    let over = Rc::new(Cell::new(false));
    let capped = BufReader::new(Capped {
        inner: input,
        left: max_bytes,
        over: over.clone(),
    });
    parse(capped).map_err(|error| {
        if over.get() {
            ParseError::TooLarge
        } else {
            error
        }
    })
}

/// Reads zstd-compressed updateinfo (`updateinfo.xml.zst`), at most
/// `max_bytes` after decompression.
pub fn read_zstd(input: impl BufRead, max_bytes: u64) -> Result<Vec<Advisory>, ParseError> {
    let decoder =
        ruzstd::decoding::StreamingDecoder::new(input).map_err(|_| ParseError::Malformed)?;
    read(BufReader::new(decoder), max_bytes)
}

/// Stops reading past a byte budget, flagging it so the caller can tell a
/// cap from malformed input.
struct Capped<R> {
    inner: R,
    left: u64,
    over: Rc<Cell<bool>>,
}

impl<R: Read> Read for Capped<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.left == 0 {
            // One probe byte tells the end of input from an overflow.
            let mut probe = [0u8; 1];
            return match self.inner.read(&mut probe)? {
                0 => Ok(0),
                _ => {
                    self.over.set(true);
                    Err(io::Error::other("size cap"))
                }
            };
        }
        let limit = usize::try_from(self.left)
            .unwrap_or(usize::MAX)
            .min(buf.len());
        let read = self.inner.read(&mut buf[..limit])?;
        self.left -= read as u64;
        Ok(read)
    }
}

/// Which text the parser is collecting.
#[derive(Clone, Copy, PartialEq)]
enum Field {
    None,
    Id,
    Title,
    Severity,
    Description,
}

#[derive(Default)]
struct Current {
    security: bool,
    id: String,
    title: String,
    severity: String,
    issued: String,
    updated: String,
    cves: BTreeSet<String>,
    packages: Vec<FixedPackage>,
}

fn parse(input: impl BufRead) -> Result<Vec<Advisory>, ParseError> {
    let mut reader = Reader::from_reader(input);
    let mut buf = Vec::new();
    let mut advisories = Vec::new();
    let mut current: Option<Current> = None;
    let mut field = Field::None;
    loop {
        let event = reader
            .read_event_into(&mut buf)
            .map_err(|_| ParseError::Malformed)?;
        match event {
            Event::Eof => break,
            Event::Start(ref element) | Event::Empty(ref element) => {
                let empty = matches!(event, Event::Empty(_));
                let name = element.local_name();
                match name.as_ref() {
                    "update" => {
                        current = Some(Current {
                            security: attribute(element, "type")?.as_deref() == Some("security"),
                            ..Current::default()
                        });
                    }
                    other => {
                        let Some(update) = current.as_mut().filter(|u| u.security) else {
                            continue;
                        };
                        match other {
                            "id" if !empty => field = Field::Id,
                            "title" if !empty => field = Field::Title,
                            "severity" if !empty => field = Field::Severity,
                            "description" if !empty => field = Field::Description,
                            "issued" => {
                                update.issued = attribute(element, "date")?.unwrap_or_default()
                            }
                            "updated" => {
                                update.updated = attribute(element, "date")?.unwrap_or_default()
                            }
                            "reference" => {
                                if let Some(title) = attribute(element, "title")? {
                                    cves_in(&title, &mut update.cves);
                                }
                            }
                            "package" => {
                                let arch = attribute(element, "arch")?.unwrap_or_default();
                                if arch != "src" {
                                    update.packages.push(FixedPackage {
                                        name: attribute(element, "name")?
                                            .ok_or(ParseError::Malformed)?,
                                        epoch: attribute(element, "epoch")?
                                            .and_then(|e| e.parse().ok())
                                            .unwrap_or(0),
                                        version: attribute(element, "version")?
                                            .ok_or(ParseError::Malformed)?,
                                        release: attribute(element, "release")?.unwrap_or_default(),
                                        arch,
                                    });
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
            Event::Text(text) => append(&mut current, field, &text.xml10_content()),
            Event::CData(data) => {
                append(&mut current, field, AsRef::<str>::as_ref(&data));
            }
            Event::GeneralRef(entity) => {
                let resolved = match entity.resolve_char_ref() {
                    Ok(Some(c)) => c.to_string(),
                    _ => match entity.xml10_content().as_ref() {
                        "lt" => "<".into(),
                        "gt" => ">".into(),
                        "amp" => "&".into(),
                        "quot" => "\"".into(),
                        "apos" => "'".into(),
                        _ => String::new(),
                    },
                };
                append(&mut current, field, &resolved);
            }
            Event::End(element) => match element.local_name().as_ref() {
                "update" => {
                    if let Some(update) = current.take().filter(|u| u.security) {
                        advisories.push(finish(update)?);
                    }
                }
                "id" | "title" | "severity" | "description" => field = Field::None,
                _ => {}
            },
            _ => {}
        }
        buf.clear();
    }
    if current.is_some() {
        return Err(ParseError::Malformed);
    }
    Ok(advisories)
}

fn append(current: &mut Option<Current>, field: Field, text: &str) {
    let Some(update) = current.as_mut().filter(|u| u.security) else {
        return;
    };
    match field {
        Field::Id => update.id.push_str(text),
        Field::Title => update.title.push_str(text),
        Field::Severity => update.severity.push_str(text),
        Field::Description => cves_in(text, &mut update.cves),
        Field::None => {}
    }
}

fn finish(update: Current) -> Result<Advisory, ParseError> {
    let id = update.id.trim().to_owned();
    if id.is_empty() {
        return Err(ParseError::Malformed);
    }
    let severity = match update.severity.trim() {
        "Critical" => Severity::Critical,
        "Important" => Severity::Important,
        "Moderate" => Severity::Moderate,
        "Low" => Severity::Low,
        _ => Severity::Unrated,
    };
    let updated = if update.updated.is_empty() {
        update.issued.clone()
    } else {
        update.updated
    };
    Ok(Advisory {
        id,
        severity,
        title: update.title.trim().to_owned(),
        issued: update.issued,
        updated,
        cves: update.cves.into_iter().collect(),
        packages: update.packages,
    })
}

fn attribute(element: &BytesStart<'_>, name: &str) -> Result<Option<String>, ParseError> {
    match element.try_get_attribute(name) {
        Ok(Some(value)) => value
            .normalized_value(XmlVersion::Explicit1_0)
            .map(|v| Some(v.into_owned()))
            .map_err(|_| ParseError::Malformed),
        Ok(None) => Ok(None),
        Err(_) => Err(ParseError::Malformed),
    }
}

/// Adds every `CVE-YYYY-NNNN…` id found in `text`.
fn cves_in(text: &str, found: &mut BTreeSet<String>) {
    let bytes = text.as_bytes();
    let mut at = 0;
    while let Some(offset) = text[at..].find("CVE-") {
        let start = at + offset;
        let rest = &bytes[start + 4..];
        let year = rest.iter().take_while(|c| c.is_ascii_digit()).count();
        let number = rest.get(year + 1..).map_or(0, |tail| {
            tail.iter().take_while(|c| c.is_ascii_digit()).count()
        });
        if year == 4 && rest.get(4) == Some(&b'-') && number >= 4 {
            found.insert(text[start..start + 4 + 5 + number].to_owned());
        }
        at = start + 4;
    }
}
