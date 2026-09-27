//! A service's configuration file as a form (admin TUI spec §5). The file is
//! kept as a `toml_edit` document, so comments and layout survive a save;
//! only the service's listed fields change, and every change is checked by
//! the service's own configuration type.

use platform_host::Service;
use toml_edit::{DocumentMut, Item, Table, TableLike, Value};

use crate::{
    configs,
    fields::{self, Field, Kind},
};

/// A field whose value differs from the file as read.
#[derive(Debug, Eq, PartialEq)]
pub struct Change {
    pub key: &'static str,
    /// In the file; `None` when absent (the service default).
    pub before: Option<String>,
    /// In the form.
    pub after: Option<String>,
}

#[derive(Debug)]
pub struct Form {
    pub service: Service,
    /// The file as read, byte for byte (to notice edits made meanwhile).
    pub original: String,
    /// The service type's verdict on the current text.
    pub validity: Result<(), String>,
    read: DocumentMut,
    doc: DocumentMut,
}

impl Form {
    /// Fails only when the text is not TOML; an invalid configuration still
    /// opens, with `validity` saying why.
    pub fn parse(service: Service, text: &str) -> Result<Form, String> {
        let doc: DocumentMut = text.parse().map_err(|error: toml_edit::TomlError| {
            format!("not valid TOML: {}", error.message())
        })?;
        Ok(Form {
            service,
            original: text.to_owned(),
            validity: configs::validate(service, text),
            read: doc.clone(),
            doc,
        })
    }

    pub fn fields(&self) -> &'static [Field] {
        fields::fields(self.service)
    }

    /// The value as it is typed; `None` when the key is absent.
    pub fn get(&self, key: &str) -> Option<String> {
        lookup(&self.doc, key).map(show)
    }

    /// Sets a field from typed text; empty text removes the key.
    pub fn set(&mut self, field: Field, input: &str) -> Result<(), String> {
        let input = input.trim();
        let value = if input.is_empty() {
            None
        } else {
            Some(parse(field.kind, input)?)
        };
        put(&mut self.doc, field.key, value);
        self.recheck();
        Ok(())
    }

    /// Puts a field back as the file had it.
    pub fn undo(&mut self, key: &str) {
        let value = lookup(&self.read, key).cloned();
        put(&mut self.doc, key, value);
        self.recheck();
    }

    pub fn changes(&self) -> Vec<Change> {
        self.fields()
            .iter()
            .filter_map(|field| {
                let before = lookup(&self.read, field.key).map(show);
                let after = self.get(field.key);
                (before != after).then_some(Change {
                    key: field.key,
                    before,
                    after,
                })
            })
            .collect()
    }

    pub fn text(&self) -> String {
        self.doc.to_string()
    }

    fn recheck(&mut self) {
        self.validity = configs::validate(self.service, &self.text());
    }
}

/// `a.b.c` → (`["a", "b"]`, `"c"`).
fn split(key: &str) -> (Vec<&str>, &str) {
    let mut parts: Vec<&str> = key.split('.').collect();
    let last = parts.pop().unwrap_or(key);
    (parts, last)
}

fn lookup<'a>(doc: &'a DocumentMut, key: &str) -> Option<&'a Value> {
    let (parents, last) = split(key);
    let mut table: &dyn TableLike = doc.as_table();
    for part in parents {
        table = table.get(part)?.as_table_like()?;
    }
    table.get(last)?.as_value()
}

fn table_at<'a>(doc: &'a mut DocumentMut, path: &[&str]) -> Option<&'a mut dyn TableLike> {
    let mut table: &mut dyn TableLike = doc.as_table_mut();
    for part in path {
        table = table.get_mut(part)?.as_table_like_mut()?;
    }
    Some(table)
}

/// Shown and typed the same way: strings bare, lists comma-separated.
fn show(value: &Value) -> String {
    match value {
        Value::String(text) => text.value().clone(),
        Value::Array(items) => items.iter().map(show).collect::<Vec<_>>().join(", "),
        other => {
            let mut other = other.clone();
            other.decor_mut().clear();
            other.to_string()
        }
    }
}

fn parse(kind: Kind, input: &str) -> Result<Value, String> {
    let int = |text: &str| {
        text.parse::<i64>()
            .map_err(|_| format!("{text:?} is not a whole number"))
    };
    let items = || {
        input
            .split(',')
            .map(str::trim)
            .filter(|item| !item.is_empty())
    };
    Ok(match kind {
        Kind::Text => input.into(),
        Kind::Integer => int(input)?.into(),
        Kind::Bool => match input {
            "true" => true.into(),
            "false" => false.into(),
            _ => return Err("true or false".into()),
        },
        Kind::Choice(choices) if choices.contains(&input) => input.into(),
        Kind::Choice(choices) => return Err(format!("one of: {}", choices.join(", "))),
        Kind::TextList => Value::Array(items().collect()),
        Kind::IntegerList => Value::Array(
            items()
                .map(int)
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .collect(),
        ),
    })
}

/// Sets `key` (keeping the old value's trailing comment), creating its
/// tables; `None` removes it and any table it leaves empty.
fn put(doc: &mut DocumentMut, key: &str, value: Option<Value>) {
    let (parents, last) = split(key);
    let Some(mut value) = value else {
        for depth in (0..=parents.len()).rev() {
            let Some(table) = table_at(doc, &parents[..depth]) else {
                return;
            };
            if depth == parents.len() {
                table.remove(last);
            } else if table
                .get(parents[depth])
                .and_then(Item::as_table_like)
                .is_some_and(TableLike::is_empty)
            {
                table.remove(parents[depth]);
            } else {
                return;
            }
        }
        return;
    };
    let mut table: &mut dyn TableLike = doc.as_table_mut();
    for part in &parents {
        let item = table.entry(part).or_insert_with(|| {
            // Implicit: no `[assistant]` header just to hold `[assistant.backend]`.
            let mut new = Table::new();
            new.set_implicit(true);
            Item::Table(new)
        });
        let Some(next) = item.as_table_like_mut() else {
            return;
        };
        table = next;
    }
    match table.get_mut(last) {
        Some(Item::Value(old)) => {
            *value.decor_mut() = old.decor().clone();
            *old = value;
        }
        Some(other) => *other = Item::Value(value),
        None => {
            table.insert(last, Item::Value(value));
        }
    }
}

#[cfg(test)]
mod tests {
    use platform_host::Service;

    use super::Form;
    use crate::{
        configs::tests::packaged,
        fields::{Field, Kind, fields},
    };

    fn field(service: Service, key: &str) -> Field {
        *fields(service)
            .iter()
            .find(|field| field.key == key)
            .unwrap()
    }

    #[test]
    fn packaged_files_open_valid_and_unchanged() {
        for service in Service::ALL {
            let form = Form::parse(service, packaged(service)).unwrap();
            assert_eq!(form.validity, Ok(()), "{}", service.name());
            assert_eq!(form.text(), packaged(service));
            assert!(form.changes().is_empty());
        }
    }

    #[test]
    fn set_keeps_comments_and_layout() {
        let text = "# the port\nlisten = \"0.0.0.0:18423\" # agents\nmax_in_flight = 4096\n";
        let mut form = Form::parse(Service::Distribution, text).unwrap();
        form.set(field(Service::Distribution, "listen"), "0.0.0.0:443")
            .unwrap();
        assert_eq!(
            form.text(),
            "# the port\nlisten = \"0.0.0.0:443\" # agents\nmax_in_flight = 4096\n"
        );
    }

    #[test]
    fn a_nested_field_creates_its_table_and_clearing_removes_it() {
        let base = packaged(Service::Console);
        let mut form = Form::parse(Service::Console, base).unwrap();
        form.set(
            field(Service::Console, "assistant.backend.url"),
            "http://127.0.0.1:18430/v1",
        )
        .unwrap();
        assert!(
            form.text()
                .contains("[assistant.backend]\nurl = \"http://127.0.0.1:18430/v1\""),
            "{}",
            form.text()
        );
        assert!(
            !form.text().contains("[assistant]\n"),
            "no empty parent header"
        );
        form.set(field(Service::Console, "assistant.backend.url"), "")
            .unwrap();
        assert_eq!(form.text(), base);
    }

    #[test]
    fn kinds_are_checked() {
        let mut form = Form::parse(Service::Console, packaged(Service::Console)).unwrap();
        let err = |form: &mut Form, key, input| {
            form.set(field(Service::Console, key), input).unwrap_err()
        };
        assert!(err(&mut form, "assistant.max_lookups", "four").contains("not a whole number"));
        assert_eq!(err(&mut form, "assistant.enabled", "yes"), "true or false");
        assert_eq!(
            err(&mut form, "assistant.profile", "huge"),
            "one of: small, medium, large"
        );
        assert!(err(&mut form, "trusted_proxy_uids", "1, x").contains("not a whole number"));
        form.set(
            field(Service::Console, "trusted_proxy_addresses"),
            "127.0.0.1, ::1",
        )
        .unwrap();
        assert_eq!(
            form.get("trusted_proxy_addresses").as_deref(),
            Some("127.0.0.1, ::1")
        );
        form.set(field(Service::Console, "assistant.enabled"), "true")
            .unwrap();
        assert_eq!(form.get("assistant.enabled").as_deref(), Some("true"));
    }

    #[test]
    fn changes_undo_and_validity() {
        let mut form = Form::parse(Service::Admin, "database_url = 1\n").unwrap();
        assert!(form.validity.is_err(), "an invalid file still opens");
        form.set(field(Service::Admin, "database_url"), "postgresql:///x")
            .unwrap();
        assert_eq!(form.validity, Ok(()));
        assert_eq!(form.changes().len(), 1);
        assert_eq!(form.changes()[0].before.as_deref(), Some("1"));
        assert_eq!(form.changes()[0].after.as_deref(), Some("postgresql:///x"));
        form.undo("database_url");
        assert!(form.changes().is_empty());
        assert_eq!(form.text(), "database_url = 1\n");
        assert!(
            Form::parse(Service::Admin, "database_url = \n")
                .unwrap_err()
                .starts_with("not valid TOML")
        );
    }

    #[test]
    fn typed_text_is_escaped() {
        let mut form = Form::parse(Service::Admin, packaged(Service::Admin)).unwrap();
        let value = r#"postgresql:///a "quoted" \ value ✓"#;
        form.set(field(Service::Admin, "database_url"), value)
            .unwrap();
        assert_eq!(form.validity, Ok(()));
        let reparsed = Form::parse(Service::Admin, &form.text()).unwrap();
        assert_eq!(reparsed.get("database_url").as_deref(), Some(value));
    }

    #[test]
    fn every_listed_field_is_known_to_its_service_type() {
        for service in Service::ALL {
            for field in fields(service) {
                let mut form = Form::parse(service, packaged(service)).unwrap();
                let value = match field.kind {
                    Kind::Text => "/x",
                    Kind::Integer | Kind::IntegerList => "1",
                    Kind::Bool => "true",
                    Kind::Choice(choices) => choices[0],
                    Kind::TextList => "::1",
                };
                form.set(*field, value).unwrap();
                if let Err(error) = &form.validity {
                    assert!(
                        !error.contains("unknown field"),
                        "{}: {}: {error}",
                        service.name(),
                        field.key
                    );
                }
            }
        }
    }
}
