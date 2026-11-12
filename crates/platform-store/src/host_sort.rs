//! The sort of a detail page's Hosts table (#577): by host name (the
//! default), triage state or the table's date column.

use crate::host_list::values;

values!(
    /// The sort column; ties are broken by host name, then agent id.
    HostSort {
        /// Host name, then agent id.
        Host = "host",
        /// Triage state, open first.
        State = "state",
        /// The table's date: checked, first seen or last report.
        Date = "date",
    }
);

/// A Hosts table's sort and direction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostOrder {
    /// The column.
    pub sort: HostSort,
    /// Largest, newest or last first.
    pub descending: bool,
}

impl Default for HostOrder {
    fn default() -> Self {
        Self {
            sort: HostSort::Host,
            descending: false,
        }
    }
}

/// States from the most to the least in need of work.
const STATES: &str =
    "ARRAY['open','mitigated','accepted_risk','false_positive','resolved','passing']";

impl HostOrder {
    /// The `ORDER BY` list over the query's `host` name, `agent` id, `state`
    /// (None: the table has no state; sorts by host) and `date` columns.
    /// Only fixed expressions reach the SQL.
    pub(crate) fn sql(self, host: &str, agent: &str, state: Option<&str>, date: &str) -> String {
        let dir = if self.descending { "DESC" } else { "ASC" };
        let ties = format!("{host} NULLS LAST, {agent}");
        match (self.sort, state) {
            (HostSort::State, Some(state)) => {
                format!("array_position({STATES}, {state}) {dir} NULLS LAST, {ties}")
            }
            (HostSort::Date, _) => format!("{date} {dir} NULLS LAST, {ties}"),
            _ => format!("{host} {dir} NULLS LAST, {agent} {dir}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_sort_orders_by_its_column_then_the_host() {
        let order = |sort, descending| {
            HostOrder { sort, descending }.sql("h.name", "h.id", Some("p.state"), "p.at")
        };
        assert_eq!(
            order(HostSort::Host, false),
            "h.name ASC NULLS LAST, h.id ASC"
        );
        assert_eq!(
            order(HostSort::Date, true),
            "p.at DESC NULLS LAST, h.name NULLS LAST, h.id"
        );
        assert!(order(HostSort::State, false).starts_with("array_position(ARRAY['open',"));
        let stateless = HostOrder {
            sort: HostSort::State,
            descending: true,
        }
        .sql("h.name", "h.id", None, "p.at");
        assert_eq!(stateless, "h.name DESC NULLS LAST, h.id DESC");
    }
}
