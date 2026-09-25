//! Prints RPM version order for "A B" pairs on stdin (-1, 0, 1), for
//! cross-checking against `rpm.vercmp`.

use std::{cmp::Ordering, io::BufRead};

fn main() {
    for line in std::io::stdin().lock().lines().map_while(Result::ok) {
        if let Some((a, b)) = line.split_once(' ') {
            let order = openvibes_vulns::rpmver::rpmvercmp(a, b);
            println!(
                "{}",
                match order {
                    Ordering::Less => -1,
                    Ordering::Equal => 0,
                    Ordering::Greater => 1,
                }
            );
        }
    }
}
