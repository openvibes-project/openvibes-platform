//! Prints dpkg version order for "A B" pairs on stdin (-1, 0, 1), for
//! cross-checking against `dpkg --compare-versions`.

use std::{cmp::Ordering, io::BufRead};

fn main() {
    for line in std::io::stdin().lock().lines().map_while(Result::ok) {
        if let Some((a, b)) = line.split_once(' ') {
            let order = openvibes_vulns::dpkgver::compare(a, b);
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
