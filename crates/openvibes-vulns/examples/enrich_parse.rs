//! Parses real KEV and EPSS files and prints counts and timings:
//! `cargo run --release --example enrich_parse -- kev.json epss.csv.gz`.
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let start = std::time::Instant::now();
    let kev = openvibes_vulns::enrich::parse_kev(&std::fs::read(&args[1]).unwrap()).unwrap();
    let ransomware = kev.iter().filter(|k| k.ransomware).count();
    println!(
        "kev {} ({ransomware} ransomware) in {:?}",
        kev.len(),
        start.elapsed()
    );
    let start = std::time::Instant::now();
    let epss =
        openvibes_vulns::enrich::parse_epss(&std::fs::read(&args[2]).unwrap(), 128 << 20).unwrap();
    println!(
        "epss {} dated {:?} in {:?}",
        epss.scores.len(),
        epss.date,
        start.elapsed()
    );
}
