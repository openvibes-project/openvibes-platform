//! Parses real enrichment files and prints counts and timings:
//! `cargo run --release --example enrich_parse -- kev.json epss.csv.gz [nvd.json]`.
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
    if let Some(path) = args.get(3) {
        let start = std::time::Instant::now();
        let page = openvibes_vulns::enrich::parse_nvd(&std::fs::read(path).unwrap()).unwrap();
        let scored = page
            .entries
            .iter()
            .filter(|e| e.cvss_score.is_some())
            .count();
        println!(
            "nvd {} of {} ({scored} scored) in {:?}",
            page.entries.len(),
            page.total,
            start.elapsed()
        );
    }
}
