//! The network settings' parsing and checks.

use std::net::UdpSocket;

use platform_host::network::{
    Method, NetInfo, Snapshot, change, cidr, dns_answers_at, dns_name, host_name, read_config,
    read_now, terse, wired_connection,
};

#[test]
fn terse_fields_unescape_colons() {
    assert_eq!(
        terse(r"Wired\: one:802-3-ethernet:eth0"),
        ["Wired: one", "802-3-ethernet", "eth0"]
    );
}

#[test]
fn the_first_active_wired_connection_is_found() {
    let listing = "lo:00000000-0000-4000-8000-000000000000:loopback:lo\ndocker:11111111-0000-4000-8000-000000000000:bridge:docker0\nWired connection 1:5d1f3a7c-1111-4222-8333-944455556666:802-3-ethernet:eth0\n";
    assert_eq!(
        wired_connection(listing),
        Some((
            "Wired connection 1".into(),
            "5d1f3a7c-1111-4222-8333-944455556666".into(),
            "eth0".into()
        ))
    );
    assert_eq!(
        wired_connection("wifi:5d1f3a7c-1111-4222-8333-944455556666:802-11-wireless:wlan0\n"),
        None
    );
}

#[test]
fn configured_and_current_values_are_read() {
    let mut info = NetInfo::default();
    read_config(
        &mut info,
        "ipv4.method:manual\nipv4.addresses:192.168.1.50/24\nipv4.gateway:192.168.1.1\nipv4.dns:192.168.1.1,9.9.9.9\nipv4.dns-search:lime.lab\nipv4.ignore-auto-dns:yes\n",
    );
    assert_eq!(info.method, Some(Method::Fixed));
    assert_eq!(info.address, "192.168.1.50/24");
    assert_eq!(info.dns, ["192.168.1.1", "9.9.9.9"]);
    assert_eq!(info.search, "lime.lab");
    assert!(!info.dns_auto);
    read_config(
        &mut info,
        "ipv4.method:auto\nipv4.addresses:\nipv4.gateway:\nipv4.dns:\nipv4.dns-search:\nipv4.ignore-auto-dns:no\n",
    );
    assert_eq!(info.method, Some(Method::Dhcp));
    assert!(info.address.is_empty() && info.dns.is_empty() && info.dns_auto);
    read_now(
        &mut info,
        "IP4.ADDRESS[1]:192.168.1.50/24\nIP4.GATEWAY:192.168.1.1\nIP4.DNS[1]:192.168.1.1\nIP4.DNS[2]:9.9.9.9\nIP4.DOMAIN[1]:lime.lab\n",
    );
    assert_eq!(info.now_address, "192.168.1.50/24");
    assert_eq!(info.now_dns, ["192.168.1.1", "9.9.9.9"]);
    assert_eq!(info.now_search, "lime.lab");
    read_config(&mut info, "ipv4.method:link-local\n");
    assert_eq!(info.method, None);
}

#[test]
fn addresses_and_names_are_checked() {
    assert!(cidr("192.168.1.50/24").is_some());
    for bad in [
        "192.168.1.50",
        "192.168.1.50/0",
        "192.168.1.50/31",
        "0.0.0.0/24",
        "127.0.0.1/8",
        "224.0.0.1/24",
        "a.b.c.d/24",
        "10.0.0.1/24; reboot",
    ] {
        assert!(cidr(bad).is_none(), "{bad}");
    }
    assert!(dns_name("lime.lab") && dns_name("a-b.example.com"));
    for bad in ["", "-a.lab", "a-.lab", "a..lab", "a b", "a;b", "a_b.lab"] {
        assert!(!dns_name(bad), "{bad:?}");
    }
    assert!(host_name("openvibes-va.lime.lab"));
    assert!(!host_name("localhost") && !host_name("va.") && !host_name("--help"));
    assert!(!host_name(&format!("{}.lab", "a".repeat(62))));
}

#[test]
fn a_change_is_checked_as_a_whole() {
    let ok = change(
        "fixed",
        "192.168.1.50/24",
        "192.168.1.1",
        "192.168.1.1, 9.9.9.9",
        "lime.lab",
    )
    .unwrap();
    assert_eq!(ok.dns, ["192.168.1.1", "9.9.9.9"]);
    assert!(change("dhcp", "", "", "", "").is_ok());
    // checked values are rebuilt: no "+024" prefix, no padding
    let odd = change(
        "fixed",
        "192.168.1.50/+024",
        "192.168.1.1",
        " 9.9.9.9 ,",
        "",
    )
    .unwrap();
    assert_eq!(
        (odd.address.as_str(), odd.dns.as_slice()),
        ("192.168.1.50/24", ["9.9.9.9".to_owned()].as_slice())
    );
    assert!(change("dhcp", "", "", "192.168.1.10", "").is_ok());
    for (mode, address, gateway, dns, search) in [
        ("static", "", "", "", ""),
        ("dhcp", "192.168.1.50/24", "", "", ""),
        ("fixed", "192.168.1.50/24", "10.0.0.1", "9.9.9.9", ""),
        ("fixed", "192.168.1.50/24", "192.168.1.50", "9.9.9.9", ""),
        ("fixed", "192.168.1.50/24", "192.168.1.1", "", ""),
        (
            "fixed",
            "192.168.1.50/24",
            "192.168.1.1",
            "1.1.1.1,2.2.2.2,3.3.3.3,4.4.4.4",
            "",
        ),
        ("fixed", "192.168.1.50/24", "192.168.1.1", "not-an-ip", ""),
        ("dhcp", "", "", "", "bad domain"),
    ] {
        assert!(
            change(mode, address, gateway, dns, search).is_err(),
            "{mode} {address} {gateway} {dns} {search}"
        );
    }
}

#[test]
fn a_snapshot_round_trips_and_refuses_anything_else() {
    let snapshot = Snapshot {
        uuid: "5d1f3a7c-1111-4222-8333-944455556666".into(),
        method: "manual".into(),
        addresses: "192.168.1.50/24".into(),
        gateway: "192.168.1.1".into(),
        dns: "192.168.1.1,9.9.9.9".into(),
        search: "lime.lab".into(),
        ignore_auto_dns: "yes".into(),
    };
    assert_eq!(Snapshot::decode(&snapshot.encode()), Some(snapshot.clone()));
    assert_eq!(
        Snapshot::decode("uuid=5d1f3a7c-1111-4222-8333-944455556666\n"),
        None
    );
    assert_eq!(
        Snapshot::decode(&snapshot.encode().replace("method", "other")),
        None
    );
    assert_eq!(
        Snapshot::decode(&snapshot.encode().replace("manual", "man\u{7}ual")),
        None
    );
}

#[test]
fn a_dns_server_that_replies_counts_as_answering() {
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    let to = server.local_addr().unwrap();
    let answer = std::thread::spawn(move || {
        let mut buffer = [0_u8; 512];
        let (n, from) = server.recv_from(&mut buffer).unwrap();
        let mut reply = buffer[..n].to_vec();
        reply[2] |= 0x80;
        server.send_to(&reply, from).unwrap();
    });
    assert!(dns_answers_at(to));
    answer.join().unwrap();
    let silent = UdpSocket::bind("127.0.0.1:0").unwrap();
    assert!(!dns_answers_at(silent.local_addr().unwrap()));
}
