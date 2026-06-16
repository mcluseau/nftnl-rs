//! Verdict maps and concat maps for a reverse-proxy DNAT scenario.
//!
//!
//! After running this example, the output should be the following:
//! ```ignore
//! table inet example-add-vmap {
//!     map ip_vmap_v4 {
//!         type ipv4_addr : verdict
//!         flags constant
//!         elements = { 203.0.113.10 : jump nginx-endpoints }
//!     }
//!
//!     map http_vmap_v4 {
//!         type ipv4_addr . inet_service : verdict
//!         flags constant
//!         elements = { 198.51.100.1 . 80 : jump nginx-endpoints }
//!     }
//!
//!     map backends_v4 {
//!         type 0 : ipv4_addr . inet_service
//!         flags constant
//!         elements = { 0 : 10.0.0.110 . 8080, 1 : 10.0.0.111 . 8080 }
//!     }
//!
//!     map ip_vmap_v6 {
//!         type ipv6_addr : verdict
//!         flags constant
//!         elements = { 2001:db8::1 : jump nginx-endpoints }
//!     }
//!
//!     map http_vmap_v6 {
//!         type ipv6_addr . inet_service : verdict
//!         flags constant
//!         elements = { 2001:db8::1 . 80 : jump nginx-endpoints }
//!     }
//!
//!     map backends_v6 {
//!         type 0 : ipv6_addr . inet_service
//!         flags constant
//!         elements = { 0 : 2001:db8::110 . 8080, 1 : 2001:db8::111 . 8080 }
//!     }
//!
//!     chain prerouting {
//!         type nat hook prerouting priority dstnat; policy accept;
//!         ip daddr vmap @ip_vmap_v4
//!         ip daddr . tcp dport vmap @http_vmap_v4
//!         ip6 daddr vmap @ip_vmap_v6
//!         ip6 daddr . tcp dport vmap @http_vmap_v6
//!     }
//!
//!     chain nginx-endpoints {
//!         meta nfproto ipv4 dnat ip to numgen random mod 2 map @backends_v4
//!         meta nfproto ipv6 dnat ip6 to numgen random mod 2 map @backends_v6
//!     }
//! }
//! ```
//!
//! Everything created by this example can be removed by running
//! ```bash
//! # nft delete table inet example-add-vmap
//! ```

use nftnl::expr::{L4Proto, Nat, NatType, NfProto, Register};
use nftnl::{Batch, Chain, ChainType, Hook, MsgType, Policy, ProtoFamily, Table, nft_expr};
use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr},
};

fn main() -> io::Result<()> {
    let mut batch = Batch::new();
    let table = Table::new(c"example-add-vmap", ProtoFamily::Inet);
    batch.add(&table, MsgType::Add);

    // --- chains first (elements reference chain names) ---
    let mut chain = Chain::new(c"prerouting", &table);
    chain.set_hook(Hook::PreRouting, -100);
    chain.set_type(ChainType::Nat);
    chain.set_policy(Policy::Accept);
    batch.add(&chain, MsgType::Add);

    let nginx = Chain::new(c"nginx-endpoints", &table);
    batch.add(&nginx, MsgType::Add);

    // --- IPv4 maps ---

    let mut ip_vmap_v4 = nftnl::nft_map!(c"ip_vmap_v4", 1, &table, ProtoFamily::Inet);
    ip_vmap_v4.add(
        &Ipv4Addr::new(203, 0, 113, 10),
        &nft_expr!(verdict jump c"nginx-endpoints".into()),
    );
    batch.add(&ip_vmap_v4, MsgType::Add);
    batch.add_iter(ip_vmap_v4.elems_iter(), MsgType::Add);

    let mut http_vmap_v4 = nftnl::nft_map!(c"http_vmap_v4", 2, &table, ProtoFamily::Inet);
    http_vmap_v4.add(
        &(Ipv4Addr::new(198, 51, 100, 1), 80u16),
        &nft_expr!(verdict jump c"nginx-endpoints".into()),
    );
    batch.add(&http_vmap_v4, MsgType::Add);
    batch.add_iter(http_vmap_v4.elems_iter(), MsgType::Add);

    let mut backends_v4 = nftnl::nft_map!(c"backends_v4", 3, &table, ProtoFamily::Inet);
    backends_v4.add(&0u32, &(Ipv4Addr::new(10, 0, 0, 110), 8080u16));
    backends_v4.add(&1u32, &(Ipv4Addr::new(10, 0, 0, 111), 8080u16));
    batch.add(&backends_v4, MsgType::Add);
    batch.add_iter(backends_v4.elems_iter(), MsgType::Add);

    // --- IPv6 maps ---

    let mut ip_vmap_v6 = nftnl::nft_map!(c"ip_vmap_v6", 4, &table, ProtoFamily::Inet);
    ip_vmap_v6.add(
        &Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
        &nft_expr!(verdict jump c"nginx-endpoints".into()),
    );
    batch.add(&ip_vmap_v6, MsgType::Add);
    batch.add_iter(ip_vmap_v6.elems_iter(), MsgType::Add);

    let mut http_vmap_v6 = nftnl::nft_map!(c"http_vmap_v6", 5, &table, ProtoFamily::Inet);
    http_vmap_v6.add(
        &(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), 80u16),
        &nft_expr!(verdict jump c"nginx-endpoints".into()),
    );
    batch.add(&http_vmap_v6, MsgType::Add);
    batch.add_iter(http_vmap_v6.elems_iter(), MsgType::Add);

    let mut backends_v6 = nftnl::nft_map!(c"backends_v6", 6, &table, ProtoFamily::Inet);
    backends_v6.add(
        &0u32,
        &(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x110), 8080u16),
    );
    backends_v6.add(
        &1u32,
        &(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x111), 8080u16),
    );
    batch.add(&backends_v6, MsgType::Add);
    batch.add_iter(backends_v6.elems_iter(), MsgType::Add);

    // --- IPv4 rules ---

    {
        let mut r = nftnl::Rule::new(&chain);
        r.add_expr(&nft_expr!(meta nfproto));
        r.add_expr(&nft_expr!(cmp == NfProto::Ipv4));
        r.add_expr(&nft_expr!(payload ipv4 daddr));
        r.add_expr(&nft_expr!(lookup_map &ip_vmap_v4 => Register::Verdict));
        batch.add(&r, MsgType::Add);
    }

    {
        let mut r = nftnl::Rule::new(&chain);
        r.add_expr(&nft_expr!(meta nfproto));
        r.add_expr(&nft_expr!(cmp == NfProto::Ipv4));
        r.add_expr(&nft_expr!(meta l4proto));
        r.add_expr(&nft_expr!(cmp == L4Proto::Tcp));
        r.add_expr(&nft_expr!(payload ipv4 daddr => Register::Reg32_00));
        r.add_expr(&nft_expr!(payload tcp dport => Register::Reg32_01));
        r.add_expr(&nft_expr!(lookup_map &http_vmap_v4, Register::Reg32_00 => Register::Verdict));
        batch.add(&r, MsgType::Add);
    }

    // --- IPv6 rules ---

    {
        let mut r = nftnl::Rule::new(&chain);
        r.add_expr(&nft_expr!(meta nfproto));
        r.add_expr(&nft_expr!(cmp == NfProto::Ipv6));
        r.add_expr(&nft_expr!(payload ipv6 daddr));
        r.add_expr(&nft_expr!(lookup_map &ip_vmap_v6 => Register::Verdict));
        batch.add(&r, MsgType::Add);
    }

    {
        let mut r = nftnl::Rule::new(&chain);
        r.add_expr(&nft_expr!(meta nfproto));
        r.add_expr(&nft_expr!(cmp == NfProto::Ipv6));
        r.add_expr(&nft_expr!(meta l4proto));
        r.add_expr(&nft_expr!(cmp == L4Proto::Tcp));
        r.add_expr(&nft_expr!(payload ipv6 daddr => Register::Reg32_00));
        r.add_expr(&nft_expr!(payload tcp dport => Register::Reg32_04));
        r.add_expr(&nft_expr!(lookup_map &http_vmap_v6, Register::Reg32_00 => Register::Verdict));
        batch.add(&r, MsgType::Add);
    }

    // --- endpoint rules: pick random backend and DNAT ---

    {
        let mut r = nftnl::Rule::new(&nginx);
        r.add_expr(&nft_expr!(meta nfproto));
        r.add_expr(&nft_expr!(cmp == NfProto::Ipv4));
        r.add_expr(&nft_expr!(numgen random mod 2));
        r.add_expr(&nft_expr!(lookup_map &backends_v4 => Register::Reg2));
        r.add_expr(&Nat {
            nat_type: NatType::DNat,
            family: ProtoFamily::Ipv4,
            ip_register: Register::Reg2,
            port_register: None,
        });
        batch.add(&r, MsgType::Add);
    }

    {
        let mut r = nftnl::Rule::new(&nginx);
        r.add_expr(&nft_expr!(meta nfproto));
        r.add_expr(&nft_expr!(cmp == NfProto::Ipv6));
        r.add_expr(&nft_expr!(numgen random mod 2));
        r.add_expr(&nft_expr!(lookup_map &backends_v6 => Register::Reg2));
        r.add_expr(&Nat {
            nat_type: NatType::DNat,
            family: ProtoFamily::Ipv6,
            ip_register: Register::Reg2,
            port_register: None,
        });
        batch.add(&r, MsgType::Add);
    }

    // --- send batch ---
    let finalized = batch.finalize();
    let socket = mnl::Socket::new(mnl::Bus::Netfilter)?;
    let portid = socket.portid();
    socket.send_all(&finalized)?;

    let mut buffer = vec![0; nftnl::nft_nlmsg_maxsize() as usize];
    let mut expected_seqs = finalized.sequence_numbers();
    while !expected_seqs.is_empty() {
        for message in socket.recv(&mut buffer[..])? {
            let message = message?;
            let expected_seq = expected_seqs.next().expect("Unexpected ACK");
            mnl::cb_run(message, expected_seq, portid)?;
        }
    }

    Ok(())
}
