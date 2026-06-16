//! Demonstrates creating sets and maps whose keys are ranges (intervals).
//!
//! Run this example as root, then use `nft list table ip example-table` to inspect the result.
//! The table can be removed with `nft delete table ip example-table`.

use nftnl::{
    Batch, FinalizedBatch, MsgType, ProtoFamily, Table,
    interval::{IntervalMap, IntervalSet},
};
use std::{io, net::Ipv4Addr};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let table = Table::new(c"example-table", ProtoFamily::Ipv4);
    let mut batch = Batch::new();
    batch.add(&table, MsgType::Add);

    // A range set: each element spans a contiguous interval of addresses.
    let mut set: IntervalSet<Ipv4Addr> =
        IntervalSet::new_named(c"test_ranges", 1, &table, ProtoFamily::Ipv4);
    set.add(&Ipv4Addr::new(10, 0, 0, 0), &Ipv4Addr::new(10, 0, 0, 15));
    set.add(&Ipv4Addr::new(192, 168, 1, 0), &Ipv4Addr::new(192, 168, 1, 255));
    // An interval set can also match a single address exactly.
    set.add_exact(&Ipv4Addr::new(100, 64, 0, 1));
    batch.add(&set, MsgType::Add);
    batch.add_iter(set.elems_iter(), MsgType::Add);

    // A range map: each interval maps to a value.
    let mut map: IntervalMap<Ipv4Addr, u16> =
        IntervalMap::new_named(c"test_range_map", 2, &table, ProtoFamily::Ipv4);
    map.add(&Ipv4Addr::new(10, 0, 0, 0), &Ipv4Addr::new(10, 0, 0, 15), &8080);
    map.add(&Ipv4Addr::new(192, 168, 1, 0), &Ipv4Addr::new(192, 168, 1, 255), &8081);
    // An interval map can also map a single address exactly.
    map.add_exact(&Ipv4Addr::new(100, 64, 0, 1), &8082);
    batch.add(&map, MsgType::Add);
    batch.add_iter(map.elems_iter(), MsgType::Add);

    send_and_process(&batch.finalize())?;
    println!("Created range set 'test_ranges' and range map 'test_range_map'");

    Ok(())
}

fn send_and_process(batch: &FinalizedBatch) -> io::Result<()> {
    let socket = mnl::Socket::new(mnl::Bus::Netfilter)?;
    let portid = socket.portid();
    socket.send_all(batch)?;

    let mut buffer = vec![0; nftnl::nft_nlmsg_maxsize() as usize];
    let mut expected_seqs = batch.sequence_numbers();
    while !expected_seqs.is_empty() {
        for message in socket.recv(&mut buffer[..])? {
            let message = message?;
            let expected_seq = expected_seqs.next().expect("Unexpected ACK");
            mnl::cb_run(message, expected_seq, portid)?;
        }
    }
    Ok(())
}
