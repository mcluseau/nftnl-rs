//! Demonstrates flushing all elements from a map.
//!
//! Run this example as root, then use `nft list table ip example-table` to inspect the result.
//! The table can be removed with `nft delete table ip example-table`.

use nftnl::{Batch, FinalizedBatch, MsgType, ProtoFamily, Table, map::Map};
use std::{io, net::Ipv4Addr};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let table = Table::new(c"example-table", ProtoFamily::Ipv4);

    // 1. Create table and populate the map
    let mut batch = Batch::new();
    batch.add(&table, MsgType::Add);

    let mut map: Map<Ipv4Addr, u16> = Map::new_named(c"test_v4", 1, &table, ProtoFamily::Ipv4);
    map.add(&Ipv4Addr::new(1, 2, 3, 4), &8080);
    map.add(&Ipv4Addr::new(5, 6, 7, 8), &8081);
    batch.add(&map, MsgType::Add);
    batch.add_iter(map.elems_iter(), MsgType::Add);
    send_and_process(&batch.finalize())?;
    println!("Created map 'test_v4' with elements {{ 1.2.3.4 -> 8080, 5.6.7.8 -> 8081 }}");

    // 2. Flush all elements from the map
    let mut batch = Batch::new();
    batch.add(&map.flush(), MsgType::Del);
    send_and_process(&batch.finalize())?;
    println!("Flushed all elements from map 'test_v4'");

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
