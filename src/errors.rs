use pcap;
use protobuf;
use std::io;

error_chain! {
    foreign_links {
        Io(io::Error);
        Pcap(pcap::Error);
        Protobuf(protobuf::ProtobufError);
    }
}
