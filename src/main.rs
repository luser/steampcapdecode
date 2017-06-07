#[macro_use]
extern crate error_chain;
extern crate pcap;
extern crate protobuf;

mod errors;
mod proto;

use errors::*;
use pcap::Capture;
use proto::steammessages_remoteclient_discovery::*;
use protobuf::{parse_from_bytes, CodedInputStream};
use std::env;
use std::path::Path;

// 14 byte Ethernet frame header + 20 byte IPv4 header + 8 byte UDP header
const HEADER_LEN: usize = 42;
const MAGIC: [u8; 8] = [0xFF, 0xFF, 0xFF, 0xFF, 0x21, 0x4C, 0x5F, 0xA0];

fn run<P: AsRef<Path>>(pcap_file: P) -> Result<()> {
    let mut cap = Capture::from_file(pcap_file)?;
    while let Ok(packet) = cap.next() {
        if packet.data.len() < HEADER_LEN {
            println!("Packet too short!");
            continue
        }
        let data = &packet.data[HEADER_LEN..];
        if data.len() < MAGIC.len() || data[..MAGIC.len()] != MAGIC {
            println!("Packet too short, or doesn't start with magic number!");
            continue
        }
        let mut is = CodedInputStream::from_bytes(&data[MAGIC.len()..]);
        let len = is.read_raw_little_endian32()?;
        println!("header len: {}", len);
        let bytes = is.read_raw_bytes(len)?;
        let header: CMsgRemoteClientBroadcastHeader = parse_from_bytes(&bytes)?;
        println!("header: {:?}", header);
        let len = is.read_raw_little_endian32()?;
        let bytes = is.read_raw_bytes(len)?;
        match header.get_msg_type() {
            ERemoteClientBroadcastMsg::k_ERemoteClientBroadcastMsgDiscovery => {
                let body: CMsgRemoteClientBroadcastDiscovery = parse_from_bytes(&bytes)?;
                println!("CMsgRemoteClientBroadcastDiscovery: {:?}", body);
            }
            ERemoteClientBroadcastMsg::k_ERemoteClientBroadcastMsgStatus => {
                let body: CMsgRemoteClientBroadcastStatus = parse_from_bytes(&bytes)?;
                println!("CMsgRemoteClientBroadcastStatus: {:?}", body);
            }
            ERemoteClientBroadcastMsg::k_ERemoteClientBroadcastMsgOffline => {
                println!("k_ERemoteClientBroadcastMsgOffline");
            }
            ERemoteClientBroadcastMsg::k_ERemoteDeviceAuthorizationRequest => {
                let body: CMsgRemoteDeviceAuthorizationRequest = parse_from_bytes(&bytes)?;
                println!("CMsgRemoteDeviceAuthorizationRequest: {:?}", body);
            }
            ERemoteClientBroadcastMsg::k_ERemoteDeviceAuthorizationResponse => {
                let body: CMsgRemoteDeviceAuthorizationResponse = parse_from_bytes(&bytes)?;
                println!("CMsgRemoteDeviceAuthorizationResponse: {:?}", body);
            }
            ERemoteClientBroadcastMsg::k_ERemoteDeviceStreamingRequest => {
                let body: CMsgRemoteDeviceStreamingRequest = parse_from_bytes(&bytes)?;
                println!("CMsgRemoteDeviceStreamingRequest: {:?}", body);
            }
            ERemoteClientBroadcastMsg::k_ERemoteDeviceStreamingResponse => {
                let body: CMsgRemoteDeviceStreamingResponse = parse_from_bytes(&bytes)?;
                println!("CMsgRemoteDeviceStreamingResponse: {:?}", body);
            }
            ERemoteClientBroadcastMsg::k_ERemoteDeviceProofRequest => {
                let body: CMsgRemoteDeviceProofRequest = parse_from_bytes(&bytes)?;
                println!("CMsgRemoteDeviceProofRequest: challenge: {:?}", body.get_challenge());
            }
            ERemoteClientBroadcastMsg::k_ERemoteDeviceProofResponse => {
                let body: CMsgRemoteDeviceProofResponse = parse_from_bytes(&bytes)?;
                println!("CMsgRemoteDeviceProofResponse: response: {:?}", body.get_response());
            }
            ERemoteClientBroadcastMsg::k_ERemoteDeviceAuthorizationCancelRequest => {
                let body: CMsgRemoteDeviceAuthorizationCancelRequest = parse_from_bytes(&bytes)?;
                println!("CMsgRemoteDeviceAuthorizationCancelRequest: {:?}", body);
            }
            ERemoteClientBroadcastMsg::k_ERemoteDeviceStreamingCancelRequest => {
                let body: CMsgRemoteDeviceStreamingCancelRequest = parse_from_bytes(&bytes)?;
                println!("CMsgRemoteDeviceStreamingCancelRequest: {:?}", body);
            }
        }
    }
    Ok(())
}

fn main() {
    let filename = env::args_os().nth(1).expect("No filename given!");
    match run(&filename) {
        Ok(()) => {}
        Err(e) => println!("Error: {}", e),
    }
}
