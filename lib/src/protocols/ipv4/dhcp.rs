use crate::common::err_as_eof;
use crate::protocols::ethernet::mac::MacAddr;
use crate::write_to_buffer::WriteToBuffer;
use bytes::BufMut;
use std::net::Ipv4Addr;
use std::time;
use strum::{EnumDiscriminants, FromRepr};
use tracing::debug;

#[derive(Debug, Copy, Clone)]
#[repr(u8)]
enum Operation {
    BootRequest = 1,
    BootReply = 2,
}

impl From<Operation> for u8 {
    fn from(value: Operation) -> u8 {
        match value {
            Operation::BootRequest => 1,
            Operation::BootReply => 2,
        }
    }
}

///                     1 1 1 1 1 1
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |B|             MBZ             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///
/// B:  BROADCAST flag
///
/// MBZ:  MUST BE ZERO (reserved for future use)
///
/// Figure 2:  Format of the 'flags' field
#[derive(Debug, Copy, Clone)]
struct Flags {
    broadcast: bool,
}

impl TryFrom<[u8; 2]> for Flags {
    type Error = std::io::Error;
    fn try_from(value: [u8; 2]) -> Result<Self, Self::Error> {
        let broadcast = match value {
            [0b0000_0000, 0b0000_0000] => false,
            [0b1000_0000, 0b0000_0000] => true,
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Flags has data in reserved",
                ));
            }
        };

        Ok(Self { broadcast })
    }
}

impl From<Flags> for u16 {
    fn from(value: Flags) -> u16 {
        if value.broadcast {
            0b1000_0000_0000_0000
        } else {
            0b0000_0000_0000_0000
        }
    }
}

#[derive(Debug, Copy, Clone)]
#[repr(u8)]
pub enum OptionsOverload {
    File = 1,
    ServerName = 2,
    Both = 3,
}

/// Value   Message Type
/// -----   ------------
/// 1     DHCPDISCOVER
/// 2     DHCPOFFER
/// 3     DHCPREQUEST
/// 4     DHCPDECLINE
/// 5     DHCPACK
/// 6     DHCPNAK
/// 7     DHCPRELEASE
#[derive(Debug, Copy, Clone)]
#[repr(u8)]
pub enum DHCPMessageType {
    Discover = 1,
    Offer = 2,
    Request = 3,
    Decline = 4,
    Ack = 5,
    Nak = 6,
    Release = 7,
}

/// RFC1533
///
/// ```test
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |      tag(1)       |      length(1)    | data(variable)        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
// The pad option can be used to cause subsequent fields to align on word boundaries.
// The code for the pad option is 0, and its length is 1 octet.

// The end option marks the end of valid information in the vendor field. Subsequent octets
// should be filled with pad options. The code for the end option is 255, and its length is
// 1 octet.
#[derive(Debug, Clone, EnumDiscriminants)]
#[strum_discriminants(derive(FromRepr), name(OptionCode))]
#[repr(u8)]
pub enum DHCPOption {
    /// The subnet mask option specifies the client's subnet mask as per RFC 950.
    /// If both the subnet mask and the router option are specified in a DHCP reply, the subnet
    /// mask option MUST be first.
    ///
    /// The code for the subnet mask option is 1, and its length is 4 octets.
    ///
    /// ```text
    /// Code   Len        Subnet Mask
    /// +-----+-----+-----+-----+-----+-----+
    /// |  1  |  4  |  m1 |  m2 |  m3 |  m4 |
    /// +-----+-----+-----+-----+-----+-----+
    /// ```
    SubnetMask(Ipv4Addr) = 1,
    /// The time offset field specifies the offset of the client's subnet in
    /// seconds from Coordinated Universal Time (UTC).  The offset is
    /// expressed as a signed 32-bit integer.
    ///
    /// The code for the time offset option is 2, and its length is 4 octets.
    ///
    /// ```text
    ///  Code   Len        Time Offset
    /// +-----+-----+-----+-----+-----+-----+
    /// |  2  |  4  |  n1 |  n2 |  n3 |  n4 |
    /// +-----+-----+-----+-----+-----+-----+
    /// ```
    TimeOffset(i32) = 2,
    /// The router option specifies a list of IP addresses for routers on the
    /// client's subnet.  Routers SHOULD be listed in order of preference.
    ///
    /// The code for the router option is 3.  The minimum length for the
    /// router option is 4 octets, and the length MUST always be a multiple
    /// of 4.
    ///
    /// ```text
    ///  Code   Len         Address 1               Address 2
    /// +-----+-----+-----+-----+-----+-----+-----+-----+--
    /// |  3  |  n  |  a1 |  a2 |  a3 |  a4 |  a1 |  a2 |  ...
    /// +-----+-----+-----+-----+-----+-----+-----+-----+--
    /// ```
    RouterOption(Vec<Ipv4Addr>) = 3,
    /// (STD 13, RFC 1035 [8]) name servers available to the client.  Servers
    /// SHOULD be listed in order of preference.
    ///
    /// The code for the domain name server option is 6.  The minimum length
    /// for this option is 4 octets, and the length MUST always be a multiple
    /// of 4.
    ///
    /// ```text
    /// Code   Len         Address 1               Address 2
    /// +-----+-----+-----+-----+-----+-----+-----+-----+--
    /// |  6  |  n  |  a1 |  a2 |  a3 |  a4 |  a1 |  a2 |  ...
    /// +-----+-----+-----+-----+-----+-----+-----+-----+--
    /// ```
    DomainNameServerOption(Vec<Ipv4Addr>) = 6,
    /// This option specifies the name of the client.  The name may or may
    /// not be qualified with the local domain name (see section 3.17 for the
    /// preferred way to retrieve the domain name).  See RFC 1035 for
    /// character set restrictions.
    ///
    /// The code for this option is 12, and its minimum length is 1.
    ///
    /// ```text
    /// Code   Len                 Host Name
    /// +-----+-----+-----+-----+-----+-----+-----+-----+--
    /// |  12 |  n  |  h1 |  h2 |  h3 |  h4 |  h5 |  h6 |  ...
    /// +-----+-----+-----+-----+-----+-----+-----+-----+--
    /// ```
    HostNameOption(String) = 12,
    /// This option specifies the domain name that client should use when
    /// resolving hostnames via the Domain Name System.
    ///
    /// The code for this option is 15.  Its minimum length is 1.
    ///
    /// ```text
    /// Code   Len        Domain Name
    /// +-----+-----+-----+-----+-----+-----+--
    /// |  15 |  n  |  d1 |  d2 |  d3 |  d4 |  ...
    /// +-----+-----+-----+-----+-----+-----+--
    /// ```
    DomainName(String) = 15,
    /// This option specifies the timeout (in seconds) to use when aging Path
    /// MTU values discovered by the mechanism defined in RFC 1191 [12].  The
    /// timeout is specified as a 32-bit unsigned integer.
    ///
    /// The code for this option is 24, and its length is 4.
    ///
    /// ```text
    /// Code   Len           Timeout
    /// +-----+-----+-----+-----+-----+-----+
    /// |  24 |  4  |  t1 |  t2 |  t3 |  t4 |
    /// +-----+-----+-----+-----+-----+-----+
    /// ```
    PathMTUAgingTimeoutOption(u32) = 24,
    /// This option specifies a table of MTU sizes to use when performing
    /// Path MTU Discovery as defined in RFC 1191.  The table is formatted as
    /// a list of 16-bit unsigned integers, ordered from smallest to largest.
    /// The minimum MTU value cannot be smaller than 68.
    ///
    /// The code for this option is 25.  Its minimum length is 2, and the
    /// length MUST be a multiple of 2.
    ///
    /// ```text
    /// Code   Len     Size 1      Size 2
    /// +-----+-----+-----+-----+-----+-----+---
    /// |  25 |  n  |  s1 |  s2 |  s1 |  s2 | ...
    /// +-----+-----+-----+-----+-----+-----+---
    /// ```
    PathMTUPlateauOption(Vec<u16>) = 25,
    /// This option specifies the broadcast address in use on the client's
    /// subnet.  Legal values for broadcast addresses are specified in
    /// section 3.2.1.3 of [4].
    ///
    /// The code for this option is 28, and its length is 4.
    ///
    /// ```text
    /// Code   Len     Broadcast Address
    /// +-----+-----+-----+-----+-----+-----+
    /// |  28 |  4  |  b1 |  b2 |  b3 |  b4 |
    /// +-----+-----+-----+-----+-----+-----+
    /// ```
    BroadcastAddressOption(Ipv4Addr) = 28,
    /// This option specifies a list of static routes that the client should
    /// install in its routing cache.  If multiple routes to the same
    /// destination are specified, they are listed in descending order of
    /// priority.
    ///
    /// The routes consist of a list of IP address pairs.  The first address
    /// is the destination address, and the second address is the router for
    /// the destination.
    ///
    /// The default route (0.0.0.0) is an illegal destination for a static
    /// route.  See section 3.5 for information about the router option.
    ///
    /// The code for this option is 33.  The minimum length of this option is
    /// 8, and the length MUST be a multiple of 8.
    ///
    /// ```text
    ///  Code   Len         Destination 1           Router 1
    /// +-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+
    /// |  33 |  n  |  d1 |  d2 |  d3 |  d4 |  r1 |  r2 |  r3 |  r4 |
    /// +-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+
    ///         Destination 2           Router 2
    /// +-----+-----+-----+-----+-----+-----+-----+-----+---
    /// |  d1 |  d2 |  d3 |  d4 |  r1 |  r2 |  r3 |  r4 | ...
    /// +-----+-----+-----+-----+-----+-----+-----+-----+---
    /// ```
    StaticRouteOption(Vec<(Ipv4Addr, Ipv4Addr)>) = 33,
    // TODO maybe want tcp options? need to actually see what of these are passed anyway
    /// This option specifies a list of IP addresses indicating NTP [18]
    /// servers available to the client.  Servers SHOULD be listed in order
    /// of preference.
    ///
    /// The code for this option is 42.  Its minimum length is 4, and the
    /// length MUST be a multiple of 4.
    ///
    /// ```text
    /// Code   Len         Address 1               Address 2
    /// +-----+-----+-----+-----+-----+-----+-----+-----+--
    /// |  42 |  n  |  a1 |  a2 |  a3 |  a4 |  a1 |  a2 |  ...
    /// +-----+-----+-----+-----+-----+-----+-----+-----+--
    /// ```
    NetworkTimeProtocolServersOption(Vec<Ipv4Addr>) = 42,
    /// This option is used in a client request (DHCPDISCOVER) to allow the
    /// client to request that a particular IP address be assigned.
    ///
    /// The code for this option is 50, and its length is 4.
    ///
    /// ```text
    /// Code   Len          Address
    /// +-----+-----+-----+-----+-----+-----+
    /// |  50 |  4  |  a1 |  a2 |  a3 |  a4 |
    /// +-----+-----+-----+-----+-----+-----+
    /// ```
    RequestedIpAddress(Ipv4Addr) = 50,
    /// This option is used in a client request (DHCPDISCOVER or DHCPREQUEST)
    /// to allow the client to request a lease time for the IP address.  In a
    /// server reply (DHCPOFFER), a DHCP server uses this option to specify
    /// the lease time it is willing to offer.
    ///
    /// The time is in units of seconds, and is specified as a 32-bit
    /// unsigned integer.
    ///
    /// The code for this option is 51, and its length is 4.
    ///
    /// ```text
    /// Code   Len         Lease Time
    /// +-----+-----+-----+-----+-----+-----+
    /// |  51 |  4  |  t1 |  t2 |  t3 |  t4 |
    /// +-----+-----+-----+-----+-----+-----+
    /// ```
    IPAddressLeaseTime(u32) = 51,
    /// fields are being overloaded by using them to carry DHCP options. A
    /// DHCP server inserts this option if the returned parameters will
    /// exceed the usual space allotted for options.
    ///
    /// If this option is present, the client interprets the specified
    /// additional fields after it concludes interpretation of the standard
    /// option fields.
    ///
    /// The code for this option is 52, and its length is 1.  Legal values
    /// for this option are:
    ///
    /// Value   Meaning
    /// -----   --------
    /// 1     the "file" field is used to hold options
    /// 2     the "sname" field is used to hold options
    /// 3     both fields are used to hold options
    ///
    /// ```text
    /// Code   Len  Value
    /// +-----+-----+-----+
    /// |  52 |  1  |1/2/3|
    /// +-----+-----+-----+
    /// ```
    OptionsOverload(OptionsOverload) = 52,
    /// This option is used to convey the type of the DHCP message.  The code
    /// for this option is 53, and its length is 1.  Legal values for this
    /// option are:
    ///
    /// Value   Message Type
    /// -----   ------------
    /// 1     DHCPDISCOVER
    /// 2     DHCPOFFER
    /// 3     DHCPREQUEST
    /// 4     DHCPDECLINE
    /// 5     DHCPACK
    /// 6     DHCPNAK
    /// 7     DHCPRELEASE
    ///
    /// ```text
    /// Code   Len  Type
    /// +-----+-----+-----+
    /// |  53 |  1  | 1-7 |
    /// +-----+-----+-----+
    /// ```
    DHCPMessageType(DHCPMessageType) = 53,
    /// This option is used in DHCPOFFER and DHCPREQUEST messages, and may
    /// optionally be included in the DHCPACK and DHCPNAK messages.  DHCP
    /// servers include this option in the DHCPOFFER in order to allow the
    /// client to distinguish between lease offers.  DHCP clients indicate
    /// which of several lease offers is being accepted by including this
    /// option in a DHCPREQUEST message.
    ///
    /// The identifier is the IP address of the selected server.
    ///
    /// The code for this option is 54, and its length is 4.
    ///
    /// ```text
    /// Code   Len            Address
    /// +-----+-----+-----+-----+-----+-----+
    /// |  54 |  4  |  a1 |  a2 |  a3 |  a4 |
    /// +-----+-----+-----+-----+-----+-----+
    /// ```
    ServerIdentifier(Ipv4Addr) = 54,
    /// This option is used by a DHCP client to request values for specified
    /// configuration parameters.  The list of requested parameters is
    /// specified as n octets, where each octet is a valid DHCP option code
    /// as defined in this document.
    ///
    /// The client MAY list the options in order of preference.  The DHCP
    /// server is not required to return the options in the requested order,
    /// but MUST try to insert the requested options in the order requested
    /// by the client.
    ///
    /// The code for this option is 55.  Its minimum length is 1.
    ///
    /// ```text
    /// Code   Len   Option Codes
    /// +-----+-----+-----+-----+---
    /// |  55 |  n  |  c1 |  c2 | ...
    /// +-----+-----+-----+-----+---
    /// ```
    ParameterRequestList(Vec<u8>) = 55,
    /// This option is used by a DHCP server to provide an error message to a
    /// DHCP client in a DHCPNAK message in the event of a failure. A client
    /// may use this option in a DHCPDECLINE message to indicate the why the
    /// client declined the offered parameters.  The message consists of n
    /// octets of NVT ASCII text, which the client may display on an
    /// available output device.
    ///
    /// The code for this option is 56 and its minimum length is 1.
    ///
    /// ```text
    /// Code   Len     Text
    /// +-----+-----+-----+-----+---
    /// |  56 |  n  |  c1 |  c2 | ...
    /// +-----+-----+-----+-----+---
    /// ```
    Message(String) = 56,
    /// This option specifies the maximum length DHCP message that it is
    /// willing to accept.  The length is specified as an unsigned 16-bit
    /// integer.  A client may use the maximum DHCP message size option in
    /// DHCPDISCOVER or DHCPREQUEST messages, but should not use the option
    /// in DHCPDECLINE messages.
    ///
    /// The code for this option is 57, and its length is 2.  The minimum
    /// legal value is 576 octets.
    ///
    /// ```text
    /// Code   Len     Length
    /// +-----+-----+-----+-----+
    /// |  57 |  2  |  l1 |  l2 |
    /// +-----+-----+-----+-----+
    /// ```
    MaximumDHCPMessageSize(u16) = 57,
    /// This option specifies the time interval from address assignment until
    /// the client transitions to the RENEWING state.
    ///
    /// The value is in units of seconds, and is specified as a 32-bit
    /// unsigned integer.
    ///
    /// The code for this option is 58, and its length is 4.
    ///
    /// ```text
    /// Code   Len         T1 Interval
    /// +-----+-----+-----+-----+-----+-----+
    /// |  58 |  4  |  t1 |  t2 |  t3 |  t4 |
    /// +-----+-----+-----+-----+-----+-----+
    /// ```
    RenewalTimeValue(u32) = 58,
    /// This option specifies the time interval from address assignment until
    /// the client transitions to the REBINDING state.
    ///
    /// The value is in units of seconds, and is specified as a 32-bit
    /// unsigned integer.
    ///
    /// The code for this option is 59, and its length is 4.
    ///
    /// ```text
    /// Code   Len         T2 Interval
    /// +-----+-----+-----+-----+-----+-----+
    /// |  59 |  4  |  t1 |  t2 |  t3 |  t4 |
    /// +-----+-----+-----+-----+-----+-----+
    /// ```
    RebindingTimeValue(u32) = 59,
    /// This option is used by DHCP clients to optionally identify the type
    /// and configuration of a DHCP client.  The information is a string of n
    /// octets, interpreted by servers.  Vendors and sites may choose to
    /// define specific class identifiers to convey particular configuration
    /// or other identification information about a client.  For example, the
    /// identifier may encode the client's hardware configuration.  Servers
    /// not equipped to interpret the class-specific information sent by a
    /// client MUST ignore it (although it may be reported).
    ///
    /// The code for this option is 60, and its minimum length is 1.
    ///
    /// ```text
    /// Code   Len   Class-Identifier
    /// +-----+-----+-----+-----+---
    /// |  60 |  n  |  i1 |  i2 | ...
    /// +-----+-----+-----+-----+---
    /// ```
    ClassIdentifier(String) = 60,
    /// This option is used by DHCP clients to specify their unique
    /// identifier.  DHCP servers use this value to index their database of
    /// address bindings.  This value is expected to be unique for all
    /// clients in an administrative domain.
    ///
    /// Identifiers consist of a type-value pair, similar to the
    ///
    /// It is expected that this field will typically contain a hardware type
    /// and hardware address, but this is not required.  Current legal values
    /// for hardware types are defined in <https://datatracker.ietf.org/doc/html/rfc1340>.
    ///
    /// The code for this option is 61, and its minimum length is 2.
    ///
    /// ```text
    /// Code   Len   Type  Client-Identifier
    /// +-----+-----+-----+-----+-----+---
    /// |  61 |  n  |  t1 |  i1 |  i2 | ...
    /// +-----+-----+-----+-----+-----+---
    /// ```
    // I'm just going to assume this is a Mac Address and drop it otherwise
    ClientIdentifier(MacAddr) = 61,
    // TODO Implement Option 121 - RFC3442
}

impl WriteToBuffer for DHCPOption {
    fn encoded_length(&self) -> usize {
        #[allow(clippy::match_same_arms)]
        match self {
            Self::SubnetMask(_) => 4,
            Self::TimeOffset(_) => 4,
            Self::RouterOption(o) => o.len() * 4,
            Self::DomainNameServerOption(o) => o.len() * 4,
            Self::HostNameOption(s) => s.len(),
            Self::DomainName(s) => s.len(),
            Self::PathMTUAgingTimeoutOption(_) => 4,
            Self::PathMTUPlateauOption(o) => o.len() * 2,
            Self::BroadcastAddressOption(_) => 4,
            Self::StaticRouteOption(o) => o.len() * 8,
            Self::NetworkTimeProtocolServersOption(o) => o.len() * 4,
            Self::RequestedIpAddress(_) => 4,
            Self::IPAddressLeaseTime(_) => 4,
            Self::OptionsOverload(_) => 1,
            Self::DHCPMessageType(_) => 1,
            Self::ServerIdentifier(_) => 4,
            Self::ParameterRequestList(o) => o.len(),
            Self::Message(s) => s.len(),
            Self::MaximumDHCPMessageSize(_) => 2,
            Self::RenewalTimeValue(_) => 4,
            Self::RebindingTimeValue(_) => 4,
            Self::ClassIdentifier(s) => s.len(),
            Self::ClientIdentifier(_) => 1 + MacAddr::LENGTH,
        }
    }

    fn write_to_buffer<Buf: BufMut>(&self, mut buffer: Buf) {
        match self {
            Self::SubnetMask(o) => {
                buffer.put_u8(OptionCode::SubnetMask as u8);
                Self::write_ipv4_address(&mut buffer, o);
            }
            Self::TimeOffset(o) => {
                buffer.put_u8(OptionCode::TimeOffset as u8);
                Self::write_i32(&mut buffer, *o);
            }
            Self::RouterOption(o) => {
                buffer.put_u8(OptionCode::RouterOption as u8);
                Self::write_vec_ipv4_address(&mut buffer, o);
            }
            Self::DomainNameServerOption(o) => {
                buffer.put_u8(OptionCode::DomainNameServerOption as u8);
                Self::write_vec_ipv4_address(&mut buffer, o);
            }
            Self::HostNameOption(o) => {
                buffer.put_u8(OptionCode::HostNameOption as u8);
                Self::write_string(&mut buffer, o);
            }
            Self::DomainName(o) => {
                buffer.put_u8(OptionCode::DomainName as u8);
                Self::write_string(&mut buffer, o);
            }
            Self::PathMTUAgingTimeoutOption(o) => {
                buffer.put_u8(OptionCode::PathMTUAgingTimeoutOption as u8);
                Self::write_u32(&mut buffer, *o);
            }
            Self::PathMTUPlateauOption(o) => {
                buffer.put_u8(OptionCode::PathMTUPlateauOption as u8);
                Self::write_vec_u16(&mut buffer, o);
            }
            Self::BroadcastAddressOption(o) => {
                buffer.put_u8(OptionCode::BroadcastAddressOption as u8);
                Self::write_ipv4_address(&mut buffer, o);
            }
            Self::StaticRouteOption(o) => {
                buffer.put_u8(OptionCode::StaticRouteOption as u8);
                Self::write_vec_ipv4_address_tuple(&mut buffer, o);
            }
            Self::NetworkTimeProtocolServersOption(o) => {
                buffer.put_u8(OptionCode::NetworkTimeProtocolServersOption as u8);
                Self::write_vec_ipv4_address(&mut buffer, o);
            }
            Self::RequestedIpAddress(o) => {
                buffer.put_u8(OptionCode::RequestedIpAddress as u8);
                Self::write_ipv4_address(&mut buffer, o);
            }
            Self::IPAddressLeaseTime(o) => {
                buffer.put_u8(OptionCode::IPAddressLeaseTime as u8);
                Self::write_u32(&mut buffer, *o);
            }
            Self::OptionsOverload(o) => {
                buffer.put_u8(OptionCode::OptionsOverload as u8);
                Self::write_options_overload(&mut buffer, *o);
            }
            Self::DHCPMessageType(o) => {
                buffer.put_u8(OptionCode::DHCPMessageType as u8);
                Self::write_dhcp_message_type(&mut buffer, *o);
            }
            Self::ServerIdentifier(o) => {
                buffer.put_u8(OptionCode::ServerIdentifier as u8);
                Self::write_ipv4_address(&mut buffer, o);
            }
            Self::ParameterRequestList(o) => {
                buffer.put_u8(OptionCode::ParameterRequestList as u8);
                buffer.put_u8(o.len() as u8);
                buffer.put_slice(o);
            }
            Self::Message(o) => {
                buffer.put_u8(OptionCode::Message as u8);
                Self::write_string(&mut buffer, o);
            }
            Self::MaximumDHCPMessageSize(o) => {
                buffer.put_u8(OptionCode::MaximumDHCPMessageSize as u8);
                Self::write_u16(&mut buffer, *o);
            }
            Self::RenewalTimeValue(o) => {
                buffer.put_u8(OptionCode::RenewalTimeValue as u8);
                Self::write_u32(&mut buffer, *o);
            }
            Self::RebindingTimeValue(o) => {
                buffer.put_u8(OptionCode::RebindingTimeValue as u8);
                Self::write_u32(&mut buffer, *o);
            }
            Self::ClassIdentifier(o) => {
                buffer.put_u8(OptionCode::ClassIdentifier as u8);
                Self::write_string(&mut buffer, o);
            }
            Self::ClientIdentifier(o) => {
                buffer.put_u8(OptionCode::ClientIdentifier as u8);
                buffer.put_u8(6);
                buffer.put_u8(1);
                buffer.put_slice(o.octets().as_ref());
            }
        }
    }
}

impl DHCPOption {
    fn parse(code: u8, data: &[u8]) -> Option<Self> {
        let Some(option) = OptionCode::from_repr(code) else {
            // We're not intersted in this option so jump by length
            debug!(
                "Found probably uninteresting DHCP Option {:?}={:?} ",
                code, data
            );
            return None;
        };

        match option {
            OptionCode::SubnetMask => Self::parse_ipv4_address(data).map(Self::SubnetMask),
            OptionCode::TimeOffset => Self::parse_i32(data).map(Self::TimeOffset),
            OptionCode::RouterOption => Self::parse_vec_ipv4_address(data).map(Self::RouterOption),
            OptionCode::DomainNameServerOption => {
                Self::parse_vec_ipv4_address(data).map(Self::DomainNameServerOption)
            }
            OptionCode::HostNameOption => Self::parse_string(data).map(Self::HostNameOption),
            OptionCode::DomainName => Self::parse_string(data).map(Self::DomainName),
            OptionCode::PathMTUAgingTimeoutOption => {
                Self::parse_u32(data).map(Self::PathMTUAgingTimeoutOption)
            }
            OptionCode::PathMTUPlateauOption => {
                Self::parse_vec_u16(data).map(Self::PathMTUPlateauOption)
            }
            OptionCode::BroadcastAddressOption => {
                Self::parse_ipv4_address(data).map(Self::BroadcastAddressOption)
            }
            OptionCode::StaticRouteOption => {
                Self::parse_vec_ipv4_address_tuple(data).map(Self::StaticRouteOption)
            }
            OptionCode::NetworkTimeProtocolServersOption => {
                Self::parse_vec_ipv4_address(data).map(Self::NetworkTimeProtocolServersOption)
            }
            OptionCode::RequestedIpAddress => {
                Self::parse_ipv4_address(data).map(Self::RequestedIpAddress)
            }
            OptionCode::IPAddressLeaseTime => Self::parse_u32(data).map(Self::IPAddressLeaseTime),
            OptionCode::OptionsOverload => {
                Self::parse_options_overload(data).map(Self::OptionsOverload)
            }
            OptionCode::DHCPMessageType => {
                Self::parse_dhcp_message_type(data).map(Self::DHCPMessageType)
            }
            OptionCode::ServerIdentifier => {
                Self::parse_ipv4_address(data).map(Self::ServerIdentifier)
            }
            OptionCode::ParameterRequestList => Some(Self::ParameterRequestList(data.to_vec())),
            OptionCode::Message => Self::parse_string(data).map(Self::Message),
            OptionCode::MaximumDHCPMessageSize => {
                Self::parse_u16(data).map(Self::MaximumDHCPMessageSize)
            }
            OptionCode::RenewalTimeValue => Self::parse_u32(data).map(Self::RenewalTimeValue),
            OptionCode::RebindingTimeValue => Self::parse_u32(data).map(Self::RebindingTimeValue),
            OptionCode::ClassIdentifier => Self::parse_string(data).map(Self::ClassIdentifier),
            OptionCode::ClientIdentifier => Self::parse_mac(data).map(Self::ClientIdentifier),
        }
    }

    fn parse_u16(data: &[u8]) -> Option<u16> {
        if data.len() == 2 {
            Some(u16::from_be_bytes([data[0], data[1]]))
        } else {
            None
        }
    }
    fn write_u16<A: BufMut>(buf: &mut A, data: u16) {
        buf.put_u8(2);
        buf.put_u16(data);
    }

    fn parse_u32(data: &[u8]) -> Option<u32> {
        if data.len() == 4 {
            Some(u32::from_be_bytes([data[0], data[1], data[2], data[3]]))
        } else {
            None
        }
    }
    fn write_u32<A: BufMut>(buf: &mut A, data: u32) {
        buf.put_u8(4);
        buf.put_u32(data);
    }

    fn parse_i32(data: &[u8]) -> Option<i32> {
        if data.len() == 4 {
            Some(i32::from_be_bytes([data[0], data[1], data[2], data[3]]))
        } else {
            None
        }
    }
    fn write_i32<A: BufMut>(buf: &mut A, data: i32) {
        buf.put_u8(4);
        buf.put_i32(data);
    }

    fn parse_vec_u16(data: &[u8]) -> Option<Vec<u16>> {
        if data.len() < 2 {
            None
        } else {
            Some(
                data.chunks_exact(2)
                    .map(|x| u16::from_be_bytes([x[0], x[1]]))
                    .collect(),
            )
        }
    }
    fn write_vec_u16<A: BufMut>(buf: &mut A, data: &Vec<u16>) {
        buf.put_u8(data.len() as u8 * 2);
        for val in data {
            buf.put_u16(*val);
        }
    }

    fn parse_string(data: &[u8]) -> Option<String> {
        String::from_utf8(data.to_vec()).ok()
    }
    fn write_string<A: BufMut>(buf: &mut A, data: &String) {
        let bytes = data.as_bytes();
        buf.put_u8(bytes.len() as u8);
        buf.put_slice(bytes);
    }

    fn parse_ipv4_address(data: &[u8]) -> Option<Ipv4Addr> {
        if data.len() == 4 {
            Some(Ipv4Addr::new(data[0], data[1], data[2], data[3]))
        } else {
            None
        }
    }
    fn write_ipv4_address<A: BufMut>(buf: &mut A, data: &Ipv4Addr) {
        buf.put_u8(4);
        buf.put_slice(&data.octets());
    }

    fn parse_vec_ipv4_address(data: &[u8]) -> Option<Vec<Ipv4Addr>> {
        if data.len() < 4 {
            None
        } else {
            Some(
                data.chunks_exact(4)
                    .map(|x| Ipv4Addr::new(x[0], x[1], x[2], x[3]))
                    .collect(),
            )
        }
    }
    fn write_vec_ipv4_address<A: BufMut>(buf: &mut A, data: &Vec<Ipv4Addr>) {
        buf.put_u8(data.len() as u8 * 4);
        for val in data {
            buf.put_slice(&val.octets());
        }
    }

    fn parse_vec_ipv4_address_tuple(data: &[u8]) -> Option<Vec<(Ipv4Addr, Ipv4Addr)>> {
        if data.len() < 8 {
            None
        } else {
            Some(
                data.chunks_exact(8)
                    .map(|x| {
                        (
                            Ipv4Addr::new(x[0], x[1], x[2], x[3]),
                            Ipv4Addr::new(x[4], x[5], x[6], x[7]),
                        )
                    })
                    .collect(),
            )
        }
    }
    fn write_vec_ipv4_address_tuple<A: BufMut>(buf: &mut A, data: &Vec<(Ipv4Addr, Ipv4Addr)>) {
        buf.put_u8(data.len() as u8 * 8);
        for val in data {
            buf.put_slice(&val.0.octets());
            buf.put_slice(&val.1.octets());
        }
    }

    fn parse_options_overload(data: &[u8]) -> Option<OptionsOverload> {
        if data.len() == 1 {
            match data[0] {
                1 => Some(OptionsOverload::File),
                2 => Some(OptionsOverload::ServerName),
                3 => Some(OptionsOverload::Both),
                _ => None,
            }
        } else {
            None
        }
    }
    fn write_options_overload<A: BufMut>(buf: &mut A, data: OptionsOverload) {
        buf.put_u8(1);
        buf.put_u8(data as u8);
    }

    fn parse_dhcp_message_type(data: &[u8]) -> Option<DHCPMessageType> {
        if data.len() == 1 {
            match data[0] {
                1 => Some(DHCPMessageType::Discover),
                2 => Some(DHCPMessageType::Offer),
                3 => Some(DHCPMessageType::Request),
                4 => Some(DHCPMessageType::Decline),
                5 => Some(DHCPMessageType::Ack),
                6 => Some(DHCPMessageType::Nak),
                7 => Some(DHCPMessageType::Release),
                _ => None,
            }
        } else {
            None
        }
    }
    fn write_dhcp_message_type<A: BufMut>(buf: &mut A, data: DHCPMessageType) {
        buf.put_u8(1);
        buf.put_u8(data as u8);
    }

    fn parse_mac(data: &[u8]) -> Option<MacAddr> {
        if data.len() != 7 || data[0] != 1u8 {
            None
        } else {
            Some(MacAddr::new(
                data[1], data[2], data[3], data[4], data[5], data[6],
            ))
        }
    }
}

#[derive(Debug)]
struct DHCPOptions(Vec<DHCPOption>);

impl DHCPOptions {
    fn with(&mut self, other: Self) {
        self.0.extend(other.0);
    }

    fn options_overload(&self) -> Option<OptionsOverload> {
        self.0.iter().find_map(|x| match x {
            DHCPOption::OptionsOverload(opt) => Some(*opt),
            _ => None,
        })
    }
}

impl From<&[u8]> for DHCPOptions {
    fn from(value: &[u8]) -> Self {
        let mut position = 0;
        let mut options = Vec::new();
        while position < value.len() {
            let code = value[position];
            // Increment the position now we have read code
            position += 1;

            // 255 = End
            if code == 255 {
                break;
            }

            // 0 = Pad - so skip it and move on
            if code == 0 {
                continue;
            }

            // Defence for reading the option length
            if position >= value.len() {
                break;
            }
            let length = value[position] as usize;
            // And increment position again now we have length (just staying current)
            position += 1;
            if position + length >= value.len() {
                break;
            }
            // Grab the data
            let data = &value[position..position + length];
            // and now we have the data increment
            position += length;

            if let Some(option) = DHCPOption::parse(code, data) {
                options.push(option);
            }
        }

        Self(options)
    }
}

impl WriteToBuffer for DHCPOptions {
    fn encoded_length(&self) -> usize {
        // Start at 1 as the options collection will contain at least 255 end
        self.0.iter().fold(1, |acc, x| acc + x.encoded_length())
    }

    fn write_to_buffer<Buf: BufMut>(&self, mut buffer: Buf) {
        for option in &self.0 {
            option.write_to_buffer(&mut buffer);
            buffer.put_u8(255);
        }
    }
}

/// DHCP Message
///
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     op (1)    |   htype (1)   |   hlen (1)    |   hops (1)    |
/// +---------------+---------------+---------------+---------------+
/// |                            xid (4)                            |
/// +-------------------------------+-------------------------------+
/// |           secs (2)            |           flags (2)           |
/// +-------------------------------+-------------------------------+
/// |                          ciaddr  (4)                          |
/// +---------------------------------------------------------------+
/// |                          yiaddr  (4)                          |
/// +---------------------------------------------------------------+
/// |                          siaddr  (4)                          |
/// +---------------------------------------------------------------+
/// |                          giaddr  (4)                          |
/// +---------------------------------------------------------------+
/// |                                                               |
/// |                          chaddr  (16)                         |
/// |                                                               |
/// |                                                               |
/// +---------------------------------------------------------------+
/// |                                                               |
/// |                          sname   (64)                         |
/// +---------------------------------------------------------------+
/// |                                                               |
/// |                          file    (128)                        |
/// +---------------------------------------------------------------+
/// |                                                               |
/// |                          options (variable)                   |
/// +---------------------------------------------------------------+
/// ```
#[derive(Debug)]
pub struct DHCP {
    /// Message op code / message type.
    /// 1 = BOOTREQUEST, 2 = BOOTREPLY
    operation: Operation,
    // Hardware address type, see ARP section in "Assigned Numbers" RFC; e.g., '1' = 10mb ethernet.
    // hardware_type: super::super::arp::HardwareType,
    // Hardware address length (e.g.  '6' for 10mb ethernet).
    // hardware_len: u8, // this is defined by the above
    /// Client sets to zero, optionally used by relay agents when booting via a relay agent.
    hops: u8,
    /// Transaction ID, a random number chosen by the client, used by the client and server
    /// to associate messages and responses between a client and a server.
    transaction_id: u32, // or maybe [u8;4]
    /// Filled in by client, seconds elapsed since client began address acquisition or renewal process.
    secs: u16,
    /// see [`Flags`]
    flags: Flags,
    /// Client IP address; only filled in if client is in BOUND, RENEW or REBINDING state
    /// and can respond to ARP requests.
    client_ip_addr: Option<Ipv4Addr>,
    /// 'your' (client) IP address.
    /// -- that is the IP address offered to this client by the server to become its IP address
    your_ip_addr: Option<Ipv4Addr>,
    /// IP address of next server to use in bootstrap; returned in DHCPOFFER, DHCPACK by server.
    next_server_ip_addr: Option<Ipv4Addr>,
    /// Relay agent IP address, used in booting via a relay agent.
    relay_agent_ip_addr: Option<Ipv4Addr>,
    /// Client hardware Address
    client_hardware_addr: [u8; 16], // Not quite sure what this is but i don't think it's a mac addr
    /// Optional server host name, null terminated string.
    server_hostname: Option<String>,
    /// Boot file name, null terminated string; "generic" name or null in DHCPDISCOVER, fully qualified
    /// directory-path name in DHCPOFFER.
    boot_file_name: Option<String>,
    /// Optional parameters field.  See the options documents for a list of defined options.
    options: DHCPOptions,
}

impl TryFrom<&[u8]> for DHCP {
    type Error = std::io::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() < Self::MIN_LENGTH {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        // Magic cookie!
        if value[236..240] != [0x63, 0x82, 0x53, 0x63] {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid magic cookie",
            ));
        }

        let operation = match value[0] {
            1 => Operation::BootRequest,
            2 => Operation::BootReply,
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Invalid BOOTP Operation",
                ));
            }
        };

        if value[1] != 1u8 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Unsupported Hardware Type",
            ));
        }

        // let hardware_type = HardwareType::Ethernet;
        // let hardware_len = value[2];
        let hops = value[3];

        let transaction_id = u32::from_be_bytes([value[4], value[5], value[6], value[7]]);
        let secs = u16::from_be_bytes([value[8], value[9]]);
        let flags = [value[10], value[11]].try_into()?;

        let client_ip_addr = match [value[12], value[13], value[14], value[15]] {
            [0, 0, 0, 0] => None,
            [a, b, c, d] => Some(Ipv4Addr::new(a, b, c, d)),
        };
        let your_ip_addr = match [value[16], value[17], value[18], value[19]] {
            [0, 0, 0, 0] => None,
            [a, b, c, d] => Some(Ipv4Addr::new(a, b, c, d)),
        };
        let next_server_ip_addr = match [value[20], value[21], value[22], value[23]] {
            [0, 0, 0, 0] => None,
            [a, b, c, d] => Some(Ipv4Addr::new(a, b, c, d)),
        };
        let relay_agent_ip_addr = match [value[24], value[25], value[26], value[27]] {
            [0, 0, 0, 0] => None,
            [a, b, c, d] => Some(Ipv4Addr::new(a, b, c, d)),
        };
        let client_hardware_addr = value[28..44]
            .try_into()
            .map_err(err_as_eof("unable to parse client hardware address"))?;

        let mut options: DHCPOptions = value[240..].into();
        let overload = options.options_overload();

        let mut server_hostname = None;
        if let Some(OptionsOverload::ServerName | OptionsOverload::Both) = overload {
            options.with(value[44..108].into());
        } else {
            server_hostname = str_from_null_terminated_utf8(&value[44..108])?
                .map(std::string::ToString::to_string);
        }

        let mut boot_file_name = None;
        if let Some(OptionsOverload::File | OptionsOverload::Both) = overload {
            options.with(value[108..236].into());
        } else {
            boot_file_name = str_from_null_terminated_utf8(&value[108..236])?
                .map(std::string::ToString::to_string);
        }

        Ok(Self {
            operation,
            hops,
            transaction_id,
            secs,
            flags,
            client_ip_addr,
            your_ip_addr,
            next_server_ip_addr,
            relay_agent_ip_addr,
            client_hardware_addr,
            server_hostname,
            boot_file_name,
            options,
        })
    }
}

impl WriteToBuffer for DHCP {
    fn encoded_length(&self) -> usize {
        (const {
            4 // op, htype, hlem, hops
            + 4 // xid
            + 4 // secs + flags
            + 16 // ciaddr, yiaddr, siaddr, giaddr
            + 16 // chaddr
            + 64 // sname
            + 128 // file
        }) + self.options.encoded_length()
    }

    fn write_to_buffer<Buf: BufMut>(&self, mut buffer: Buf) {
        buffer.put_u8(self.operation.into());
        buffer.put_u8(1); // Ethernet
        buffer.put_u8(6); // Ethernet=6 Octets
        buffer.put_u8(self.hops);

        buffer.put_u32(self.transaction_id);

        buffer.put_u16(self.secs);
        buffer.put_u16(self.flags.into());

        if let Some(ciaddr) = self.client_ip_addr {
            buffer.put_slice(&ciaddr.octets());
        } else {
            buffer.put_u32(0);
        }

        if let Some(yiaddr) = self.your_ip_addr {
            buffer.put_slice(&yiaddr.octets());
        } else {
            buffer.put_u32(0);
        }

        if let Some(siaddr) = self.next_server_ip_addr {
            buffer.put_slice(&siaddr.octets());
        } else {
            buffer.put_u32(0);
        }

        if let Some(giaddr) = self.relay_agent_ip_addr {
            buffer.put_slice(&giaddr.octets());
        } else {
            buffer.put_u32(0);
        }

        buffer.put_slice(&self.client_hardware_addr[..]);

        // TODO check options for if we're packing options into server hostname and/or boot file
        // name
        if let Some(server_hostname) = &self.server_hostname {
            buffer.put_slice(&server_hostname.as_bytes()[..64]);
        }
        if let Some(boot_file_name) = &self.boot_file_name {
            buffer.put_slice(&boot_file_name.as_bytes()[..128]);
        }
    }
}

impl DHCP {
    /// 236 DHCP/BOOTP Message Header + 4 byte "Magic Cookie"
    // I don't think this would actually be a valid DHCP packet but thats to be determined as we dive into the spec
    const MIN_LENGTH: usize = 240;

    /// DHCPDISCOVER
    /// Client broadcast to locate available servers.
    ///
    /// Page 36
    pub fn discover(transaction_id: u32, started: time::Instant, mac_addr: MacAddr) -> Self {
        let mut client_hardware_addr = [0u8; 16];
        client_hardware_addr[..6].copy_from_slice(&mac_addr.octets());

        let mut options = Vec::new();
        // TODO requested IP Address
        // TODO Ip Address Lease time

        options.push(DHCPOption::DHCPMessageType(DHCPMessageType::Discover));

        // TODO client identifier
        // TODO vendor class information ??
        // TODO parameter request list
        // TODO maximum message size

        Self {
            operation: Operation::BootRequest,
            hops: 0,
            transaction_id,
            secs: time::Instant::now().duration_since(started).as_secs() as u16,
            flags: Flags { broadcast: false }, // or true?
            client_ip_addr: None,
            your_ip_addr: None,
            next_server_ip_addr: None,
            relay_agent_ip_addr: None,
            client_hardware_addr,
            server_hostname: None,
            boot_file_name: None,
            options: DHCPOptions(options),
        }
    }

    /// DHCPOFFER
    /// Server to client in response to DHCPDISCOVER with offer of configuration parameters.
    ///
    /// NOT IMPLEMENTED
    pub fn offer() -> Self {
        unimplemented!()
    }

    /// DHCPREQUEST
    /// Client message to servers either (a) requesting offered parameters from one server and
    /// implicitly declining offers from all others, (b) confirming correctness of previously
    /// allocated address after, e.g., system reboot, or (c) extending the lease on a particular
    /// network address.
    pub fn request() -> Self {
        todo!()
    }

    /// DHCPACK
    /// Server to client with configuration parameters, including committed network address.
    ///
    /// NOT IMPLEMENTED
    pub fn ack() -> Self {
        unimplemented!()
    }

    /// DHCPNAK
    /// Server to client indicating client's notion of network address is incorrect (e.g., client
    /// has moved to new subnet) or client's lease as expired
    ///
    /// NOT IMPLEMENTED
    pub fn nack() -> Self {
        unimplemented!()
    }

    /// DHCPDECLINE
    /// Client to server indicating network address is already in use.
    pub fn decline() -> Self {
        todo!()
    }

    /// DHCPRELEASE
    /// Client to server relinquishing network address and cancelling remaining lease.
    pub fn release() -> Self {
        todo!()
    }

    /// DHCPINFORM
    /// Client to server, asking only for local configuration parameters; client already has
    /// externally configured network address.
    pub fn inform() -> Self {
        todo!()
    }
}

fn str_from_null_terminated_utf8(s: &[u8]) -> std::io::Result<Option<&str>> {
    let Some(null_pos) = s.iter().position(|&x| x == b'\0') else {
        return Err(std::io::ErrorKind::InvalidData.into());
    };

    if null_pos == 0 {
        return Ok(None);
    }

    std::str::from_utf8(&s[..null_pos])
        .map(Some)
        .map_err(|x| std::io::Error::new(std::io::ErrorKind::InvalidData, x))
}
