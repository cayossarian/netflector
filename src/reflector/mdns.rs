//! The mDNS reflector: queries flow source → target, responses target → source, each re-emitted to
//! the same group at TTL 255 (RFC 6762 §11) from the egress interface.
//!
//! Answers bound for a side with peers go to each peer as a unicast copy, on purpose. RFC 6762
//! §5.4 has a client take a unicast answer only to a question it asked with the unicast-response
//! bit: Apple's resolver enforces that (within two seconds of the question, from a source on the
//! interface's subnet; mDNSResponder's `ExpectingUnicastResponseForRecord`), Avahi takes any
//! answer from the link. iOS asks that way when a browse starts, so the copies serve Apple clients
//! for their initial discovery and Avahi ones throughout. The alternative on such a link, a
//! multicast answer, reaches nobody, so the RFC is no reason to refuse the peers here.
//!
//! Limitation: a legacy querier asking from an ephemeral port expects its answer there, but the
//! relayed query is sourced from port 5353, so the device answers on the group, which that
//! querier does not listen on.
//!
//! An entry's `mdns_services` allow-list gates both legs after the direction check: a query goes
//! out unless every question names a refused service, and a response is dropped when it names
//! services and none is allowed. A response naming both is re-emitted trimmed of the refused
//! records ([`Trimmer`]), the one place the relay is not verbatim.

use std::net::SocketAddr;

use crate::config::Reflector;
use crate::dispatch::{CaptureKey, Filter, IpSet, MessageType, PacketDispatcher};
use crate::net::mdns::services::{Scope, ServiceList, Trimmer, scope};
use crate::net::mdns::{
    MDNS_GROUP_V4, MDNS_GROUP_V6, MDNS_PORT, MDNS_TTL, MdnsKind, advertises_only_unreachable,
    classify,
};
use crate::net::packet::Packet;
use crate::reactor::Reactor;

use super::{
    BuildError, Classify, Delivery, Emit, InterfaceMap, NoRewrite, ReplyRewrite, SimpleReflector,
    Verdict, directional_verdict, group_addrs, open_pair,
};

impl From<MdnsKind> for MessageType {
    fn from(kind: MdnsKind) -> Self {
        match kind {
            MdnsKind::Query => Self::MdnsQuery,
            MdnsKind::Response => Self::MdnsResponse,
        }
    }
}

/// One leg's ingress gate: the direction check, then the entry's allow-list.
struct Gate {
    kind: MdnsKind,
    services: Option<ServiceList>,
}

impl Gate {
    fn new(kind: MdnsKind, services: Option<ServiceList>) -> Self {
        Self { kind, services }
    }

    fn verdict(&self, payload: &[u8]) -> Verdict {
        let verdict = directional_verdict(classify(payload), self.kind);
        match (verdict, &self.services) {
            (Verdict::Reflect(message_type), Some(services)) => match scope(payload, services) {
                Scope::Refuse => Verdict::Refused(message_type),
                Scope::Malformed => Verdict::Junk,
                Scope::Pass | Scope::Trim => verdict,
            },
            _ => verdict,
        }
    }
}

impl Classify for Gate {
    fn classify(&self, packet: &Packet) -> Verdict {
        let verdict = self.verdict(packet.payload);
        if let Verdict::Refused(_) = verdict {
            log::debug!(
                "mDNS: not reflecting {:?} from {}: it names only services outside mdns_services",
                self.kind,
                packet.source
            );
        }
        verdict
    }
}

/// The response leg's trim of a mixed response; see [`Trimmer`].
struct ServiceTrim(Trimmer);

impl ReplyRewrite for ServiceTrim {
    fn rewrite<'a>(
        &'a mut self,
        payload: &[u8],
        _egress: CaptureKey,
        _dispatcher: &mut PacketDispatcher,
        _reactor: &mut Reactor,
    ) -> Option<&'a [u8]> {
        self.0.trim(payload)
    }

    fn keeps_advertised_addresses(&self) -> bool {
        true
    }
}

/// # Errors
/// As [`open_pair`].
pub(crate) fn build(
    reflector: &Reflector,
    interfaces: &InterfaceMap,
    dispatcher: &mut PacketDispatcher,
) -> Result<(), BuildError> {
    let Some(mdns) = &reflector.mdns else {
        return Ok(());
    };
    let groups = group_addrs(
        reflector.address_family,
        MDNS_PORT,
        MDNS_GROUP_V4,
        &[MDNS_GROUP_V6],
    );
    let (source, target) = open_pair(reflector, interfaces, dispatcher, "mDNS", &groups)?;
    let group_ips: IpSet = groups.iter().map(SocketAddr::ip).collect();
    // source → target: queries.
    dispatcher.register(
        source,
        Filter {
            dst_ip: Some(group_ips.clone()),
            dst_port: Some(MDNS_PORT.into()),
            ..Filter::default()
        },
        Box::new(SimpleReflector::new(
            target,
            Delivery::new(reflector.target_peers.as_ref()),
            "mDNS",
            "query",
            Gate::new(MdnsKind::Query, mdns.services.clone()),
            Emit::fixed(MDNS_PORT, MDNS_TTL),
        )),
    );
    // target → source: responses. `dst_own` takes in an answer sent to this host rather than the
    // group (a QU query, RFC 6762 §5.4, or one that reached a peer as unicast, §5.5). `src_port`:
    // a response from anywhere but 5353 is ignored by every client (§6).
    dispatcher.register(
        target,
        Filter {
            src_port: Some(MDNS_PORT),
            dst_ip: Some(group_ips),
            dst_port: Some(MDNS_PORT.into()),
            src_mac: reflector.macs.clone(),
            dst_own: Some(reflector.address_family),
            ..Filter::default()
        },
        Box::new(
            SimpleReflector::new(
                source,
                // To the source's peers as unicast copies, §5.4 notwithstanding: a deliberate
                // choice, reasoned in the module doc. Don't "fix" it back to the link.
                Delivery::new(reflector.source_peers.as_ref()),
                "mDNS",
                "response",
                Gate::new(MdnsKind::Response, mdns.services.clone()),
                Emit::fixed(MDNS_PORT, MDNS_TTL).unicast_to_group(MDNS_GROUP_V4, MDNS_GROUP_V6),
            )
            .with_rewrite(match &mdns.services {
                Some(services) => Box::new(ServiceTrim(Trimmer::new(services.clone()))),
                None => Box::new(NoRewrite),
            })
            // Queries carry no advertisement, so only this leg checks.
            .with_suppress(advertises_only_unreachable),
        ),
    );
    log::info!(
        "mDNS reflector \"{}\": {} <-> {}",
        reflector.name.as_str(),
        reflector.source_if,
        reflector.target_if
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `text` in wire form, uncompressed.
    fn name(text: &str) -> Vec<u8> {
        let mut wire = Vec::new();
        for label in text.split('.') {
            wire.push(u8::try_from(label.len()).unwrap());
            wire.extend_from_slice(label.as_bytes());
        }
        wire.push(0);
        wire
    }

    /// A query with one PTR question for `question`.
    fn ptr_query(question: &str) -> Vec<u8> {
        let mut m = vec![0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        m.extend(name(question));
        m.extend_from_slice(&[0, 12, 0, 1]);
        m
    }

    /// A response with one PTR answer per `(owner, target)`.
    fn ptr_response(answers: &[(&str, &str)]) -> Vec<u8> {
        let mut m = vec![
            0,
            0,
            0x84,
            0,
            0,
            0,
            0,
            u8::try_from(answers.len()).unwrap(),
            0,
            0,
            0,
            0,
        ];
        for (owner, target) in answers {
            m.extend(name(owner));
            m.extend_from_slice(&[0, 12, 0, 1, 0, 0, 0, 120]);
            let rdata = name(target);
            m.extend_from_slice(&u16::try_from(rdata.len()).unwrap().to_be_bytes());
            m.extend(rdata);
        }
        m
    }

    #[test]
    fn verdicts_gate_by_direction() {
        // A 12-byte DNS header: QR bit (offset 2, 0x80) clear = query, set = response; shorter = junk.
        let query = [0u8; 12];
        let mut response = [0u8; 12];
        response[2] = 0x80;
        let queries = Gate::new(MdnsKind::Query, None);
        let responses = Gate::new(MdnsKind::Response, None);
        assert_eq!(
            queries.verdict(&query),
            Verdict::Reflect(MessageType::MdnsQuery)
        );
        assert_eq!(
            queries.verdict(&response),
            Verdict::Skip(MessageType::MdnsResponse)
        );
        assert_eq!(queries.verdict(&[0u8; 4]), Verdict::Junk);
        assert_eq!(
            responses.verdict(&query),
            Verdict::Skip(MessageType::MdnsQuery)
        );
        assert_eq!(
            responses.verdict(&response),
            Verdict::Reflect(MessageType::MdnsResponse)
        );
        assert_eq!(responses.verdict(&[0u8; 4]), Verdict::Junk);
    }

    #[test]
    fn the_allow_list_excludes_what_names_only_refused_services() {
        let services: Option<ServiceList> = Some("_ipp._tcp".parse().unwrap());
        let queries = Gate::new(MdnsKind::Query, services.clone());
        let responses = Gate::new(MdnsKind::Response, services);
        assert_eq!(
            queries.verdict(&ptr_query("_hap._tcp.local")),
            Verdict::Refused(MessageType::MdnsQuery)
        );
        assert_eq!(
            queries.verdict(&ptr_query("_ipp._tcp.local")),
            Verdict::Reflect(MessageType::MdnsQuery)
        );
        assert_eq!(
            responses.verdict(&ptr_response(&[("_hap._tcp.local", "L._hap._tcp.local")])),
            Verdict::Refused(MessageType::MdnsResponse)
        );
        // A message the allow-list cannot walk is junk, not a refusal of some service.
        let mut truncated = ptr_response(&[("_ipp._tcp.local", "L._ipp._tcp.local")]);
        truncated.truncate(truncated.len() - 3);
        assert_eq!(responses.verdict(&truncated), Verdict::Junk);
        // A mixed response is reflected; the trim takes the refused records out.
        let mixed = ptr_response(&[
            ("_hap._tcp.local", "L._hap._tcp.local"),
            ("_ipp._tcp.local", "L._ipp._tcp.local"),
        ]);
        assert_eq!(
            responses.verdict(&mixed),
            Verdict::Reflect(MessageType::MdnsResponse)
        );
        // The direction gate runs first: a refused query on the response leg is still a Skip.
        assert_eq!(
            responses.verdict(&ptr_query("_hap._tcp.local")),
            Verdict::Skip(MessageType::MdnsQuery)
        );
    }

    #[test]
    fn a_trim_keeps_the_unreachable_advertisement_check() {
        let trim = ServiceTrim(Trimmer::new("_ipp._tcp".parse().unwrap()));
        assert!(trim.keeps_advertised_addresses());
    }
}
