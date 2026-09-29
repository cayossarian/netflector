//! The DNS-SD service-type allow-list an mDNS entry can carry (`mdns_services`).

use std::cell::Cell;
use std::fmt::{self, Write as _};
use std::str::FromStr;

use serde::{Deserialize, Deserializer};
use thiserror::Error;

use super::{
    ANCOUNT_AT, ARCOUNT_AT, DNS_HEADER_LEN, MdnsKind, NSCOUNT_AT, QDCOUNT_AT, classify, skip_name,
};
use crate::unique_list::{ListRule, UniqueList};

/// The longest service label: a DNS label (63 octets, RFC 1035 §2.3.4) less its underscore.
/// RFC 6335 §5.1 caps a registered service name at 15, but unregistered ones run longer in the
/// wild (`_androidtvremote2`), so only the DNS limit is enforced.
const MAX_SERVICE_LEN: usize = 62;

/// A name spans at most 255 octets (RFC 1035 §3.1).
const MAX_NAME_LEN: usize = 255;
/// Each hop must add a label to stay under [`MAX_NAME_LEN`], so more hops than that can only loop.
const MAX_POINTER_HOPS: usize = MAX_NAME_LEN / 2;

const TYPE_NS: u16 = 2;
const TYPE_MD: u16 = 3;
const TYPE_MF: u16 = 4;
const TYPE_CNAME: u16 = 5;
const TYPE_SOA: u16 = 6;
const TYPE_MB: u16 = 7;
const TYPE_MG: u16 = 8;
const TYPE_MR: u16 = 9;
const TYPE_PTR: u16 = 12;
const TYPE_MINFO: u16 = 14;
const TYPE_MX: u16 = 15;
const TYPE_RP: u16 = 17;
const TYPE_AFSDB: u16 = 18;
const TYPE_RT: u16 = 21;
const TYPE_PX: u16 = 26;
const TYPE_SRV: u16 = 33;
const TYPE_KX: u16 = 36;
const TYPE_NSEC: u16 = 47;
const TYPE_DNAME: u16 = 39;

/// The transport label of a service type (RFC 6763 §7): `_tcp`, or `_udp` for everything else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    /// Case-insensitive, as DNS labels are.
    fn from_label(label: &[u8]) -> Option<Self> {
        if label.eq_ignore_ascii_case(b"_tcp") {
            Some(Self::Tcp)
        } else if label.eq_ignore_ascii_case(b"_udp") {
            Some(Self::Udp)
        } else {
            None
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Tcp => "_tcp",
            Self::Udp => "_udp",
        }
    }
}

/// The mDNS domain (RFC 6762 §3), accepted after a service type.
const LOCAL_SUFFIX: &[u8] = b".local";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("expected a DNS-SD service type such as \"_ipp._tcp\"")]
pub(crate) struct ParseServiceTypeError;

/// A DNS-SD service type, `_<service>._<proto>` (RFC 6763 §7). Stored ASCII-lowercased, the
/// service label without its underscore, so `Eq` is DNS's case-insensitive identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ServiceType {
    service: [u8; MAX_SERVICE_LEN],
    len: u8,
    proto: Proto,
}

impl ServiceType {
    fn service(&self) -> &[u8] {
        &self.service[..usize::from(self.len)]
    }
}

impl fmt::Display for ServiceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_char('_')?;
        // ASCII by construction.
        for &b in self.service() {
            f.write_char(char::from(b))?;
        }
        write!(f, ".{}", self.proto.label())
    }
}

impl FromStr for ServiceType {
    type Err = ParseServiceTypeError;

    /// `_<service>._tcp` or `_<service>._udp`, optionally followed by the `local` domain and a
    /// root dot, which are dropped. The service label takes letters, digits, hyphens and
    /// underscores.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.strip_suffix('.').unwrap_or(s);
        let s = match s.len().checked_sub(LOCAL_SUFFIX.len()) {
            // The suffix is ASCII, so the cut falls on a char boundary.
            Some(cut) if s.as_bytes()[cut..].eq_ignore_ascii_case(LOCAL_SUFFIX) => &s[..cut],
            _ => s,
        };
        let (service, proto) = s.split_once('.').ok_or(ParseServiceTypeError)?;
        let proto = Proto::from_label(proto.as_bytes()).ok_or(ParseServiceTypeError)?;
        let service = service
            .strip_prefix('_')
            .map(str::as_bytes)
            .filter(|service| (1..=MAX_SERVICE_LEN).contains(&service.len()))
            .filter(|service| {
                service
                    .iter()
                    .all(|&b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            })
            .ok_or(ParseServiceTypeError)?;
        let mut stored = [0u8; MAX_SERVICE_LEN];
        stored[..service.len()].copy_from_slice(service);
        stored.make_ascii_lowercase();
        Ok(Self {
            service: stored,
            len: u8::try_from(service.len()).expect("at most MAX_SERVICE_LEN"),
            proto,
        })
    }
}

impl<'de> Deserialize<'de> for ServiceType {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

/// The rule for [`ServiceList`]: any service type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Services;

impl ListRule for Services {
    type Item = ServiceType;

    const NOUN: &'static str = "service type";
}

/// A non-empty, duplicate-free list of DNS-SD service types.
pub(crate) type ServiceList = UniqueList<Services>;

/// What an allow-list makes of one message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Scope {
    /// Nothing service-scoped in it is refused: relay it verbatim.
    Pass,
    /// Nothing service-scoped in it is allowed, or it is malformed: do not relay it.
    Refuse,
    /// A response carrying both: relay it with the refused records removed.
    Trim,
    /// Not walkable within bounds: truncated, a reserved label type, a looping or overlong name,
    /// or more work than the message is long. Never relayed while a list is set.
    Malformed,
}

/// A message this module cannot walk: truncated, a reserved label type, a looping or overlong
/// name. The filter fails closed on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Malformed;

/// Label and pointer steps one message may cost across every walk of its names. Real traffic
/// stays under 1.5 per byte; a crafted message whose records all point into one long chain would
/// cost dozens, so it is refused as malformed before it can starve the reactor.
const STEPS_PER_BYTE: usize = 4;

/// The steps left for one message; see [`STEPS_PER_BYTE`].
struct Budget(Cell<usize>);

impl Budget {
    fn for_message(payload: &[u8]) -> Self {
        Self(Cell::new(payload.len().saturating_mul(STEPS_PER_BYTE)))
    }

    fn spend(&self) -> Result<(), Malformed> {
        let left = self.0.get().checked_sub(1).ok_or(Malformed)?;
        self.0.set(left);
        Ok(())
    }
}

/// A name's labels in order, compression pointers followed (RFC 1035 §4.1.4). Yields one error and
/// then ends.
struct Labels<'a, 'b> {
    payload: &'a [u8],
    at: usize,
    hops: usize,
    len: usize,
    done: bool,
    budget: &'b Budget,
}

impl<'a, 'b> Labels<'a, 'b> {
    fn new(payload: &'a [u8], at: usize, budget: &'b Budget) -> Self {
        Self {
            payload,
            at,
            hops: 0,
            len: 0,
            done: false,
            budget,
        }
    }

    fn step(&mut self) -> Result<Option<&'a [u8]>, Malformed> {
        loop {
            self.budget.spend()?;
            let len = *self.payload.get(self.at).ok_or(Malformed)?;
            match len {
                0 => return Ok(None),
                1..=0x3f => {
                    let start = self.at + 1;
                    let label = self
                        .payload
                        .get(start..start + usize::from(len))
                        .ok_or(Malformed)?;
                    self.len += 1 + label.len();
                    if self.len >= MAX_NAME_LEN {
                        return Err(Malformed);
                    }
                    self.at = start + label.len();
                    return Ok(Some(label));
                }
                0xc0..=0xff => {
                    let low = *self.payload.get(self.at + 1).ok_or(Malformed)?;
                    self.hops += 1;
                    if self.hops > MAX_POINTER_HOPS {
                        return Err(Malformed);
                    }
                    self.at = usize::from(len & 0x3f) << 8 | usize::from(low);
                }
                _ => return Err(Malformed),
            }
        }
    }
}

impl<'a> Iterator for Labels<'a, '_> {
    type Item = Result<&'a [u8], Malformed>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let step = self.step();
        self.done = !matches!(step, Ok(Some(_)));
        step.transpose()
    }
}

/// A message section (RFC 1035 §4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Section {
    Question,
    Answer,
    Authority,
    Additional,
}

/// One question or resource record, as offsets into the message (RFC 1035 §4.1.2 / §4.1.3).
/// A question has no rdata: `rdata == end`.
#[derive(Debug, Clone, Copy)]
struct Entry {
    section: Section,
    /// The owner name.
    name: usize,
    /// Just past the owner name's inline octets: TYPE and CLASS, then (records) TTL and RDLENGTH.
    fixed: usize,
    rtype: u16,
    rdata: usize,
    end: usize,
}

impl Entry {
    /// Every name the entry carries is walkable, and each inline part ends inside its rdata.
    fn check_names(self, payload: &[u8], budget: &Budget) -> Result<(), Malformed> {
        check_name(payload, self.name, budget)?;
        let Some((offset, count)) = rdata_names(self.rtype).filter(|_| self.rdata < self.end)
        else {
            return Ok(());
        };
        let mut at = self.rdata + offset;
        for _ in 0..count {
            check_name(payload, at, budget)?;
            at = skip_name(payload, at).ok_or(Malformed)?;
            if at > self.end {
                return Err(Malformed);
            }
        }
        Ok(())
    }

    /// The service type the entry falls under: a PTR's by its target, else by its owner.
    fn service<'a>(
        self,
        payload: &'a [u8],
        budget: &Budget,
    ) -> Result<Option<(&'a [u8], Proto)>, Malformed> {
        if self.rtype == TYPE_PTR
            && self.rdata < self.end
            && let Some(service) = service_of(payload, self.rdata, budget)?
        {
            return Ok(Some(service));
        }
        service_of(payload, self.name, budget)
    }
}

/// The message's entries in wire order, questions first. Yields one error and then ends.
struct Entries<'a> {
    payload: &'a [u8],
    at: usize,
    /// Entries still to come per section, in wire order.
    remaining: [(Section, usize); 4],
    done: bool,
}

impl<'a> Entries<'a> {
    fn new(payload: &'a [u8]) -> Self {
        let count = |at: usize| {
            payload
                .get(at..at + 2)
                .map_or(0, |n| usize::from(u16::from_be_bytes([n[0], n[1]])))
        };
        Self {
            payload,
            at: DNS_HEADER_LEN,
            remaining: [
                (Section::Question, count(QDCOUNT_AT)),
                (Section::Answer, count(ANCOUNT_AT)),
                (Section::Authority, count(NSCOUNT_AT)),
                (Section::Additional, count(ARCOUNT_AT)),
            ],
            done: payload.len() < DNS_HEADER_LEN,
        }
    }

    fn step(&mut self, section: Section) -> Result<Entry, Malformed> {
        let payload = self.payload;
        let name = self.at;
        let fixed = skip_name(payload, name).ok_or(Malformed)?;
        let (rdata, end) = if section == Section::Question {
            payload.get(fixed..fixed + 4).ok_or(Malformed)?;
            (fixed + 4, fixed + 4)
        } else {
            let head = payload.get(fixed..fixed + 10).ok_or(Malformed)?;
            let rdata = fixed + 10;
            let end = rdata + usize::from(u16::from_be_bytes([head[8], head[9]]));
            if end > payload.len() {
                return Err(Malformed);
            }
            (rdata, end)
        };
        self.at = end;
        Ok(Entry {
            section,
            name,
            fixed,
            rtype: u16::from_be_bytes([payload[fixed], payload[fixed + 1]]),
            rdata,
            end,
        })
    }
}

impl Iterator for Entries<'_> {
    type Item = Result<Entry, Malformed>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let Some(slot) = self.remaining.iter_mut().find(|(_, left)| *left > 0) else {
            self.done = true;
            return None;
        };
        slot.1 -= 1;
        let section = slot.0;
        let step = self.step(section);
        self.done = step.is_err();
        Some(step)
    }
}

/// No new offset for this original one: `placed` holds only offsets a pointer can name, and a
/// pointer is 14 bits.
const UNPLACED: u16 = u16::MAX;
const MAX_POINTER_TARGET: usize = 0x3fff;

/// Rewrites a response the allow-list trims, with the refused records removed, into buffers it
/// keeps between messages.
///
/// Names are re-encoded label by label while `placed` maps each original label offset to where it
/// landed, so a pointer to a label already written becomes a pointer to its new offset, and one to
/// a label that was dropped (or not yet written) is spelled out from the original.
pub(crate) struct Trimmer {
    allowed: ServiceList,
    out: Vec<u8>,
    placed: Vec<u16>,
}

impl Trimmer {
    pub(crate) fn new(allowed: ServiceList) -> Self {
        Self {
            allowed,
            out: Vec::new(),
            placed: Vec::new(),
        }
    }

    /// The trimmed message, or `None` when [`scope`] does not call for a trim.
    pub(crate) fn trim(&mut self, payload: &[u8]) -> Option<&[u8]> {
        if scope(payload, &self.allowed) != Scope::Trim {
            return None;
        }
        if self.rewrite(payload).is_err() {
            // Not expected: `scope` walked every name the rewrite does, within the same budget.
            // `None` would relay the untrimmed message verbatim, so fail closed instead.
            self.empty_like(payload);
        }
        Some(&self.out)
    }

    /// `payload`'s header with no entries: what a trim that cannot complete relays.
    fn empty_like(&mut self, payload: &[u8]) {
        self.out.clear();
        self.out.extend_from_slice(
            payload
                .get(..DNS_HEADER_LEN)
                .unwrap_or(&[0; DNS_HEADER_LEN]),
        );
        self.out[QDCOUNT_AT..DNS_HEADER_LEN].fill(0);
    }

    /// Bounds-checked throughout, so input `scope` never vetted is an error, never a panic.
    fn rewrite(&mut self, payload: &[u8]) -> Result<(), Malformed> {
        let budget = Budget::for_message(payload);
        self.out.clear();
        self.out
            .extend_from_slice(payload.get(..DNS_HEADER_LEN).ok_or(Malformed)?);
        self.placed.clear();
        self.placed.resize(payload.len(), UNPLACED);
        let mut counts = [0u16; 4];
        for entry in Entries::new(payload) {
            let entry = entry?;
            let keep = entry.section == Section::Question
                || entry
                    .service(payload, &budget)?
                    .is_none_or(|service| allows(&self.allowed, service));
            if !keep {
                continue;
            }
            self.write_entry(payload, entry, &budget)?;
            counts[entry.section as usize] += 1;
        }
        for (count, at) in counts
            .into_iter()
            .zip([QDCOUNT_AT, ANCOUNT_AT, NSCOUNT_AT, ARCOUNT_AT])
        {
            self.out[at..at + 2].copy_from_slice(&count.to_be_bytes());
        }
        Ok(())
    }

    fn write_entry(
        &mut self,
        payload: &[u8],
        entry: Entry,
        budget: &Budget,
    ) -> Result<(), Malformed> {
        let span = |from: usize, to: usize| payload.get(from..to).ok_or(Malformed);
        self.write_name(payload, entry.name, budget)?;
        if entry.section == Section::Question {
            self.out.extend_from_slice(span(entry.fixed, entry.end)?);
            return Ok(());
        }
        // TYPE, CLASS and TTL; RDLENGTH is patched once the rdata is written.
        self.out
            .extend_from_slice(span(entry.fixed, entry.fixed + 8)?);
        let length_at = self.out.len();
        self.out.extend_from_slice(&[0, 0]);
        match rdata_names(entry.rtype).filter(|_| entry.rdata < entry.end) {
            Some((offset, count)) => {
                let mut at = entry.rdata + offset;
                self.out.extend_from_slice(span(entry.rdata, at)?);
                for _ in 0..count {
                    self.write_name(payload, at, budget)?;
                    at = skip_name(payload, at).ok_or(Malformed)?;
                }
                self.out.extend_from_slice(span(at, entry.end)?);
            }
            None => self.out.extend_from_slice(span(entry.rdata, entry.end)?),
        }
        let length = u16::try_from(self.out.len() - length_at - 2).map_err(|_| Malformed)?;
        self.out[length_at..length_at + 2].copy_from_slice(&length.to_be_bytes());
        Ok(())
    }

    fn write_name(
        &mut self,
        payload: &[u8],
        mut at: usize,
        budget: &Budget,
    ) -> Result<(), Malformed> {
        let mut hops = 0;
        loop {
            budget.spend()?;
            let placed = self.placed.get(at).copied().unwrap_or(UNPLACED);
            if placed != UNPLACED {
                self.out.extend_from_slice(&(0xc000 | placed).to_be_bytes());
                return Ok(());
            }
            let len = *payload.get(at).ok_or(Malformed)?;
            match len {
                0 => {
                    self.out.push(0);
                    return Ok(());
                }
                1..=0x3f => {
                    let label = payload
                        .get(at..at + 1 + usize::from(len))
                        .ok_or(Malformed)?;
                    if let Ok(here) = u16::try_from(self.out.len())
                        && usize::from(here) <= MAX_POINTER_TARGET
                    {
                        self.placed[at] = here;
                    }
                    self.out.extend_from_slice(label);
                    at += label.len();
                }
                0xc0..=0xff => {
                    let low = *payload.get(at + 1).ok_or(Malformed)?;
                    hops += 1;
                    if hops > MAX_POINTER_HOPS {
                        return Err(Malformed);
                    }
                    at = usize::from(len & 0x3f) << 8 | usize::from(low);
                }
                _ => return Err(Malformed),
            }
        }
    }
}

/// Where `allowed` puts `payload`, a query or a response per its QR bit.
///
/// A query is refused only when every question names a refused service: a mixed one goes out
/// whole, and its answer is trimmed on the way back. A response is refused when it names services
/// and none is allowed, its address records included: they ride with the refused services. A
/// response naming no service at all (a hostname answer) passes.
pub(crate) fn scope(payload: &[u8], allowed: &[ServiceType]) -> Scope {
    assess(payload, allowed).unwrap_or(Scope::Malformed)
}

fn assess(payload: &[u8], allowed: &[ServiceType]) -> Result<Scope, Malformed> {
    let kind = classify(payload).ok_or(Malformed)?;
    let budget = Budget::for_message(payload);
    let (mut granted, mut refused, mut unscoped) = (false, false, false);
    for entry in Entries::new(payload) {
        let entry = entry?;
        entry.check_names(payload, &budget)?;
        let asked = match kind {
            MdnsKind::Query => entry.section == Section::Question,
            MdnsKind::Response => entry.section != Section::Question,
        };
        if !asked {
            continue;
        }
        match entry.service(payload, &budget)? {
            None => unscoped = true,
            Some(service) if allows(allowed, service) => granted = true,
            Some(_) => refused = true,
        }
    }
    // What survives the refusal: for a query, any question worth asking; for a response, an
    // allowed service (its unscoped records ride along).
    let survives = match kind {
        MdnsKind::Query => granted || unscoped,
        MdnsKind::Response => granted,
    };
    Ok(match (refused, survives, kind) {
        (false, _, _) | (true, true, MdnsKind::Query) => Scope::Pass,
        (true, true, MdnsKind::Response) => Scope::Trim,
        (true, false, _) => Scope::Refuse,
    })
}

/// The service type a name falls under: its `_<service>._tcp` / `_<service>._udp` pair nearest the
/// domain, as the service label (underscore stripped) and transport. The DNS-SD meta-names
/// (`_services._dns-sd._udp`, the browse-domain `b._dns-sd._udp`) are infrastructure, not a
/// service, so their pair does not count.
fn service_of<'a>(
    payload: &'a [u8],
    at: usize,
    budget: &Budget,
) -> Result<Option<(&'a [u8], Proto)>, Malformed> {
    let mut previous: Option<&[u8]> = None;
    let mut found = None;
    for label in Labels::new(payload, at, budget) {
        let label = label?;
        if let (Some(service), Some(proto)) = (previous, Proto::from_label(label))
            && let Some(service) = service.strip_prefix(b"_")
            && !service.eq_ignore_ascii_case(b"dns-sd")
        {
            found = Some((service, proto));
        }
        previous = Some(label);
    }
    Ok(found)
}

fn allows(allowed: &[ServiceType], (service, proto): (&[u8], Proto)) -> bool {
    allowed
        .iter()
        .any(|a| a.proto == proto && a.service().eq_ignore_ascii_case(service))
}

/// Where names sit in the rdata of the types that may compress them: the fixed octets before the
/// first name, and how many names follow back to back. RFC 6762 §18.14 lists them for mDNS (NS,
/// CNAME, PTR, DNAME, SOA, MX, AFSDB, RT, KX, RP, PX, SRV, NSEC); RFC 3597 §4 adds the obsolete
/// RFC 1035 types. Any other rdata holds no compressed name, so it is opaque octets.
fn rdata_names(rtype: u16) -> Option<(usize, usize)> {
    match rtype {
        TYPE_NS | TYPE_MD | TYPE_MF | TYPE_CNAME | TYPE_MB | TYPE_MG | TYPE_MR | TYPE_PTR
        | TYPE_NSEC | TYPE_DNAME => Some((0, 1)),
        TYPE_SOA | TYPE_MINFO | TYPE_RP => Some((0, 2)),
        TYPE_MX | TYPE_AFSDB | TYPE_RT | TYPE_KX => Some((2, 1)),
        TYPE_PX => Some((2, 2)),
        TYPE_SRV => Some((6, 1)),
        _ => None,
    }
}

fn check_name(payload: &[u8], at: usize, budget: &Budget) -> Result<(), Malformed> {
    Labels::new(payload, at, budget).try_for_each(|label| label.map(|_| ()))
}

#[cfg(test)]
mod tests {
    use super::super::tests::{MDNS_RESPONSE_BONJOUR, MDNS_RESPONSE_RAOP};
    use super::*;
    use crate::unique_list::ListError;

    const TYPE_A: u16 = 1;
    const TYPE_TXT: u16 = 16;

    /// `text` in wire form, uncompressed.
    fn name(text: &str) -> Vec<u8> {
        let mut wire = Vec::new();
        for label in text.split('.').filter(|label| !label.is_empty()) {
            wire.push(u8::try_from(label.len()).unwrap());
            wire.extend_from_slice(label.as_bytes());
        }
        wire.push(0);
        wire
    }

    fn header(qr: bool, qd: usize, an: usize) -> Vec<u8> {
        let mut m = vec![0u8; 12];
        m[2] = if qr { 0x84 } else { 0 };
        m[4..6].copy_from_slice(&u16::try_from(qd).unwrap().to_be_bytes());
        m[6..8].copy_from_slice(&u16::try_from(an).unwrap().to_be_bytes());
        m
    }

    /// A query asking a PTR question for each of `names`.
    fn query(names: &[&str]) -> Vec<u8> {
        let mut m = header(false, names.len(), 0);
        for n in names {
            m.extend(name(n));
            m.extend_from_slice(&TYPE_PTR.to_be_bytes());
            m.extend_from_slice(&[0x00, 0x01]);
        }
        m
    }

    /// A response whose answer section holds `records`: `(owner, type, rdata)`, IN, TTL 120.
    fn response(records: &[(&str, u16, Vec<u8>)]) -> Vec<u8> {
        let mut m = header(true, 0, records.len());
        for (owner, rtype, rdata) in records {
            m.extend(name(owner));
            m.extend_from_slice(&rtype.to_be_bytes());
            m.extend_from_slice(&[0x80, 0x01, 0, 0, 0, 120]);
            m.extend_from_slice(&u16::try_from(rdata.len()).unwrap().to_be_bytes());
            m.extend_from_slice(rdata);
        }
        m
    }

    fn srv(target: &str) -> Vec<u8> {
        let mut rdata = vec![0, 0, 0, 0, 0x02, 0x77];
        rdata.extend(name(target));
        rdata
    }

    fn allow(list: &str) -> ServiceList {
        list.parse().unwrap()
    }

    #[test]
    fn a_service_type_parses_case_insensitively_and_displays_lowercased() {
        for (text, shown) in [
            ("_ipp._tcp", "_ipp._tcp"),
            ("_IPP._TCP", "_ipp._tcp"),
            ("_companion-link._tcp", "_companion-link._tcp"),
            ("_hap._udp", "_hap._udp"),
            ("_androidtvremote2._tcp", "_androidtvremote2._tcp"),
            // mDNS lives under `local`, so the domain and a trailing root dot are accepted and
            // dropped: they are how Avahi users write the type.
            ("_ipp._tcp.local", "_ipp._tcp"),
            ("_ipp._tcp.local.", "_ipp._tcp"),
            ("_ipp._tcp.", "_ipp._tcp"),
            ("_ipp._tcp.LOCAL", "_ipp._tcp"),
        ] {
            let service: ServiceType = text.parse().unwrap();
            assert_eq!(service.to_string(), shown);
        }
        assert_eq!(
            "_Hap._Udp".parse::<ServiceType>(),
            "_hap._udp".parse::<ServiceType>()
        );
    }

    #[test]
    fn a_service_type_must_be_an_underscored_label_and_a_transport() {
        for bad in [
            "",
            "ipp._tcp",          // no underscore on the service
            "_ipp.tcp",          // no underscore on the transport
            "_ipp._sctp",        // not a DNS-SD transport label
            "_ipp",              // no transport
            "_._tcp",            // empty service
            "_ipp._tcp.example", // mDNS names live under `local` only
            "_ipp._tcp..",
            "_ipp._tcp.local..",
            " _ipp._tcp",
            "_ip p._tcp",
            "_ipp.x._tcp",
        ] {
            assert_eq!(
                bad.parse::<ServiceType>(),
                Err(ParseServiceTypeError),
                "{bad:?}"
            );
        }
        // A DNS label is at most 63 octets, underscore included.
        let longest = format!("_{}._tcp", "a".repeat(MAX_SERVICE_LEN));
        assert!(longest.parse::<ServiceType>().is_ok());
        let too_long = format!("_{}._tcp", "a".repeat(MAX_SERVICE_LEN + 1));
        assert_eq!(too_long.parse::<ServiceType>(), Err(ParseServiceTypeError));
    }

    #[test]
    fn a_service_list_refuses_a_case_variant_duplicate() {
        let list: ServiceList = "_ipp._tcp, _airplay._tcp".parse().unwrap();
        assert_eq!(list.len(), 2);
        assert!(matches!(
            "_ipp._tcp,_IPP._tcp".parse::<ServiceList>(),
            Err(ListError::Duplicate { .. })
        ));
        assert!(matches!(
            "_ipp._tcp,ipp".parse::<ServiceList>(),
            Err(ListError::Invalid { .. })
        ));
    }

    #[test]
    fn a_query_is_refused_only_when_every_question_is_a_refused_service() {
        let allowed = allow("_ipp._tcp");
        assert_eq!(
            scope(&query(&["_airplay._tcp.local"]), &allowed),
            Scope::Refuse
        );
        assert_eq!(
            scope(
                &query(&["_airplay._tcp.local", "_raop._tcp.local"]),
                &allowed
            ),
            Scope::Refuse
        );
        assert_eq!(scope(&query(&["_ipp._tcp.local"]), &allowed), Scope::Pass);
        // A mixed query goes out whole; its answer is trimmed on the way back.
        assert_eq!(
            scope(
                &query(&["_airplay._tcp.local", "_ipp._tcp.local"]),
                &allowed
            ),
            Scope::Pass
        );
        // Not service-scoped: a hostname, a reverse lookup, the DNS-SD enumeration.
        for unscoped in [
            "printer.local",
            "9.1.168.192.in-addr.arpa",
            "_services._dns-sd._udp.local",
        ] {
            assert_eq!(
                scope(&query(&[unscoped]), &allowed),
                Scope::Pass,
                "{unscoped}"
            );
        }
        assert_eq!(scope(&query(&[]), &allowed), Scope::Pass);
    }

    #[test]
    fn a_response_passes_when_nothing_in_it_is_refused() {
        let allowed = allow("_ipp._tcp, _airplay._tcp");
        // Address records alone are not service-scoped: hostname resolution keeps working.
        let host = response(&[("printer.local", TYPE_A, vec![192, 0, 2, 9])]);
        assert_eq!(scope(&host, &allowed), Scope::Pass);
        let ipp = response(&[
            ("_ipp._tcp.local", TYPE_PTR, name("Laser._ipp._tcp.local")),
            ("Laser._ipp._tcp.local", TYPE_SRV, srv("printer.local")),
            ("Laser._ipp._tcp.local", TYPE_TXT, b"\x06txtvers=1".to_vec()),
            ("printer.local", TYPE_A, vec![192, 0, 2, 9]),
        ]);
        assert_eq!(scope(&ipp, &allowed), Scope::Pass);
        // DNS names compare case-insensitively.
        let shouted = response(&[(
            "_AirPlay._TCP.local",
            TYPE_PTR,
            name("TV._AirPlay._TCP.local"),
        )]);
        assert_eq!(scope(&shouted, &allowed), Scope::Pass);
    }

    #[test]
    fn a_response_is_refused_when_no_service_in_it_is_allowed() {
        let allowed = allow("_ipp._tcp");
        // The address record rides with the refused service: it does not keep the message alive.
        let airplay = response(&[
            (
                "_airplay._tcp.local",
                TYPE_PTR,
                name("TV._airplay._tcp.local"),
            ),
            ("TV._airplay._tcp.local", TYPE_SRV, srv("tv.local")),
            ("tv.local", TYPE_A, vec![192, 0, 2, 10]),
        ]);
        assert_eq!(scope(&airplay, &allowed), Scope::Refuse);
        // The enumeration is scoped by the type it names.
        let listing = response(&[(
            "_services._dns-sd._udp.local",
            TYPE_PTR,
            name("_hap._tcp.local"),
        )]);
        assert_eq!(scope(&listing, &allowed), Scope::Refuse);
    }

    #[test]
    fn a_response_mixing_allowed_and_refused_services_is_trimmed() {
        let allowed = allow("_ipp._tcp");
        let mixed = response(&[
            ("_ipp._tcp.local", TYPE_PTR, name("Laser._ipp._tcp.local")),
            (
                "_airplay._tcp.local",
                TYPE_PTR,
                name("TV._airplay._tcp.local"),
            ),
        ]);
        assert_eq!(scope(&mixed, &allowed), Scope::Trim);
        let listing = response(&[
            (
                "_services._dns-sd._udp.local",
                TYPE_PTR,
                name("_ipp._tcp.local"),
            ),
            (
                "_services._dns-sd._udp.local",
                TYPE_PTR,
                name("_hap._tcp.local"),
            ),
        ]);
        assert_eq!(scope(&listing, &allowed), Scope::Trim);
    }

    #[test]
    fn the_service_is_the_pair_nearest_the_domain() {
        // A subtype browse (RFC 6763 §7.1) is scoped by its parent type.
        let subtype = response(&[(
            "_I0123456789ABCDEF._sub._matter._tcp.local",
            TYPE_PTR,
            name("0123456789ABCDEF-00000000000000A1._matter._tcp.local"),
        )]);
        assert_eq!(scope(&subtype, &allow("_matter._tcp")), Scope::Pass);
        assert_eq!(scope(&subtype, &allow("_hap._tcp")), Scope::Refuse);
        // An instance label that looks like a service type does not make it one.
        let decoy = response(&[("_ipp._http._tcp.local", TYPE_SRV, srv("box.local"))]);
        assert_eq!(scope(&decoy, &allow("_ipp._tcp")), Scope::Refuse);
        assert_eq!(scope(&decoy, &allow("_http._tcp")), Scope::Pass);
    }

    #[test]
    fn real_bundled_responses_are_scoped() {
        // One Bonjour response bundles `_smb._tcp` and `_afpovertcp._tcp` with the host's
        // addresses and NSECs.
        assert_eq!(
            scope(&MDNS_RESPONSE_BONJOUR, &allow("_smb._tcp")),
            Scope::Trim
        );
        assert_eq!(
            scope(
                &MDNS_RESPONSE_BONJOUR,
                &allow("_smb._tcp, _afpovertcp._tcp")
            ),
            Scope::Pass
        );
        assert_eq!(
            scope(&MDNS_RESPONSE_BONJOUR, &allow("_ipp._tcp")),
            Scope::Refuse
        );
        assert_eq!(
            scope(&MDNS_RESPONSE_RAOP, &allow("_raop._tcp")),
            Scope::Pass
        );
        assert_eq!(
            scope(&MDNS_RESPONSE_RAOP, &allow("_airplay._tcp")),
            Scope::Refuse
        );
    }

    #[test]
    fn a_malformed_message_is_its_own_scope() {
        let allowed = allow("_ipp._tcp");
        let mut truncated = response(&[("_ipp._tcp.local", TYPE_PTR, name("L._ipp._tcp.local"))]);
        truncated.truncate(truncated.len() - 3);
        assert_eq!(scope(&truncated, &allowed), Scope::Malformed);
        // A compression pointer to itself.
        let mut looped = header(true, 0, 1);
        looped.extend_from_slice(&[0xc0, 12]);
        looped.extend_from_slice(&[0, 12, 0, 1, 0, 0, 0, 120, 0, 0]);
        assert_eq!(scope(&looped, &allowed), Scope::Malformed);
        assert_eq!(scope(b"", &allowed), Scope::Malformed);
    }

    /// A response whose every record names one long chain of compression pointers: legal hop by
    /// hop, but walking it for each record costs far more than the message is long.
    fn pointer_chain_response(hops: usize, records: usize) -> Vec<u8> {
        let mut m = header(true, 0, 0);
        // `_ipp._tcp.local`, then `hops` one-label names, each pointing at the one before.
        let base = m.len();
        m.extend(name("_ipp._tcp.local"));
        let mut tail = base;
        for _ in 0..hops {
            let here = m.len();
            m.extend_from_slice(&[
                1,
                b'x',
                0xc0 | u8::try_from(tail >> 8).unwrap(),
                u8::try_from(tail & 0xff).unwrap(),
            ]);
            tail = here;
        }
        // The chain is not itself a record: move it inside the first record's rdata so the
        // message stays well formed, then point every record's owner at its far end.
        let chain = m.split_off(base);
        let mut out = header(true, 0, records);
        let offset = out.len() + 12;
        let shift = |p: usize| p - base + offset;
        let mut rdata = chain.clone();
        let mut at = 0;
        while at < rdata.len() {
            let n = rdata[at];
            if n & 0xc0 == 0xc0 {
                let target = shift((usize::from(n & 0x3f) << 8) | usize::from(rdata[at + 1]));
                rdata[at] = 0xc0 | u8::try_from(target >> 8).unwrap();
                rdata[at + 1] = u8::try_from(target & 0xff).unwrap();
                at += 2;
            } else if n == 0 {
                at += 1;
            } else {
                at += 1 + usize::from(n);
            }
        }
        let far_end = shift(tail);
        for i in 0..records {
            out.extend_from_slice(&[
                0xc0 | u8::try_from(far_end >> 8).unwrap(),
                u8::try_from(far_end & 0xff).unwrap(),
            ]);
            out.extend_from_slice(&[0, 16, 0, 1, 0, 0, 0, 120]);
            let rd: &[u8] = if i == 0 { &rdata } else { &[] };
            out.extend_from_slice(&u16::try_from(rd.len()).unwrap().to_be_bytes());
            out.extend_from_slice(rd);
        }
        out
    }

    #[test]
    fn the_work_per_message_is_bounded() {
        let allowed = allow("_ipp._tcp");
        // A handful of records over a short chain is ordinary and still scoped.
        assert_eq!(scope(&pointer_chain_response(3, 4), &allowed), Scope::Pass);
        // Hundreds of records over a 120-hop chain would walk ~40 steps per byte: refused as
        // malformed long before, whatever the allow-list says.
        let heavy = pointer_chain_response(120, 300);
        assert_eq!(scope(&heavy, &allowed), Scope::Malformed);
        assert_eq!(Trimmer::new(allowed).trim(&heavy), None);
    }

    #[test]
    fn a_dname_target_pointing_into_a_dropped_record_is_spelled_out() {
        // Record 1 (refused) owns `local`; record 2 (allowed) keeps the message a trim; record 3 is
        // a DNAME whose target is a pointer to record 1's `local`.
        let mut m = header(true, 0, 3);
        let first = m.len();
        m.extend(name("_hap._tcp.local"));
        m.extend_from_slice(&[0, 12, 0x80, 1, 0, 0, 0, 120]);
        let target = name("L._hap._tcp.local");
        m.extend_from_slice(&u16::try_from(target.len()).unwrap().to_be_bytes());
        m.extend(target);
        m.extend(name("_ipp._tcp.local"));
        m.extend_from_slice(&[0, 12, 0x80, 1, 0, 0, 0, 120]);
        let target = name("L._ipp._tcp.local");
        m.extend_from_slice(&u16::try_from(target.len()).unwrap().to_be_bytes());
        m.extend(target);
        let local = u8::try_from(first + 1 + 4 + 1 + 4).unwrap(); // past `_hap` and `_tcp`
        m.extend(name("alias.example"));
        m.extend_from_slice(&[0, 39, 0x80, 1, 0, 0, 0, 120, 0, 2, 0xc0, local]);
        let trimmed = Trimmer::new(allow("_ipp._tcp")).trim(&m).unwrap().to_vec();
        let dname = decode(&trimmed).into_iter().find(|r| r.2 == 39).unwrap();
        assert_eq!(dname.3, "|local|");
    }

    #[test]
    fn a_trim_that_cannot_complete_relays_nothing() {
        // Never the untrimmed message: the header survives, every count is zero.
        let mut filter = Trimmer::new(allow("_ipp._tcp"));
        filter.empty_like(&MDNS_RESPONSE_BONJOUR);
        assert_eq!(
            filter.out[..QDCOUNT_AT],
            MDNS_RESPONSE_BONJOUR[..QDCOUNT_AT]
        );
        assert_eq!(filter.out.len(), DNS_HEADER_LEN);
        assert!(filter.out[QDCOUNT_AT..].iter().all(|&b| b == 0));
    }

    #[test]
    fn the_rewrite_errs_rather_than_panics_on_unvetted_input() {
        let mut filter = Trimmer::new(allow("_ipp._tcp"));
        // An SRV whose RDLENGTH is shorter than its fixed fields.
        let mut m = response(&[("_ipp._tcp.local", TYPE_SRV, vec![0, 0])]);
        assert!(filter.rewrite(&m).is_err());
        m.truncate(5);
        assert!(filter.rewrite(&m).is_err());
    }

    /// Each record as `(section, owner, type, rdata)`, the rdata's names spelled out so a
    /// recompressed message compares equal to its original.
    fn decode(payload: &[u8]) -> Vec<(Section, String, u16, String)> {
        let budget = Budget(Cell::new(usize::MAX));
        let text = |at: usize| {
            Labels::new(payload, at, &budget)
                .map(|label| String::from_utf8_lossy(label.unwrap()).into_owned())
                .collect::<Vec<_>>()
                .join(".")
        };
        let hex = |bytes: &[u8]| {
            bytes.iter().fold(String::new(), |mut out, b| {
                write!(out, "{b:02x}").unwrap();
                out
            })
        };
        Entries::new(payload)
            .map(|entry| {
                let e = entry.unwrap();
                let rdata = match rdata_names(e.rtype).filter(|_| e.rdata < e.end) {
                    Some((offset, count)) => {
                        let mut parts = vec![hex(&payload[e.rdata..e.rdata + offset])];
                        let mut at = e.rdata + offset;
                        for _ in 0..count {
                            parts.push(text(at));
                            at = skip_name(payload, at).unwrap();
                        }
                        parts.push(hex(&payload[at..e.end]));
                        parts.join("|")
                    }
                    None => hex(&payload[e.rdata..e.end]),
                };
                (e.section, text(e.name), e.rtype, rdata)
            })
            .collect()
    }

    #[test]
    fn a_mixed_response_is_trimmed_to_its_allowed_and_unscoped_records() {
        let original = response(&[
            ("_ipp._tcp.local", TYPE_PTR, name("Laser._ipp._tcp.local")),
            (
                "_airplay._tcp.local",
                TYPE_PTR,
                name("TV._airplay._tcp.local"),
            ),
            ("Laser._ipp._tcp.local", TYPE_SRV, srv("printer.local")),
            ("TV._airplay._tcp.local", TYPE_SRV, srv("tv.local")),
            ("printer.local", TYPE_A, vec![192, 0, 2, 9]),
        ]);
        let mut filter = Trimmer::new(allow("_ipp._tcp"));
        let trimmed = filter
            .trim(&original)
            .expect("a mixed response is trimmed")
            .to_vec();
        let kept: Vec<_> = decode(&original)
            .into_iter()
            .filter(|(_, owner, _, rdata)| !owner.contains("airplay") && !rdata.contains("airplay"))
            .collect();
        assert_eq!(decode(&trimmed), kept);
        assert_eq!(kept.len(), 3);
        // The ID and flags carry over.
        assert_eq!(trimmed[..4], original[..4]);
    }

    #[test]
    fn a_real_bundled_response_keeps_every_record_but_the_refused_services() {
        let mut filter = Trimmer::new(allow("_smb._tcp"));
        let trimmed = filter.trim(&MDNS_RESPONSE_BONJOUR).unwrap().to_vec();
        let original = decode(&MDNS_RESPONSE_BONJOUR);
        let kept: Vec<_> = original
            .iter()
            .filter(|(_, owner, _, _)| !owner.contains("_afpovertcp"))
            .cloned()
            .collect();
        // The `_afpovertcp` SRV in the answers and its NSEC in the additionals.
        assert_eq!(original.len() - kept.len(), 2);
        assert_eq!(decode(&trimmed), kept);
        // Recompressed, not spelled out: dropping records never grows this message.
        assert!(trimmed.len() < MDNS_RESPONSE_BONJOUR.len());
    }

    #[test]
    fn a_kept_name_pointing_into_a_dropped_record_is_spelled_out() {
        // The second record's owner is `_ipp` plus a pointer to `_tcp.local` inside the first
        // record's owner, which the trim drops.
        let mut m = header(true, 0, 2);
        m.extend(name("_airplay._tcp.local"));
        m.extend_from_slice(&[0, 12, 0x80, 1, 0, 0, 0, 120]);
        let target = name("TV._airplay._tcp.local");
        m.extend_from_slice(&u16::try_from(target.len()).unwrap().to_be_bytes());
        m.extend(target);
        m.extend_from_slice(&[4, b'_', b'i', b'p', b'p', 0xc0, 12 + 9]);
        m.extend_from_slice(&[0, 12, 0x80, 1, 0, 0, 0, 120]);
        let target = name("L._ipp._tcp.local");
        m.extend_from_slice(&u16::try_from(target.len()).unwrap().to_be_bytes());
        m.extend(target);
        assert_eq!(decode(&m)[1].1, "_ipp._tcp.local");

        let mut filter = Trimmer::new(allow("_ipp._tcp"));
        let trimmed = filter.trim(&m).unwrap().to_vec();
        assert_eq!(
            decode(&trimmed),
            [(
                Section::Answer,
                "_ipp._tcp.local".to_owned(),
                TYPE_PTR,
                "|L._ipp._tcp.local|".to_owned()
            )]
        );
    }

    #[test]
    fn only_a_mixed_response_is_rewritten() {
        let mut filter = Trimmer::new(allow("_smb._tcp, _afpovertcp._tcp"));
        assert!(
            filter.trim(&MDNS_RESPONSE_BONJOUR).is_none(),
            "nothing refused"
        );
        let mut filter = Trimmer::new(allow("_ipp._tcp"));
        assert!(
            filter.trim(&MDNS_RESPONSE_BONJOUR).is_none(),
            "nothing allowed"
        );
        assert!(
            filter
                .trim(&query(&["_ipp._tcp.local", "_hap._tcp.local"]))
                .is_none(),
            "a query is never rewritten"
        );
    }
}
