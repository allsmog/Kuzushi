use anyhow::{Context, Result};
use globset::Glob;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// Operator-controlled bug-bounty scope file loaded from
/// `<workspace>/.kuzushi/scope.toml`. Contains an in-scope allow list
/// and an out-of-scope deny list. Recon, Burp/HAR import, and any tool
/// that takes a host or URL argument runs every target through
/// [`ProgramScope::verdict`] before dispatch. Out-of-scope assets are
/// refused with an actionable message; when an in-scope allow list is present,
/// unmatched assets are also refused.
///
/// File schema:
/// ```toml
/// [in_scope]
/// hosts = ["*.example.com", "api.test"]
/// cidrs = ["10.0.0.0/8"]
///
/// [out_of_scope]
/// hosts = ["admin.example.com"]
/// cidrs = ["10.99.0.0/16"]
/// ```
#[derive(Debug, Default, Clone)]
pub struct ProgramScope {
    in_scope: Vec<HostPattern>,
    out_of_scope: Vec<HostPattern>,
}

/// One entry in a scope allow/deny list. Either a host glob
/// (e.g. `*.example.com`) compiled via `globset`, or a CIDR range
/// parsed via `ipnet`.
#[derive(Debug, Clone)]
pub enum HostPattern {
    HostGlob(Glob),
    Cidr(IpNet),
}

/// How the tool that received a target will read it, which decides whether the
/// string can name more than one address.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum TargetSyntax {
    /// A host, IP literal, or URL — what curl, the HTTP clients, and the
    /// importers read. `10.0.0.1-2` is a domain name to every one of them, so
    /// it names whatever DNS resolves it to, not the two addresses it reads
    /// like, and judging it as a block would admit an asset no rule covers.
    #[default]
    Host,
    /// An nmap target specification, which also names a CIDR block or an octet
    /// range or list. Only a tool that hands its target to nmap may use this.
    AddressBlock,
}

/// Outcome of validating a candidate target against the active scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeVerdict {
    /// Target matches an in-scope pattern and no out-of-scope pattern.
    InScope,
    /// Target matches an out-of-scope pattern — dispatch must refuse.
    OutOfScope,
    /// Target matches neither list and there is no allow list. Callers may warn.
    Unknown,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProgramScopeFile {
    #[serde(default)]
    pub in_scope: ProgramScopeList,
    #[serde(default)]
    pub out_of_scope: ProgramScopeList,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProgramScopeList {
    #[serde(default)]
    pub hosts: Vec<String>,
    #[serde(default)]
    pub cidrs: Vec<String>,
}

impl ProgramScope {
    pub fn from_file(parsed: &ProgramScopeFile) -> Result<Self> {
        Ok(Self {
            in_scope: compile_patterns(&parsed.in_scope)?,
            out_of_scope: compile_patterns(&parsed.out_of_scope)?,
        })
    }

    pub fn parse(toml_text: &str) -> Result<Self> {
        let parsed: ProgramScopeFile =
            toml::from_str(toml_text).context("Could not parse scope.toml")?;
        Self::from_file(&parsed)
    }

    pub fn is_empty(&self) -> bool {
        self.in_scope.is_empty() && self.out_of_scope.is_empty()
    }

    /// `false` when the host is explicitly out-of-scope, or when an allow list
    /// exists and the host does not match it. Used by per-entry import gates
    /// (M2 §2.2 / §2.3) so each amass/httpx/nuclei/nmap-xml/HAR/Burp
    /// entry is checked individually — `recon:import` does not carry
    /// a top-level target field, so the dispatch-level scope guard is
    /// not sufficient.
    pub fn host_allowed(&self, target: &str) -> bool {
        self.verdict(target) != ScopeVerdict::OutOfScope
    }

    /// Validate a candidate target — host, IP, or URL — against the active
    /// scope. Out-of-scope wins over in-scope so deny rules dominate. Returns
    /// [`ScopeVerdict::Unknown`] only when no allow list exists and the target
    /// matches nothing.
    ///
    /// A target that two real URL parsers read as two different hosts is
    /// judged as every host it could name: one deny match denies it, and an
    /// allow list has to cover all of them. See [`candidate_hosts`].
    ///
    /// Reads the target as a host. A caller whose tool reads its target as an
    /// nmap target specification calls [`ProgramScope::verdict_for`] instead.
    pub fn verdict(&self, target: &str) -> ScopeVerdict {
        self.verdict_for(target, TargetSyntax::Host)
    }

    /// As [`ProgramScope::verdict`], for a caller that knows how its tool reads
    /// the target. Under [`TargetSyntax::AddressBlock`] a target that names a
    /// block of addresses rather than one host is judged as the whole block.
    /// See [`candidate_range`].
    pub fn verdict_for(&self, target: &str, syntax: TargetSyntax) -> ScopeVerdict {
        let hosts = candidate_hosts(target);
        let range = candidate_range(target, syntax);
        if self.denies(&hosts, range) {
            return ScopeVerdict::OutOfScope;
        }
        if self.admits(&hosts, range) {
            return ScopeVerdict::InScope;
        }
        unmatched_scope_verdict(!self.in_scope.is_empty())
    }

    /// `true` when one deny rule names any host this target reaches: a rule
    /// matching one of the target's readings, or a rule reaching into the range
    /// it spans.
    fn denies(&self, hosts: &[String], range: Option<AddressRange>) -> bool {
        hosts.iter().any(|host| matches_any(&self.out_of_scope, host))
            || range.is_some_and(|range| reaches_range(&self.out_of_scope, range))
    }

    /// `true` when the allow list covers every host this target reaches.
    fn admits(&self, hosts: &[String], range: Option<AddressRange>) -> bool {
        match range {
            Some(range) => covers_range(&self.in_scope, range),
            None => hosts.iter().all(|host| matches_any(&self.in_scope, host)),
        }
    }
}

fn unmatched_scope_verdict(has_allow_list: bool) -> ScopeVerdict {
    if has_allow_list {
        ScopeVerdict::OutOfScope
    } else {
        ScopeVerdict::Unknown
    }
}

fn compile_patterns(list: &ProgramScopeList) -> Result<Vec<HostPattern>> {
    let mut compiled = Vec::with_capacity(list.hosts.len() + list.cidrs.len());
    for raw in &list.hosts {
        push_host_patterns(&mut compiled, raw)?;
    }
    for raw in &list.cidrs {
        let cidr =
            IpNet::from_str(raw).with_context(|| format!("invalid cidr in scope.toml: {raw}"))?;
        compiled.push(HostPattern::Cidr(cidr));
    }
    Ok(compiled)
}

/// Compile one host rule in every spelling the candidate it names can arrive
/// in. Both sides of the comparison are normalized, so a glob written with
/// uppercase letters or a root dot still denies the asset it names. Character
/// classes are normalized too: `[A-Z]` becomes `[a-z]`, which matches the same
/// hosts once the candidate is lowercased.
fn push_host_patterns(compiled: &mut Vec<HostPattern>, raw: &str) -> Result<()> {
    let normalized = normalize_host(raw);
    compiled.push(host_glob(&normalized, raw)?);
    for spelling in alternate_rule_spellings(&normalized) {
        compiled.push(host_glob(&spelling, raw)?);
    }
    Ok(())
}

/// The other spellings of one host rule, each naming the same asset the
/// operator wrote down rather than a new one. Candidates arrive carrying the
/// dotted quad a shorthand IPv4 host names and the ASCII domain IDNA resolves a
/// non-ASCII host to, so a rule written either way is compiled in both forms;
/// a rule written in punycode also gains the Unicode domain it encodes, so it
/// keeps matching a target spelled the way an operator reads it.
fn alternate_rule_spellings(normalized: &str) -> Vec<String> {
    let mut spellings = Vec::new();
    if let Some(address) = ipv4_shorthand_address(normalized) {
        spellings.push(address);
    }
    if let Some(ascii) = idna_ascii_rule_spelling(normalized) {
        spellings.push(ascii);
    }
    if let Some(unicode) = punycode_decoded_domain(normalized) {
        spellings.push(unicode);
    }
    spellings
}

fn host_glob(pattern: &str, raw: &str) -> Result<HostPattern> {
    Glob::new(pattern)
        .map(HostPattern::HostGlob)
        .with_context(|| format!("invalid host glob in scope.toml: {raw}"))
}

fn matches_any(patterns: &[HostPattern], host: &str) -> bool {
    patterns
        .iter()
        .any(|pattern| matches_pattern(pattern, host))
}

fn matches_pattern(pattern: &HostPattern, host: &str) -> bool {
    match pattern {
        HostPattern::HostGlob(glob) => glob.compile_matcher().is_match(host),
        HostPattern::Cidr(cidr) => cidr_contains_host(cidr, host),
    }
}

/// `true` when a candidate host is an IP literal inside the rule's range.
/// A candidate is tested in both of the families it can name: `::ffff:10.0.0.1`
/// is the IPv4-mapped form of `10.0.0.1` (RFC 4291 §2.5.5.2), so a client that
/// connects to it reaches the IPv4 host and an IPv4 rule has to cover it.
/// `ipnet` compares families strictly, so without the mapped form a deny rule
/// written `10.99.0.0/16` would let `[::ffff:10.99.0.1]:443` through.
/// Both forms are tried, never one instead of the other, so a rule already
/// written in the mapped IPv6 range keeps matching the addresses it named.
fn cidr_contains_host(cidr: &IpNet, host: &str) -> bool {
    let Ok(addr) = IpAddr::from_str(host) else {
        return false;
    };
    cidr.contains(&addr) || mapped_ipv4(addr).is_some_and(|v4| cidr.contains(&v4))
}

/// The IPv4 address an IPv4-mapped IPv6 literal names, if it is one. The
/// deprecated IPv4-compatible form (`::10.0.0.1`) is deliberately excluded:
/// RFC 4291 §2.5.5.1 retired it and current stacks do not route it to the
/// embedded IPv4 host, so treating it as that host would widen a rule past
/// what an operator's file says.
fn mapped_ipv4(addr: IpAddr) -> Option<IpAddr> {
    match addr {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4),
        IpAddr::V4(_) => None,
    }
}

/// An inclusive run of addresses, in one family, as comparable numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AddressRange {
    is_ipv4: bool,
    low: u128,
    high: u128,
}

/// The block a target names when it names more than one address, or `None`
/// when it names a single host that [`candidate_hosts`] already judges.
///
/// nmap takes a block, not just a host: `nmap 10.0.0.0/8`, `10.99.0-255.1`, and
/// `10.0.0.1,2` each probe every address between their ends. Reading only the
/// one host such a target starts with broke the gate in both directions. A deny
/// rule was evaded by widening the target — `10.0.0.0/8` reaches every address
/// a `10.99.0.0/16` deny rule names, but its own network address sits outside
/// that rule, so the target came back `Unknown` and the scan ran. An allow list
/// was satisfied by a network address while the scan continued past it —
/// `10.0.0.0/7` matched a `10.0.0.0/8` allow rule and then reached
/// `11.0.0.0/8` — and a plainly in-scope `10.0.0-255.5` was refused, because
/// the literal matched no rule at all.
///
/// Only a caller reading an nmap target specification gets this, because the
/// syntax is nmap's. Every other client resolves `10.0.0.1-2` as a domain name,
/// which can answer with any address at all, so reading it as the two addresses
/// it looks like would admit an asset no rule covers.
///
/// The block is weighed alongside the host readings, never instead of them, so
/// a rule written against the block's own address keeps matching it. A form
/// this cannot read names no block it can judge, so it contributes none rather
/// than a guessed one.
fn candidate_range(target: &str, syntax: TargetSyntax) -> Option<AddressRange> {
    if syntax != TargetSyntax::AddressBlock {
        return None;
    }
    let trimmed = target.trim();
    let range = cidr_target_range(trimmed).or_else(|| octet_target_range(trimmed))?;
    (range.low < range.high).then_some(range)
}

/// The range a CIDR block covers. `ipnet` parses only `address/prefix`, so a
/// URL, a bare host, and a dotted quad all yield nothing here.
fn cidr_target_range(target: &str) -> Option<AddressRange> {
    Some(cidr_range(IpNet::from_str(target).ok()?))
}

fn cidr_range(cidr: IpNet) -> AddressRange {
    match cidr {
        IpNet::V4(v4) => AddressRange {
            is_ipv4: true,
            low: u128::from(u32::from(v4.network())),
            high: u128::from(u32::from(v4.broadcast())),
        },
        IpNet::V6(v6) => AddressRange {
            is_ipv4: false,
            low: u128::from(v6.network()),
            high: u128::from(v6.broadcast()),
        },
    }
}

/// The range an nmap octet specification names: every address between the
/// lowest and highest value each octet allows. `None` unless all four octets
/// are decimal numbers, ranges, or lists, so `my-host.test` and a hostname
/// carrying a hyphen are left to the host readings.
///
/// A discontinuous list is judged by the run it spans, so `10.0.0.1,9` is
/// weighed as `10.0.0.1`–`10.0.0.9`. That can refuse a deny rule naming only an
/// address the list skips; erring toward refusal on a target the operator can
/// spell exactly is the safe direction.
fn octet_target_range(target: &str) -> Option<AddressRange> {
    let bounds: Vec<(u8, u8)> = target.split('.').map(octet_bounds).collect::<Option<_>>()?;
    let [first, second, third, fourth] = <[(u8, u8); 4]>::try_from(bounds).ok()?;
    Some(AddressRange {
        is_ipv4: true,
        low: packed_octets([first.0, second.0, third.0, fourth.0]),
        high: packed_octets([first.1, second.1, third.1, fourth.1]),
    })
}

fn packed_octets(octets: [u8; 4]) -> u128 {
    u128::from(u32::from(Ipv4Addr::from(octets)))
}

/// The lowest and highest value one octet of an nmap specification allows,
/// across every comma-separated item in it.
fn octet_bounds(octet: &str) -> Option<(u8, u8)> {
    let items: Vec<(u8, u8)> = octet.split(',').map(octet_item_bounds).collect::<Option<_>>()?;
    let low = items.iter().map(|(low, _)| *low).min()?;
    let high = items.iter().map(|(_, high)| *high).max()?;
    Some((low, high))
}

/// One item of an octet: `7`, `7-9`, or a range with an end left open, which
/// nmap fills with the widest value that end allows.
fn octet_item_bounds(item: &str) -> Option<(u8, u8)> {
    let Some((low, high)) = item.split_once('-') else {
        let value = item.parse().ok()?;
        return Some((value, value));
    };
    let low = octet_end(low, u8::MIN)?;
    let high = octet_end(high, u8::MAX)?;
    (low <= high).then_some((low, high))
}

fn octet_end(text: &str, open: u8) -> Option<u8> {
    match text.is_empty() {
        true => Some(open),
        false => text.parse().ok(),
    }
}

/// `true` when one rule names an address inside the block.
fn reaches_range(patterns: &[HostPattern], range: AddressRange) -> bool {
    weigh_range(patterns, range, |rule, reading| {
        rule.low <= reading.high && reading.low <= rule.high
    }) || addresses_in_range(range).is_some_and(|addresses| {
        addresses.iter().any(|address| matches_any(patterns, address))
    })
}

/// `true` when the rules name every address in the block.
///
/// A CIDR rule has to contain all of it on its own. Stitching a block together
/// from several rules is attempted only where every address can be weighed
/// individually, because that is where the answer is exact: the operator can
/// write the block they mean, and refusing the target they did not write is the
/// safe direction to be wrong in.
fn covers_range(patterns: &[HostPattern], range: AddressRange) -> bool {
    weigh_range(patterns, range, |rule, reading| {
        rule.low <= reading.low && reading.high <= rule.high
    }) || addresses_in_range(range).is_some_and(|addresses| {
        addresses.iter().all(|address| matches_any(patterns, address))
    })
}

/// How many addresses a block may hold and still be weighed one address at a
/// time. A host glob names names, so the only exact way to learn whether one
/// covers a block is to ask it about every address in the block. A `/24` and
/// the octet specifications operators write are worth expanding that way; a
/// larger block is left to the CIDR rules, which answer without expanding
/// anything.
const ENUMERABLE_BLOCK_ADDRESSES: u128 = 256;

/// Every address in a block small enough to expand, or `None` when it is not.
/// A rule written as a host glob therefore reaches a `/24` but not a `/8`; an
/// operator naming addresses should write them as `cidrs`, which carry no such
/// limit.
fn addresses_in_range(range: AddressRange) -> Option<Vec<String>> {
    let width = range.high.checked_sub(range.low)?;
    (width < ENUMERABLE_BLOCK_ADDRESSES).then(|| {
        (range.low..=range.high)
            .map(|value| range_address(range.is_ipv4, value))
            .collect()
    })
}

fn range_address(is_ipv4: bool, value: u128) -> String {
    match u32::try_from(value) {
        Ok(v4) if is_ipv4 => Ipv4Addr::from(v4).to_string(),
        _ => Ipv6Addr::from(value).to_string(),
    }
}

/// `true` when one CIDR rule stands in the given relation to the target range,
/// each weighed in the family the rule is written in. Host globs name names,
/// not addresses, so they take no part in weighing a range.
fn weigh_range(
    patterns: &[HostPattern],
    range: AddressRange,
    relation: impl Fn(AddressRange, AddressRange) -> bool,
) -> bool {
    let readings = range_readings(range);
    rule_ranges(patterns).any(|rule| {
        readings
            .iter()
            .any(|reading| reading.is_ipv4 == rule.is_ipv4 && relation(rule, *reading))
    })
}

fn rule_ranges(patterns: &[HostPattern]) -> impl Iterator<Item = AddressRange> + '_ {
    patterns.iter().filter_map(|pattern| match pattern {
        HostPattern::Cidr(cidr) => Some(cidr_range(*cidr)),
        HostPattern::HostGlob(_) => None,
    })
}

/// Where the IPv4-mapped IPv6 block `::ffff:0:0/96` begins (RFC 4291 §2.5.5.2).
const IPV4_MAPPED_BASE: u128 = 0xffff_0000_0000;

/// Every family a target range can be read in. An IPv4 range is also the
/// mapped IPv6 range a client reaches through `::ffff:…`, and a mapped IPv6
/// range is also the IPv4 range it names, so a rule written in either family
/// weighs the same addresses. This is the equivalence [`cidr_contains_host`]
/// already applies to a single host.
fn range_readings(range: AddressRange) -> Vec<AddressRange> {
    match mapped_range_reading(range) {
        Some(mapped) => vec![range, mapped],
        None => vec![range],
    }
}

fn mapped_range_reading(range: AddressRange) -> Option<AddressRange> {
    if range.is_ipv4 {
        return Some(AddressRange {
            is_ipv4: false,
            low: IPV4_MAPPED_BASE + range.low,
            high: IPV4_MAPPED_BASE + range.high,
        });
    }
    let low = range.low.checked_sub(IPV4_MAPPED_BASE)?;
    let high = range.high.checked_sub(IPV4_MAPPED_BASE)?;
    (high <= u128::from(u32::MAX)).then_some(AddressRange {
        is_ipv4: true,
        low,
        high,
    })
}

/// The dotted-quad address a host written in one of the URL Standard's other
/// IPv4 notations names, or `None` when the host is a domain or already a
/// canonical dotted quad.
///
/// The URL Standard's IPv4 parser reads a host whose last label is a number as
/// an address, in hexadecimal (`0xa9.0xfe.0xa9.0xfe`), octal
/// (`0251.0376.0251.0376`), or with the last label filling every octet the
/// earlier ones left (`169.254.43518`, `2852039166`). Browsers, `curl`, Go, and
/// libc `inet_aton` all reach 169.254.169.254 through each of those. But
/// `IpAddr::from_str` accepts only the dotted quad, so [`cidr_contains_host`]
/// saw no address to test and a `169.254.0.0/16` deny rule left the target
/// `Unknown` — the deny-list-shaped bypass, since an allow list refuses a host
/// it does not match either way.
///
/// The address is one more reading of the same target, never a replacement, so
/// a rule written against the literal keeps matching it. A host the parser
/// fails on names no host a client can reach, so it contributes nothing rather
/// than a guessed address.
fn ipv4_shorthand_address(host: &str) -> Option<String> {
    if !ends_in_ipv4_number(host) {
        return None;
    }
    let canonical = parse_ipv4_host(host)?.to_string();
    (canonical != host).then_some(canonical)
}

/// The URL Standard reads a host as IPv4 only when its last label is a number.
/// Every other host stays a domain, so `api.example.com` and `host1.corp` are
/// never re-read as addresses.
fn ends_in_ipv4_number(host: &str) -> bool {
    let last = ipv4_parts(host).last().copied().unwrap_or_default();
    if last.is_empty() {
        return false;
    }
    last.bytes().all(|byte| byte.is_ascii_digit()) || ipv4_number(last).is_some()
}

/// The labels the URL Standard's IPv4 parser reads, dropping the trailing empty
/// label a root dot leaves behind.
fn ipv4_parts(host: &str) -> Vec<&str> {
    let mut parts: Vec<&str> = host.split('.').collect();
    if parts.len() > 1 && parts.last() == Some(&"") {
        parts.pop();
    }
    parts
}

/// The address a host of IPv4 numbers names: the last label fills every octet
/// no earlier label claimed, which is what makes `127.1` and `2130706433` the
/// same address as `127.0.0.1`. `None` when the host carries more than four
/// labels, or a label overflows the room left for it — the URL Standard fails
/// the whole URL there.
fn parse_ipv4_host(host: &str) -> Option<Ipv4Addr> {
    let parts = ipv4_parts(host);
    if parts.len() > 4 {
        return None;
    }
    let numbers: Vec<u64> = parts.iter().map(|part| ipv4_number(part)).collect::<Option<_>>()?;
    let (last, leading) = numbers.split_last()?;
    if leading.iter().any(|number| *number > 255) {
        return None;
    }
    if *last >= 256u64.pow(4 - leading.len() as u32) {
        return None;
    }
    Some(Ipv4Addr::from(packed_ipv4_address(*last as u32, leading)))
}

fn packed_ipv4_address(last: u32, leading: &[u64]) -> u32 {
    leading
        .iter()
        .enumerate()
        .fold(last, |address, (index, number)| {
            address + (*number as u32) * 256u32.pow(3 - index as u32)
        })
}

/// One label of an IPv4 literal, in the radix its prefix names. `None` for a
/// label that is not a number in that radix, which leaves the host a domain.
fn ipv4_number(label: &str) -> Option<u64> {
    if label.is_empty() {
        return None;
    }
    let (radix, digits) = ipv4_radix(label);
    if digits.is_empty() {
        return Some(0);
    }
    if !digits.chars().all(|digit| digit.is_digit(radix)) {
        return None;
    }
    u64::from_str_radix(digits, radix).ok()
}

/// `0x` marks hexadecimal and a leading `0` octal, both only on a label long
/// enough to carry a digit after the prefix, so a lone `0` stays decimal zero.
fn ipv4_radix(label: &str) -> (u32, &str) {
    if label.len() < 2 {
        return (10, label);
    }
    if let Some(digits) = label
        .strip_prefix("0x")
        .or_else(|| label.strip_prefix("0X"))
    {
        return (16, digits);
    }
    match label.strip_prefix('0') {
        Some(digits) => (8, digits),
        None => (10, label),
    }
}

/// Where the authority stops under RFC 3986, which Go's `net/url` and most
/// non-browser HTTP clients implement. A backslash is an ordinary character
/// there, so it stays inside the authority.
const RFC_3986_AUTHORITY_END: &[char] = &['/', '?', '#'];

/// Where the authority stops under the WHATWG URL Standard, which browsers and
/// browser-derived clients implement: for a special scheme a backslash is a
/// path separator, exactly like a slash.
const URL_STANDARD_AUTHORITY_END: &[char] = &['/', '\\', '?', '#'];

/// Every host a candidate target could name, deduplicated and never empty.
///
/// The two parser families above disagree about a target such as
/// `https://evil.test\@in-scope.host`: RFC 3986 reads `evil.test\` as userinfo
/// and reaches `in-scope.host`, while the URL Standard ends the authority at
/// the backslash and reaches `evil.test`. The same split opens on an embedded
/// tab, CR, or LF, which the URL Standard strips from the whole URL before
/// parsing and RFC 3986 keeps. Whichever one a downstream scanner uses, this
/// gate cannot know, so it refuses to pick the permissive reading: the caller
/// weighs every host the target could reach.
///
/// Each reading is also weighed in its percent-decoded form, because a client
/// that decodes the domain reaches a different host than one that does not.
/// See [`percent_decoded_host`]. A reading written in one of the URL Standard's
/// other IPv4 notations additionally yields the dotted quad it names, so a CIDR
/// rule is tested against the address a client actually connects to. See
/// [`ipv4_shorthand_address`]. A non-ASCII reading additionally yields the ASCII
/// domain IDNA resolves it to, so a rule is tested against the name that
/// actually goes on the wire. See [`idna_ascii_domain`].
///
/// Legitimate targets carry none of those characters, so both readings agree
/// and this returns the single host [`extract_host`] always returned.
fn candidate_hosts(target: &str) -> Vec<String> {
    let mut hosts = Vec::new();
    push_readings(&mut hosts, extract_host(target, RFC_3986_AUTHORITY_END));
    push_readings(
        &mut hosts,
        extract_host(
            &strip_url_standard_whitespace(target),
            URL_STANDARD_AUTHORITY_END,
        ),
    );
    hosts
}

fn push_readings(hosts: &mut Vec<String>, host: String) {
    if let Some(decoded) = percent_decoded_host(&host) {
        push_domain_and_host(hosts, decoded);
    }
    push_domain_and_host(hosts, host);
}

/// Push one host reading, preceded by the ASCII domain IDNA resolves it to.
/// The mapped spelling goes through [`push_address_and_host`] too, so a host
/// whose IPv4 shorthand is written in non-ASCII digits still yields the address
/// it names.
fn push_domain_and_host(hosts: &mut Vec<String>, host: String) {
    if let Some(ascii) = idna_ascii_domain(&host) {
        push_address_and_host(hosts, ascii);
    }
    push_address_and_host(hosts, host);
}

/// Push one host reading, preceded by the dotted-quad address it names when it
/// is written in one of the URL Standard's other IPv4 notations.
fn push_address_and_host(hosts: &mut Vec<String>, host: String) {
    if let Some(address) = ipv4_shorthand_address(&host) {
        push_unique(hosts, address);
    }
    push_unique(hosts, host);
}

fn push_unique(hosts: &mut Vec<String>, host: String) {
    if !hosts.contains(&host) {
        hosts.push(host);
    }
}

/// The ASCII domain a non-ASCII host resolves to under UTS 46, or `None` when
/// the host is already ASCII or names no domain at all.
///
/// DNS carries ASCII, so every client that accepts a Unicode host first maps it
/// with UTS 46 and encodes the result as punycode. That mapping is not a
/// spelling change: it case-folds, applies compatibility decompositions, and
/// rewrites label separators, so `ａdmin.example.com` (U+FF41) and
/// `admin。example.com` (U+3002) both resolve to `admin.example.com`, and
/// `bücher.example` resolves to `xn--bcher-kva.example`. Comparing only the
/// written form let a target reach a denied host while matching no rule — the
/// deny-list-shaped bypass, since an allow list refuses a host it does not
/// match either way.
///
/// The domain is one more reading of the same target, never a replacement, so a
/// rule written against the Unicode form keeps matching it. A host UTS 46
/// rejects names nothing a client can resolve, so it contributes no reading
/// rather than a mangled one: invalid punycode, a disallowed code point, or a
/// mapping that lands on a code point the URL Standard forbids in a domain —
/// U+FF1A FULLWIDTH COLON becomes `:`, which ends the host rather than
/// extending it, so the whole URL is rejected there.
///
/// An ASCII host is already the name that goes on the wire and gains nothing
/// from the mapping. Skipping it also keeps IP literals away from the deny
/// list, which forbids the `:` every IPv6 literal is written with.
fn idna_ascii_domain(host: &str) -> Option<String> {
    if host.is_ascii() {
        return None;
    }
    let mapped = idna::domain_to_ascii_cow(host.as_bytes(), idna::AsciiDenyList::URL).ok()?;
    normalized_spelling(&mapped)
}

/// Put a mapped spelling back into the form both sides of the comparison are
/// written in. UTS 46 rewrites non-ASCII label separators, so
/// `admin.example.com。` maps to an ASCII root dot that [`normalize_host`] ran
/// too early to trim; without this the mapped reading would miss the very rule
/// it was derived to match. A spelling that normalizes to nothing names no
/// host, so it is dropped rather than compared as an empty one.
fn normalized_spelling(mapped: &str) -> Option<String> {
    let normalized = normalize_host(mapped);
    (!normalized.is_empty()).then_some(normalized)
}

/// The ASCII spelling of one non-ASCII host rule, mapped without the URL
/// Standard's forbidden-code-point list because a rule is a glob: `[a-z]` and
/// `?` are the operator's own metacharacters, not a host a client rejects.
/// UTS 46 leaves every ASCII character of a glob as written, so only the
/// Unicode labels are encoded.
fn idna_ascii_rule_spelling(pattern: &str) -> Option<String> {
    if pattern.is_ascii() {
        return None;
    }
    normalized_spelling(&idna::domain_to_ascii(pattern).ok()?)
}

/// The Unicode domain a punycode host rule encodes, or `None` when the rule
/// carries no punycode label or its labels do not decode.
///
/// Candidates are weighed in both spellings, so a rule an operator wrote as
/// `xn--bcher-kva.example` has to cover the `bücher.example` reading as well —
/// an allow list requires every reading to match, and without this the operator
/// would be refused the very asset they listed.
fn punycode_decoded_domain(pattern: &str) -> Option<String> {
    if !pattern.contains("xn--") {
        return None;
    }
    let (unicode, result) = idna::domain_to_unicode(pattern);
    result.ok()?;
    normalized_spelling(&unicode).filter(|domain| domain != pattern)
}

/// The host an escaped authority names once its percent-escapes are resolved,
/// or `None` when it carries no escape and the raw reading is the only one.
///
/// The URL Standard percent-decodes the domain before resolving it, and
/// RFC 3986 §3.2.2 defines a reg-name as percent-encoded text, so a client on
/// either side of the split above can reach `admin.example.com` through
/// `admin.example%2ecom`. A client that instead resolves the escape literally
/// reaches nothing, so this is an extra reading rather than a replacement.
///
/// `None` also when decoding yields bytes that are not UTF-8, or a forbidden
/// domain code point such as `/` or `:`: the URL Standard rejects the whole URL
/// there, so it names no host and no rule should be spent on it.
///
/// A decoded non-ASCII domain reaches [`idna_ascii_domain`] through
/// [`push_domain_and_host`] like any other reading, so an escape that hides a
/// Unicode spelling is still judged by the domain it resolves to.
fn percent_decoded_host(host: &str) -> Option<String> {
    let decoded = String::from_utf8(percent_decode(host)?).ok()?;
    if decoded.chars().any(is_forbidden_domain_code_point) {
        return None;
    }
    Some(normalize_host(&decoded))
}

/// Code points the URL Standard forbids inside a domain, beyond the controls
/// [`char::is_control`] already covers.
const FORBIDDEN_DOMAIN_CODE_POINTS: &[char] = &[
    ' ', '#', '%', '/', ':', '<', '>', '?', '@', '[', '\\', ']', '^', '|',
];

fn is_forbidden_domain_code_point(character: char) -> bool {
    character.is_control() || FORBIDDEN_DOMAIN_CODE_POINTS.contains(&character)
}

/// The bytes an escaped host decodes to, or `None` when it carries no escape.
/// A `%` that does not begin a complete two-digit escape stays as written,
/// which is what the URL Standard's percent-decode does with it.
fn percent_decode(host: &str) -> Option<Vec<u8>> {
    let bytes = host.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    let mut escaped = false;
    while index < bytes.len() {
        match hex_escape(bytes, index) {
            Some(byte) => {
                decoded.push(byte);
                index += 3;
                escaped = true;
            }
            None => {
                decoded.push(bytes[index]);
                index += 1;
            }
        }
    }
    escaped.then_some(decoded)
}

/// The byte a `%XX` escape at `index` names. Both digits must be ASCII hex:
/// `u8::from_str_radix` would otherwise accept a sign and read `%+a` as an
/// escape the standards do not define.
fn hex_escape(bytes: &[u8], index: usize) -> Option<u8> {
    let escape = bytes.get(index..index + 3)?;
    if escape[0] != b'%' || !escape[1..].iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    u8::from_str_radix(std::str::from_utf8(&escape[1..]).ok()?, 16).ok()
}

/// Drop the ASCII tab, CR, and LF that the URL Standard removes from a URL
/// before parsing it, so `ev<TAB>il.test` is also read as the `evil.test` a
/// browser would resolve.
fn strip_url_standard_whitespace(target: &str) -> String {
    target
        .chars()
        .filter(|character| !matches!(character, '\t' | '\r' | '\n'))
        .collect()
}

/// Pull the host component out of a free-form target string. Accepts
/// raw hosts, IP literals, `host:port`, and URLs with schemes. Falls
/// back to the trimmed input so unknown formats still get a chance to
/// match host globs. The result is normalized by [`normalize_host`] so a
/// deny rule cannot be evaded by changing the case of a hostname.
fn extract_host(target: &str, authority_end: &[char]) -> String {
    let trimmed = target.trim();
    let after_scheme = trimmed
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(trimmed);
    // The authority ends at the first path/query/fragment delimiter, and the
    // userinfo strip must stay inside it: an `@` later in the URL
    // (`https://evil.test/@in-scope.host`) must not spoof the host.
    let authority = after_scheme
        .split(authority_end)
        .next()
        .unwrap_or(after_scheme);
    let host_and_port = authority
        .rsplit_once('@')
        .map(|(_, rest)| rest)
        .unwrap_or(authority);
    normalize_host(strip_port(host_and_port))
}

/// Put a hostname into the one form both scope patterns and candidate targets
/// are compared in: DNS is case-insensitive (RFC 4343) and the root label is
/// optional, so `ADMIN.Example.com.` and `admin.example.com` name one asset.
/// ASCII-only folding keeps IDN labels from being widened by Unicode case
/// folding. Harmless for IP literals: addresses carry no uppercase ASCII
/// letters beyond hex digits, which parse either way.
fn normalize_host(host: &str) -> String {
    trim_root_dot(host.trim()).to_ascii_lowercase()
}

/// Drop the optional DNS root label. A scope glob may spell that final dot as
/// an escaped `\.`; globset treats `.` as an ordinary character, so the escape
/// is redundant and both spellings name the same host. The escape has to leave
/// with its dot — a lone trailing `\` is a `DanglingEscape` that globset
/// refuses to compile, which would fail the whole scope file to load. Candidate
/// hosts carry no escapes, so for them this is a plain trailing-dot trim.
fn trim_root_dot(host: &str) -> &str {
    let mut rest = host;
    while let Some(head) = rest.strip_suffix('.') {
        rest = match escapes_the_root_dot(head) {
            true => &head[..head.len() - 1],
            false => head,
        };
    }
    rest
}

/// `true` when the text before a root dot ends in a backslash that escapes it.
/// An odd run of backslashes escapes the dot; an even run is literal
/// backslashes that the dot merely follows.
fn escapes_the_root_dot(head: &str) -> bool {
    (head.len() - head.trim_end_matches('\\').len()) % 2 == 1
}

fn strip_port(host: &str) -> &str {
    // Brackets denote IPv6 literals — `[::1]:8080` becomes `::1`.
    if let Some(bracket_end) = host.strip_prefix('[').and_then(|rest| rest.find(']')) {
        return &host[1..1 + bracket_end];
    }
    // A bare IPv6 literal is all colons and has no port to strip; splitting it
    // would leave a fragment that never matches a CIDR rule.
    if IpAddr::from_str(host).is_ok() {
        return host;
    }
    host.rsplit_once(':').map(|(host, _)| host).unwrap_or(host)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(toml_text: &str) -> ProgramScope {
        ProgramScope::parse(toml_text).expect("scope must parse")
    }

    /// The verdict a caller reading an nmap target specification gets.
    fn block_verdict(scope: &ProgramScope, target: &str) -> ScopeVerdict {
        scope.verdict_for(target, TargetSyntax::AddressBlock)
    }

    #[test]
    fn empty_scope_returns_unknown_for_everything() {
        let scope = ProgramScope::default();
        assert!(scope.is_empty());
        assert_eq!(scope.verdict("example.com"), ScopeVerdict::Unknown);
        assert_eq!(scope.verdict("10.0.0.1"), ScopeVerdict::Unknown);
    }

    #[test]
    fn host_glob_matches_in_scope_subdomain() {
        let scope = scope(
            r#"
            [in_scope]
            hosts = ["*.example.com"]
            "#,
        );
        assert_eq!(scope.verdict("api.example.com"), ScopeVerdict::InScope);
        assert_eq!(scope.verdict("evil.com"), ScopeVerdict::OutOfScope);
    }

    #[test]
    fn deny_list_only_scope_allows_unknown_hosts() {
        let scope = scope(
            r#"
            [out_of_scope]
            hosts = ["admin.example.com"]
            "#,
        );
        assert_eq!(scope.verdict("admin.example.com"), ScopeVerdict::OutOfScope);
        assert_eq!(scope.verdict("api.example.com"), ScopeVerdict::Unknown);
    }

    #[test]
    fn out_of_scope_overrides_in_scope() {
        let scope = scope(
            r#"
            [in_scope]
            hosts = ["*.example.com"]
            [out_of_scope]
            hosts = ["admin.example.com"]
            "#,
        );
        assert_eq!(scope.verdict("admin.example.com"), ScopeVerdict::OutOfScope);
        assert_eq!(scope.verdict("api.example.com"), ScopeVerdict::InScope);
    }

    #[test]
    fn cidr_matches_in_scope_address() {
        let scope = scope(
            r#"
            [in_scope]
            cidrs = ["10.0.0.0/8"]
            "#,
        );
        assert_eq!(scope.verdict("10.42.7.1"), ScopeVerdict::InScope);
        assert_eq!(scope.verdict("11.0.0.1"), ScopeVerdict::OutOfScope);
    }

    #[test]
    fn url_inputs_are_reduced_to_host_for_matching() {
        let scope = scope(
            r#"
            [in_scope]
            hosts = ["*.example.com"]
            "#,
        );
        assert_eq!(
            scope.verdict("https://api.example.com/path?q=1"),
            ScopeVerdict::InScope
        );
        assert_eq!(
            scope.verdict("http://user:pw@api.example.com:8443/"),
            ScopeVerdict::InScope
        );
    }

    #[test]
    fn at_sign_in_path_query_or_fragment_cannot_spoof_the_host() {
        let scope = scope(
            r#"
            [in_scope]
            hosts = ["*.example.com"]
            "#,
        );
        assert_eq!(
            scope.verdict("https://evil.test/@api.example.com"),
            ScopeVerdict::OutOfScope
        );
        assert_eq!(
            scope.verdict("https://evil.test/?next=user@api.example.com"),
            ScopeVerdict::OutOfScope
        );
        assert_eq!(
            scope.verdict("https://evil.test/#user@api.example.com"),
            ScopeVerdict::OutOfScope
        );
    }

    #[test]
    fn a_backslash_authority_delimiter_cannot_spoof_the_host() {
        // The URL Standard ends the authority at the backslash and reaches
        // `evil.test`; RFC 3986 reads `evil.test\` as userinfo and reaches
        // `api.example.com`. The deny rule covers the first reading, so the
        // target is refused rather than handed to whichever parser runs next.
        let scope = scope(
            r#"
            [out_of_scope]
            hosts = ["evil.test"]
            "#,
        );
        assert_eq!(
            scope.verdict(r"https://evil.test\@api.example.com/"),
            ScopeVerdict::OutOfScope
        );
    }

    #[test]
    fn an_allow_list_must_cover_both_readings_of_a_backslash_target() {
        let scope = scope(
            r#"
            [in_scope]
            hosts = ["*.example.com"]
            "#,
        );
        // Only the RFC 3986 reading lands inside the allow list; a browser
        // would reach `evil.test`, which nothing allows.
        assert_eq!(
            scope.verdict(r"https://evil.test\@api.example.com/"),
            ScopeVerdict::OutOfScope
        );
        // Reversed: only the URL Standard reading is allowed.
        assert_eq!(
            scope.verdict(r"https://api.example.com\@evil.test/"),
            ScopeVerdict::OutOfScope
        );
    }

    #[test]
    fn embedded_url_whitespace_cannot_evade_a_deny_rule() {
        // The URL Standard strips tab, CR, and LF before parsing, so a client
        // that implements it resolves `admin.example.com`.
        let scope = scope(
            r#"
            [out_of_scope]
            hosts = ["admin.example.com"]
            "#,
        );
        assert_eq!(
            scope.verdict("https://admin.exa\tmple.com/panel"),
            ScopeVerdict::OutOfScope
        );
        assert_eq!(
            scope.verdict("https://admin.exa\nmple.com/panel"),
            ScopeVerdict::OutOfScope
        );
        assert_eq!(
            scope.verdict("https://admin.exa\r\nmple.com/panel"),
            ScopeVerdict::OutOfScope
        );
    }

    #[test]
    fn a_percent_escaped_dot_cannot_evade_a_deny_rule() {
        // A client that percent-decodes the domain — every browser does, and
        // RFC 3986 defines a reg-name as percent-encoded — reaches
        // `admin.example.com`.
        let scope = scope(
            r#"
            [out_of_scope]
            hosts = ["admin.example.com"]
            "#,
        );
        assert_eq!(
            scope.verdict("https://admin.example%2ecom/panel"),
            ScopeVerdict::OutOfScope
        );
        assert_eq!(
            scope.verdict("https://ADMIN.EXAMPLE%2ECOM/panel"),
            ScopeVerdict::OutOfScope
        );
        // The escape may also spell the whole label separator away from the
        // authority delimiters the earlier readings split on.
        assert_eq!(
            scope.verdict("admin%2eexample%2ecom:8443"),
            ScopeVerdict::OutOfScope
        );
    }

    #[test]
    fn an_allow_list_must_cover_both_readings_of_an_escaped_target() {
        let scope = scope(
            r#"
            [in_scope]
            hosts = ["*.example.com"]
            "#,
        );
        // Only the decoding reading lands inside the allow list; a client that
        // resolves the escape literally reaches a host nothing allows.
        assert_eq!(
            scope.verdict("https://api.example%2ecom/"),
            ScopeVerdict::OutOfScope
        );
        // An unescaped target is unaffected.
        assert_eq!(
            scope.verdict("https://api.example.com/"),
            ScopeVerdict::InScope
        );
    }

    #[test]
    fn an_escape_that_decodes_to_a_forbidden_code_point_names_no_host() {
        // The URL Standard refuses a domain containing `/`, `:`, or `%`, so
        // these URLs reach nothing and no rule is spent on the text after the
        // escape.
        let scope = scope(
            r#"
            [out_of_scope]
            hosts = ["evil.test", "admin.example.com"]
            "#,
        );
        assert_eq!(
            scope.verdict("https://admin.example%2fevil.test/"),
            ScopeVerdict::Unknown
        );
        assert_eq!(
            scope.verdict("https://admin.example%3aevil.test/"),
            ScopeVerdict::Unknown
        );
        assert_eq!(
            scope.verdict("https://admin.example%252ecom/"),
            ScopeVerdict::Unknown
        );
    }

    #[test]
    fn a_forbidden_decoded_reading_is_dropped_rather_than_matched() {
        // This deny rule matches only the decoded reading
        // `admin.example:evil.test`; the raw authority carries no `:` at all.
        // The verdict stays `Unknown` precisely because a decoded `:` is a
        // forbidden domain code point, so that reading names no host a client
        // can reach and is dropped instead of judged.
        let scope = scope(
            r#"
            [out_of_scope]
            hosts = ["admin.example:*"]
            "#,
        );
        assert_eq!(
            scope.verdict("https://admin.example%3aevil.test/"),
            ScopeVerdict::Unknown
        );
    }

    #[test]
    fn percent_decoded_host_only_reports_a_second_reachable_reading() {
        assert_eq!(
            percent_decoded_host("admin.example%2ecom"),
            Some("admin.example.com".to_string())
        );
        // A trailing root dot written as an escape normalizes with the rest.
        assert_eq!(
            percent_decoded_host("admin.example.com%2e"),
            Some("admin.example.com".to_string())
        );
        // No escape at all, so the raw reading is the only one.
        assert_eq!(percent_decoded_host("admin.example.com"), None);
        // `%` that begins no complete escape stays as written, and a literal
        // `%` is forbidden inside a domain.
        assert_eq!(percent_decoded_host("admin.example.com%"), None);
        assert_eq!(percent_decoded_host("admin.example.com%2"), None);
        // `u8::from_str_radix` accepts a sign; a `%+a` is not an escape.
        assert_eq!(percent_decoded_host("admin.example.com%+a"), None);
        // Decoded bytes that are not UTF-8 name no host a client can resolve.
        assert_eq!(percent_decoded_host("admin.example%ffcom"), None);
    }

    #[test]
    fn candidate_hosts_are_one_host_when_both_parsers_agree() {
        // The overwhelmingly common case: no second reading is invented for an
        // ordinary target, so nothing an operator writes is refused twice over.
        assert_eq!(
            candidate_hosts("https://user:pw@api.example.com:8443/path?q=1#f"),
            vec!["api.example.com".to_string()]
        );
        assert_eq!(candidate_hosts("10.0.0.1"), vec!["10.0.0.1".to_string()]);
        assert_eq!(
            candidate_hosts(r"https://evil.test\@api.example.com/"),
            vec!["api.example.com".to_string(), "evil.test".to_string()]
        );
    }

    #[test]
    fn host_with_port_strips_port_before_matching() {
        let scope = scope(
            r#"
            [in_scope]
            hosts = ["api.example.com"]
            "#,
        );
        assert_eq!(scope.verdict("api.example.com:8080"), ScopeVerdict::InScope);
    }

    #[test]
    fn ipv6_literal_strips_brackets_and_port() {
        let scope = scope(
            r#"
            [in_scope]
            cidrs = ["::1/128"]
            "#,
        );
        assert_eq!(scope.verdict("[::1]:8080"), ScopeVerdict::InScope);
    }

    #[test]
    fn bare_ipv6_literal_is_matched_against_cidr_rules() {
        let scope = scope(
            r#"
            [out_of_scope]
            cidrs = ["2001:db8::/32"]
            "#,
        );
        assert_eq!(scope.verdict("2001:db8::1"), ScopeVerdict::OutOfScope);
        assert_eq!(
            scope.verdict("https://[2001:db8::1]:8443/"),
            ScopeVerdict::OutOfScope
        );
        assert_eq!(scope.verdict("2001:dead::1"), ScopeVerdict::Unknown);
    }

    #[test]
    fn ipv4_mapped_ipv6_literal_does_not_evade_a_deny_cidr() {
        let scope = scope(
            r#"
            [out_of_scope]
            cidrs = ["10.99.0.0/16"]
            "#,
        );
        assert_eq!(scope.verdict("10.99.0.1"), ScopeVerdict::OutOfScope);
        assert_eq!(scope.verdict("::ffff:10.99.0.1"), ScopeVerdict::OutOfScope);
        assert_eq!(
            scope.verdict("https://[::ffff:10.99.0.1]:8443/panel"),
            ScopeVerdict::OutOfScope
        );
        // Uppercase hex names the same address, and the host is normalized
        // before it is parsed.
        assert_eq!(scope.verdict("::FFFF:10.99.0.1"), ScopeVerdict::OutOfScope);
        assert_eq!(scope.verdict("::ffff:10.98.0.1"), ScopeVerdict::Unknown);
    }

    #[test]
    fn ipv4_mapped_ipv6_literal_matches_an_allow_cidr() {
        let scope = scope(
            r#"
            [in_scope]
            cidrs = ["10.0.0.0/8"]
            "#,
        );
        assert_eq!(scope.verdict("::ffff:10.42.7.1"), ScopeVerdict::InScope);
        assert_eq!(scope.verdict("::ffff:11.0.0.1"), ScopeVerdict::OutOfScope);
    }

    #[test]
    fn a_cidr_rule_written_in_the_mapped_range_still_matches() {
        let scope = scope(
            r#"
            [out_of_scope]
            cidrs = ["::ffff:10.99.0.0/112"]
            "#,
        );
        assert_eq!(scope.verdict("::ffff:10.99.0.1"), ScopeVerdict::OutOfScope);
    }

    #[test]
    fn a_non_mapped_ipv6_literal_is_not_read_as_an_ipv4_address() {
        // `::10.0.0.1` is the retired IPv4-compatible form and `::1` embeds no
        // IPv4 host at all. Neither may borrow an IPv4 rule's verdict.
        let scope = scope(
            r#"
            [out_of_scope]
            cidrs = ["10.0.0.0/8"]
            "#,
        );
        assert_eq!(scope.verdict("::10.0.0.1"), ScopeVerdict::Unknown);
        assert_eq!(scope.verdict("::1"), ScopeVerdict::Unknown);
    }

    #[test]
    fn host_case_does_not_evade_a_deny_rule() {
        let scope = scope(
            r#"
            [in_scope]
            hosts = ["*.example.com"]
            [out_of_scope]
            hosts = ["admin.example.com"]
            "#,
        );
        assert_eq!(scope.verdict("ADMIN.example.com"), ScopeVerdict::OutOfScope);
        assert_eq!(
            scope.verdict("https://Admin.Example.COM/panel"),
            ScopeVerdict::OutOfScope
        );
    }

    #[test]
    fn deny_rule_written_in_uppercase_still_matches() {
        let scope = scope(
            r#"
            [out_of_scope]
            hosts = ["Admin.Example.COM"]
            "#,
        );
        assert_eq!(scope.verdict("admin.example.com"), ScopeVerdict::OutOfScope);
    }

    #[test]
    fn trailing_root_dot_does_not_evade_a_deny_rule() {
        let scope = scope(
            r#"
            [out_of_scope]
            hosts = ["admin.example.com"]
            "#,
        );
        assert_eq!(scope.verdict("admin.example.com."), ScopeVerdict::OutOfScope);
        assert_eq!(
            scope.verdict("https://admin.example.com.:8443/"),
            ScopeVerdict::OutOfScope
        );
    }

    #[test]
    fn case_and_root_dot_normalize_allow_list_matches_too() {
        let scope = scope(
            r#"
            [in_scope]
            hosts = ["*.example.com"]
            "#,
        );
        assert_eq!(scope.verdict("API.Example.com."), ScopeVerdict::InScope);
    }

    #[test]
    fn a_rule_that_escapes_its_root_dot_still_loads_and_denies_the_host() {
        // globset rejects a dangling `\`, so dropping the dot without its
        // redundant escape would fail the whole scope file to load.
        let scope = scope(
            r#"
            [out_of_scope]
            hosts = ['admin.example.com\.']
            "#,
        );
        assert_eq!(scope.verdict("admin.example.com"), ScopeVerdict::OutOfScope);
        assert_eq!(
            scope.verdict("ADMIN.example.com."),
            ScopeVerdict::OutOfScope
        );
    }

    #[test]
    fn trim_root_dot_removes_root_labels_without_corrupting_escapes() {
        assert_eq!(trim_root_dot("admin.example.com"), "admin.example.com");
        assert_eq!(trim_root_dot("admin.example.com."), "admin.example.com");
        assert_eq!(trim_root_dot("admin.example.com.."), "admin.example.com");
        // An odd run of backslashes escapes the dot: both leave together.
        assert_eq!(trim_root_dot(r"admin.example.com\."), "admin.example.com");
        // An even run is literal backslashes the dot merely follows.
        assert_eq!(trim_root_dot(r"admin.example.com\\."), r"admin.example.com\\");
        assert_eq!(trim_root_dot("."), "");
    }

    #[test]
    fn deny_cidr_covers_the_shorthand_ipv4_notations_a_client_resolves() {
        let scope = scope(
            r#"
            [out_of_scope]
            cidrs = ["169.254.0.0/16"]
            "#,
        );
        for target in [
            "http://169.254.169.254/latest/meta-data",
            "http://2852039166/latest/meta-data",
            "http://0xa9.0xfe.0xa9.0xfe/",
            "http://0xa9fea9fe/",
            "http://0251.0376.0251.0376/",
            "http://169.254.43518/",
            "http://169.254.169.254.:443/",
            "http://2852039166:8080/",
        ] {
            assert_eq!(scope.verdict(target), ScopeVerdict::OutOfScope, "{target}");
        }
    }

    #[test]
    fn deny_host_rule_written_as_a_shorthand_address_covers_the_dotted_quad() {
        let scope = scope(
            r#"
            [out_of_scope]
            hosts = ["2130706433"]
            "#,
        );
        assert_eq!(scope.verdict("127.0.0.1"), ScopeVerdict::OutOfScope);
        assert_eq!(scope.verdict("http://2130706433/"), ScopeVerdict::OutOfScope);
    }

    #[test]
    fn an_allow_list_still_admits_a_host_written_as_a_shorthand_address() {
        let scope = scope(
            r#"
            [in_scope]
            hosts = ["012.0.0.1"]
            "#,
        );
        assert_eq!(scope.verdict("10.0.0.1"), ScopeVerdict::InScope);
        assert_eq!(scope.verdict("012.0.0.1"), ScopeVerdict::InScope);
        assert_eq!(scope.verdict("10.0.0.2"), ScopeVerdict::OutOfScope);
    }

    #[test]
    fn a_domain_is_never_reread_as_an_address() {
        let scope = scope(
            r#"
            [out_of_scope]
            cidrs = ["0.0.0.0/0"]
            "#,
        );
        for target in ["api.example.com", "host1.corp", "0x.example", "1.2.3.4.5"] {
            assert_eq!(scope.verdict(target), ScopeVerdict::Unknown, "{target}");
        }
    }

    #[test]
    fn ipv4_shorthand_address_reads_every_notation_and_declines_the_rest() {
        assert_eq!(
            ipv4_shorthand_address("2852039166").as_deref(),
            Some("169.254.169.254")
        );
        assert_eq!(ipv4_shorthand_address("127.1").as_deref(), Some("127.0.0.1"));
        assert_eq!(ipv4_shorthand_address("0x7f.1").as_deref(), Some("127.0.0.1"));
        assert_eq!(ipv4_shorthand_address("0177.0.0.1").as_deref(), Some("127.0.0.1"));
        // A canonical quad is already the address it names, so it adds no
        // second reading of itself.
        assert_eq!(ipv4_shorthand_address("127.0.0.1"), None);
        assert_eq!(ipv4_shorthand_address("0.0.0.0"), None);
        // Labels the URL Standard fails on name no reachable host.
        assert_eq!(ipv4_shorthand_address("1.2.3.4.5"), None);
        assert_eq!(ipv4_shorthand_address("256.0.0.1"), None);
        assert_eq!(ipv4_shorthand_address("127.16777216"), None);
        assert_eq!(ipv4_shorthand_address("0x1p2"), None);
        assert_eq!(ipv4_shorthand_address("018"), None);
        assert_eq!(ipv4_shorthand_address("99999999999999999999"), None);
        assert_eq!(ipv4_shorthand_address("example.com"), None);
        assert_eq!(ipv4_shorthand_address("::1"), None);
        assert_eq!(ipv4_shorthand_address(""), None);
    }

    #[test]
    fn deny_host_rule_covers_the_unicode_spellings_a_client_resolves() {
        let scope = scope(
            r#"
            [out_of_scope]
            hosts = ["admin.example.com"]
            "#,
        );
        for target in [
            "https://admin.example.com/",
            // U+FF41 FULLWIDTH LATIN SMALL LETTER A maps to `a`.
            "https://\u{FF41}dmin.example.com/",
            // U+3002 IDEOGRAPHIC FULL STOP is a label separator.
            "https://admin\u{3002}example.com/",
            // U+FF21 FULLWIDTH LATIN CAPITAL LETTER A case-folds too.
            "https://\u{FF21}DMIN.example.com:8443/",
            // U+3002 as the *root* label separator: the mapping leaves an ASCII
            // root dot behind, after the trim that would have removed it.
            "https://admin.example.com\u{3002}/",
            "https://admin\u{3002}example.com\u{3002}:8443/",
            // The same fullwidth `a`, hidden behind its UTF-8 escapes.
            "https://%EF%BD%81dmin.example.com/",
        ] {
            assert_eq!(scope.verdict(target), ScopeVerdict::OutOfScope, "{target}");
        }
        assert_eq!(scope.verdict("api.example.com"), ScopeVerdict::Unknown);
    }

    #[test]
    fn deny_host_rule_written_in_unicode_covers_the_punycode_a_client_sends() {
        let scope = scope(
            r#"
            [out_of_scope]
            hosts = ["bücher.example"]
            "#,
        );
        for target in [
            "b\u{FC}cher.example",
            "xn--bcher-kva.example",
            "https://xn--bcher-kva.example/catalog",
        ] {
            assert_eq!(scope.verdict(target), ScopeVerdict::OutOfScope, "{target}");
        }
    }

    #[test]
    fn an_allow_list_admits_a_host_written_in_either_idn_spelling() {
        let punycode = scope(
            r#"
            [in_scope]
            hosts = ["xn--bcher-kva.example"]
            "#,
        );
        assert_eq!(punycode.verdict("b\u{FC}cher.example"), ScopeVerdict::InScope);
        assert_eq!(
            punycode.verdict("xn--bcher-kva.example"),
            ScopeVerdict::InScope
        );
        assert_eq!(
            punycode.verdict("\u{5225}.example.com"),
            ScopeVerdict::OutOfScope
        );

        let unicode = scope(
            r#"
            [in_scope]
            hosts = ["*.bücher.example"]
            "#,
        );
        assert_eq!(
            unicode.verdict("api.b\u{FC}cher.example"),
            ScopeVerdict::InScope
        );
        assert_eq!(
            unicode.verdict("api.xn--bcher-kva.example"),
            ScopeVerdict::InScope
        );
        assert_eq!(
            unicode.verdict("api.example.com"),
            ScopeVerdict::OutOfScope
        );
    }

    #[test]
    fn idna_ascii_domain_maps_only_a_host_dns_cannot_carry() {
        assert_eq!(
            idna_ascii_domain("b\u{FC}cher.example").as_deref(),
            Some("xn--bcher-kva.example")
        );
        assert_eq!(
            idna_ascii_domain("\u{FF41}dmin.example.com").as_deref(),
            Some("admin.example.com")
        );
        // An ASCII host is already the name that goes on the wire, so it adds
        // no second reading of itself.
        assert_eq!(idna_ascii_domain("admin.example.com"), None);
        assert_eq!(idna_ascii_domain("xn--bcher-kva.example"), None);
        assert_eq!(idna_ascii_domain("169.254.169.254"), None);
        // U+2488 DIGIT ONE FULL STOP is disallowed in a domain, so the host
        // names nothing a client can resolve.
        assert_eq!(idna_ascii_domain("\u{2488}example.com"), None);
        // Mappings that land on a forbidden domain code point end the host
        // rather than extending it — U+FF1A becomes `:` and U+FF0F becomes `/`,
        // and the URL Standard rejects the whole URL there.
        assert_eq!(idna_ascii_domain("evil.test\u{FF1A}8080"), None);
        assert_eq!(idna_ascii_domain("admin\u{FF0F}evil.test"), None);
        // The mapping can put back a root dot the trim already ran past, so
        // the spelling is normalized again before it is compared.
        assert_eq!(
            idna_ascii_domain("admin.example.com\u{3002}").as_deref(),
            Some("admin.example.com")
        );
        // A host that maps to nothing but a root label names no host at all.
        assert_eq!(idna_ascii_domain("\u{3002}"), None);
    }

    #[test]
    fn a_rule_spelling_is_normalized_like_the_rule_it_came_from() {
        assert_eq!(
            idna_ascii_rule_spelling("b\u{FC}cher.example\u{3002}").as_deref(),
            Some("xn--bcher-kva.example")
        );
        assert_eq!(
            punycode_decoded_domain("xn--bcher-kva.example\u{3002}").as_deref(),
            Some("b\u{FC}cher.example")
        );

        // Written with its root separator spelled U+3002, the rule still names
        // the one asset, in both spellings of it.
        let scope = scope(
            r#"
            [out_of_scope]
            hosts = ["bücher.example。"]
            "#,
        );
        assert_eq!(
            scope.verdict("b\u{FC}cher.example"),
            ScopeVerdict::OutOfScope
        );
        assert_eq!(
            scope.verdict("xn--bcher-kva.example"),
            ScopeVerdict::OutOfScope
        );
    }

    #[test]
    fn a_rule_glob_keeps_its_metacharacters_in_the_ascii_spelling() {
        // `[ab]` is the operator's character class, not a host a client
        // rejects, so the rule's ASCII spelling is mapped without the URL
        // Standard's forbidden-code-point list.
        assert_eq!(
            idna_ascii_rule_spelling("[ab]pi.b\u{FC}cher.example").as_deref(),
            Some("[ab]pi.xn--bcher-kva.example")
        );
        assert_eq!(idna_ascii_rule_spelling("[ab]pi.example.com"), None);

        let scope = scope(
            r#"
            [in_scope]
            hosts = ["[ab]pi.bücher.example"]
            "#,
        );
        assert_eq!(
            scope.verdict("api.b\u{FC}cher.example"),
            ScopeVerdict::InScope
        );
        assert_eq!(
            scope.verdict("bpi.xn--bcher-kva.example"),
            ScopeVerdict::InScope
        );
        assert_eq!(
            scope.verdict("cpi.xn--bcher-kva.example"),
            ScopeVerdict::OutOfScope
        );
    }

    #[test]
    fn punycode_decoded_domain_reads_only_a_rule_that_encodes_one() {
        assert_eq!(
            punycode_decoded_domain("xn--bcher-kva.example").as_deref(),
            Some("b\u{FC}cher.example")
        );
        assert_eq!(
            punycode_decoded_domain("*.xn--bcher-kva.example").as_deref(),
            Some("*.b\u{FC}cher.example")
        );
        assert_eq!(punycode_decoded_domain("admin.example.com"), None);
        assert_eq!(punycode_decoded_domain("b\u{FC}cher.example"), None);
        // Labels that do not decode name no asset the operator listed.
        assert_eq!(punycode_decoded_domain("xn--a.example.com"), None);
    }

    #[test]
    fn a_unicode_host_still_yields_the_address_its_digits_name() {
        let scope = scope(
            r#"
            [out_of_scope]
            cidrs = ["169.254.0.0/16"]
            "#,
        );
        // Fullwidth digits map to ASCII, leaving the shorthand IPv4 notation
        // the next reading resolves to 169.254.169.254.
        assert_eq!(
            scope.verdict("http://\u{FF12}852039166/"),
            ScopeVerdict::OutOfScope
        );
    }

    #[test]
    fn a_denied_block_cannot_be_reached_by_widening_the_target() {
        let scope = scope(
            r#"
            [out_of_scope]
            cidrs = ["10.99.0.0/16"]
            "#,
        );
        // Every address the deny rule names lies inside each of these, so a
        // scanner handed one probes the denied block.
        assert_eq!(block_verdict(&scope, "10.0.0.0/8"), ScopeVerdict::OutOfScope);
        assert_eq!(block_verdict(&scope, "10.99.0-255.1"), ScopeVerdict::OutOfScope);
        assert_eq!(block_verdict(&scope, "10.99.0.1,2"), ScopeVerdict::OutOfScope);
        assert_eq!(block_verdict(&scope, "10.98-99.0.1"), ScopeVerdict::OutOfScope);
        // A block beside the denied one is still nobody's business to refuse.
        assert_eq!(block_verdict(&scope, "10.98.0.0/16"), ScopeVerdict::Unknown);
        assert_eq!(block_verdict(&scope, "10.98.0.1-9"), ScopeVerdict::Unknown);
    }

    #[test]
    fn an_allow_list_must_cover_every_address_a_block_names() {
        let scope = scope(
            r#"
            [in_scope]
            cidrs = ["10.0.0.0/8"]
            "#,
        );
        assert_eq!(block_verdict(&scope, "10.0.0.0/24"), ScopeVerdict::InScope);
        assert_eq!(block_verdict(&scope, "10.0.0-255.5"), ScopeVerdict::InScope);
        assert_eq!(block_verdict(&scope, "10.0.0.1,9"), ScopeVerdict::InScope);
        // `10.0.0.0/7` starts on the allow rule's own network address and then
        // runs past it into 11.0.0.0/8.
        assert_eq!(block_verdict(&scope, "10.0.0.0/7"), ScopeVerdict::OutOfScope);
        assert_eq!(block_verdict(&scope, "10.0.0-255.5,9"), ScopeVerdict::InScope);
        assert_eq!(block_verdict(&scope, "9-10.0.0.5"), ScopeVerdict::OutOfScope);
    }

    #[test]
    fn a_host_shaped_target_is_never_read_as_an_address_block() {
        let allow = scope(
            r#"
            [in_scope]
            cidrs = ["10.0.0.0/24"]
            "#,
        );
        // curl and the importers resolve `10.0.0.1-2` as a domain name, which
        // can answer with any address at all, so the two addresses it reads
        // like are not what the caller reaches. Only nmap's own reading may
        // treat it as a block.
        assert_eq!(allow.verdict("10.0.0.1-2"), ScopeVerdict::OutOfScope);
        assert_eq!(allow.verdict("10.0.0.1,2"), ScopeVerdict::OutOfScope);
        assert_eq!(block_verdict(&allow, "10.0.0.1-2"), ScopeVerdict::InScope);
        // The same target under a deny-only file stays unknown rather than
        // silently admitted as a covered pair.
        let deny = scope(
            r#"
            [out_of_scope]
            cidrs = ["10.99.0.0/16"]
            "#,
        );
        assert_eq!(deny.verdict("10.99.0.1-2"), ScopeVerdict::Unknown);
        assert_eq!(
            block_verdict(&deny, "10.99.0.1-2"),
            ScopeVerdict::OutOfScope
        );
    }

    #[test]
    fn a_rule_naming_names_still_reaches_a_block_it_can_be_asked_about() {
        let allow = scope(
            r#"
            [in_scope]
            hosts = ["10.0.0.*"]
            "#,
        );
        assert_eq!(block_verdict(&allow, "10.0.0.0/24"), ScopeVerdict::InScope);
        assert_eq!(block_verdict(&allow, "10.0.0.1-9"), ScopeVerdict::InScope);
        // A block too wide to weigh address by address is left to the CIDR
        // rules, which this file has none of.
        assert_eq!(block_verdict(&allow, "10.0.0.0/16"), ScopeVerdict::OutOfScope);
        let deny = scope(
            r#"
            [out_of_scope]
            hosts = ["10.0.0.7"]
            "#,
        );
        assert_eq!(block_verdict(&deny, "10.0.0.0/24"), ScopeVerdict::OutOfScope);
        assert_eq!(block_verdict(&deny, "10.0.1.0/24"), ScopeVerdict::Unknown);
    }

    #[test]
    fn two_allow_rules_cover_a_block_only_where_every_address_is_weighed() {
        let scope = scope(
            r#"
            [in_scope]
            cidrs = ["10.0.0.0/25", "10.0.0.128/25", "10.1.0.0/17", "10.1.128.0/17"]
            "#,
        );
        assert_eq!(block_verdict(&scope, "10.0.0.0/24"), ScopeVerdict::InScope);
        // The same split one block wider than the gate expands, so the halves
        // are not stitched together and the target is refused.
        assert_eq!(block_verdict(&scope, "10.1.0.0/16"), ScopeVerdict::OutOfScope);
    }

    #[test]
    fn a_block_is_weighed_against_a_rule_in_either_address_family() {
        let mapped = scope(
            r#"
            [out_of_scope]
            cidrs = ["::ffff:10.99.0.0/112"]
            "#,
        );
        assert_eq!(block_verdict(&mapped, "10.0.0.0/8"), ScopeVerdict::OutOfScope);
        let ipv4 = scope(
            r#"
            [out_of_scope]
            cidrs = ["10.99.0.0/16"]
            "#,
        );
        assert_eq!(
            block_verdict(&ipv4, "::ffff:10.99.0.0/112"),
            ScopeVerdict::OutOfScope
        );
        // An IPv6 block outside the mapped range names no IPv4 address.
        assert_eq!(block_verdict(&ipv4, "2001:db8::/32"), ScopeVerdict::Unknown);
    }

    #[test]
    fn a_single_host_target_is_unchanged_by_range_matching() {
        let scope = scope(
            r#"
            [in_scope]
            hosts = ["10.0.0.5"]
            cidrs = ["10.1.0.0/16"]
            "#,
        );
        // A one-address block carries no range a rule has to cover, so the host
        // readings judge it exactly as they did before.
        assert_eq!(block_verdict(&scope, "10.0.0.5/32"), ScopeVerdict::InScope);
        assert_eq!(block_verdict(&scope, "10.0.0.5"), ScopeVerdict::InScope);
        assert_eq!(block_verdict(&scope, "10.1.4.7"), ScopeVerdict::InScope);
        assert_eq!(block_verdict(&scope, "10.2.0.1"), ScopeVerdict::OutOfScope);
    }

    #[test]
    fn a_hostname_is_never_read_as_an_octet_range() {
        assert_eq!(octet_target_range("my-host.example.com"), None);
        assert_eq!(octet_target_range("10.0.0"), None);
        assert_eq!(octet_target_range("10.0.0.1-300"), None);
        assert_eq!(octet_target_range("10.0.0.9-1"), None);
        assert_eq!(octet_target_range("10..0.1"), None);
        // A spec naming one address carries no range, so the host readings
        // keep judging it.
        assert_eq!(candidate_range("10.0.0.1", TargetSyntax::AddressBlock), None);
        assert_eq!(candidate_range("api.example.com", TargetSyntax::AddressBlock), None);
        assert_eq!(candidate_range("https://api.example.com/path", TargetSyntax::AddressBlock), None);
    }

    #[test]
    fn an_open_ended_octet_covers_the_values_nmap_fills_in() {
        assert_eq!(octet_item_bounds("7"), Some((7, 7)));
        assert_eq!(octet_item_bounds("7-9"), Some((7, 9)));
        assert_eq!(octet_item_bounds("-"), Some((0, 255)));
        assert_eq!(octet_item_bounds("7-"), Some((7, 255)));
        assert_eq!(octet_item_bounds("-9"), Some((0, 9)));
        assert_eq!(octet_item_bounds("x"), None);
        assert_eq!(octet_bounds("9,1-3"), Some((1, 9)));
        assert_eq!(octet_bounds(""), None);
    }

    #[test]
    fn malformed_cidr_fails_to_load() {
        let err = ProgramScope::parse(
            r#"
            [in_scope]
            cidrs = ["not-a-cidr"]
            "#,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("invalid cidr"));
    }
}
