use std::collections::HashMap;
use std::sync::OnceLock;

const OUI_REGISTRY: &str = include_str!("../assets/oui.tsv");
static REGISTRY: OnceLock<HashMap<(u8, u64), &'static str>> = OnceLock::new();

fn registry() -> &'static HashMap<(u8, u64), &'static str> {
    REGISTRY.get_or_init(|| {
        OUI_REGISTRY
            .lines()
            .filter(|line| !line.starts_with('#'))
            .filter_map(|line| {
                let mut fields = line.splitn(3, '\t');
                let bits = fields.next()?.parse::<u8>().ok()?;
                let prefix = u64::from_str_radix(fields.next()?, 16).ok()?;
                let vendor = fields.next()?.trim();
                (!vendor.is_empty()).then_some(((bits, prefix), vendor))
            })
            .collect()
    })
}

pub fn normalize_mac(bytes: [u8; 6]) -> Option<String> {
    if bytes == [0; 6] || bytes == [0xff; 6] || bytes[0] & 1 != 0 {
        return None;
    }
    Some(bytes.iter().map(|value| format!("{value:02X}")).collect::<Vec<_>>().join(":"))
}

pub fn lookup(mac: &str) -> Option<&'static str> {
    let compact = mac.chars().filter(|character| character.is_ascii_hexdigit()).collect::<String>();
    if compact.len() != 12 {
        return None;
    }
    let value = u64::from_str_radix(&compact, 16).ok()?;
    let first_octet = (value >> 40) as u8;
    if first_octet & 0x02 != 0 {
        return None;
    }
    for bits in [36_u8, 28, 24] {
        let prefix = value >> (48 - bits);
        if let Some(vendor) = registry().get(&(bits, prefix)) {
            return Some(*vendor);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_only_unicast_mac_addresses() {
        assert_eq!(normalize_mac([0x00, 0x1b, 0x44, 0x11, 0x3a, 0xb7]).as_deref(), Some("00:1B:44:11:3A:B7"));
        assert_eq!(normalize_mac([0xff; 6]), None);
        assert_eq!(normalize_mac([0x01, 0, 0, 0, 0, 1]), None);
    }

    #[test]
    fn locally_administered_addresses_do_not_claim_a_vendor() {
        assert_eq!(lookup("02:00:00:00:00:01"), None);
    }

    #[test]
    fn resolves_ieee_vendor_by_longest_registered_prefix() {
        assert_eq!(lookup("00:1B:44:11:3A:B7"), Some("SanDisk Corporation"));
    }
}
