// Copyright 2026 The libkrun Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fmt::Write;
use std::str::from_utf8;

pub(crate) const XATTR_NAME_C: &[u8] = b"user.torkbot.sandbox.metadata\0";
pub(crate) const USER_XATTR_CARRIER_PREFIX: &[u8] = b"user.virtiofs.";
pub(crate) const MAX_HOST_XATTR_NAME_LEN: usize = 127;
pub(crate) const OVERFLOW_ID: u32 = 65_534;

const VFS_CAP_FLAGS_MASK: u32 = 0x0000_0001;
const VFS_CAP_REVISION_MASK: u32 = 0xff00_0000;
const VFS_CAP_REVISION_2: u32 = 0x0200_0000;
const VFS_CAP_REVISION_3: u32 = 0x0300_0000;
const VFS_CAP_REVISION_2_SIZE: usize = 20;
const VFS_CAP_REVISION_3_SIZE: usize = 24;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdentityMapping {
    pub host_uid: u32,
    pub host_gid: u32,
    pub guest_uid: u32,
    pub guest_gid: u32,
}

impl IdentityMapping {
    pub(crate) fn guest_uid_for(self, host_uid: u32) -> u32 {
        if host_uid == self.host_uid {
            self.guest_uid
        } else {
            OVERFLOW_ID
        }
    }

    pub(crate) fn guest_gid_for(self, host_gid: u32) -> u32 {
        if host_gid == self.host_gid {
            self.guest_gid
        } else {
            OVERFLOW_ID
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GuestMetadata {
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub capability: Option<Vec<u8>>,
}

impl GuestMetadata {
    pub(crate) fn from_native(
        mapping: IdentityMapping,
        host_uid: u32,
        host_gid: u32,
        host_mode: u32,
    ) -> Self {
        Self {
            uid: mapping.guest_uid_for(host_uid),
            gid: mapping.guest_gid_for(host_gid),
            mode: host_mode,
            capability: None,
        }
    }

    pub(crate) fn parse(value: &[u8]) -> Result<Self, ParseError> {
        let mut fields = value.split(|byte| *byte == b':');
        let uid = parse_canonical_u32(fields.next().ok_or(ParseError)?, 10)?;
        let gid = parse_canonical_u32(fields.next().ok_or(ParseError)?, 10)?;
        let mode = parse_canonical_mode(fields.next().ok_or(ParseError)?)?;
        let capability = parse_capability(fields.next().ok_or(ParseError)?)?;
        if fields.next().is_some() || uid == u32::MAX || gid == u32::MAX {
            return Err(ParseError);
        }
        Ok(Self {
            uid,
            gid,
            mode,
            capability,
        })
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        let capability = match &self.capability {
            Some(capability) => encode_hex(capability),
            None => "-".to_owned(),
        };
        format!("{}:{}:0{:o}:{capability}", self.uid, self.gid, self.mode).into_bytes()
    }

    pub(crate) fn matches_file_kind(&self, host_mode: u32) -> bool {
        self.mode & libc::S_IFMT as u32 == host_mode & libc::S_IFMT as u32
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ParseError;

pub(crate) fn user_xattr_host_name(guest_name: &[u8]) -> Result<Vec<u8>, NameError> {
    if !guest_name.starts_with(b"user.") {
        return Err(NameError::UnsupportedNamespace);
    }
    let len = USER_XATTR_CARRIER_PREFIX.len() + guest_name.len();
    if len > MAX_HOST_XATTR_NAME_LEN {
        return Err(NameError::TooLong);
    }
    let mut name = Vec::with_capacity(len + 1);
    name.extend_from_slice(USER_XATTR_CARRIER_PREFIX);
    name.extend_from_slice(guest_name);
    name.push(0);
    Ok(name)
}

pub(crate) fn guest_name_from_carrier(host_name: &[u8]) -> Option<&[u8]> {
    host_name.strip_prefix(USER_XATTR_CARRIER_PREFIX)
}

pub(crate) fn validate_capability(value: &[u8]) -> bool {
    if value.len() != VFS_CAP_REVISION_2_SIZE && value.len() != VFS_CAP_REVISION_3_SIZE {
        return false;
    }
    let magic = u32::from_le_bytes(value[..4].try_into().expect("four-byte capability header"));
    if magic & !(VFS_CAP_REVISION_MASK | VFS_CAP_FLAGS_MASK) != 0 {
        return false;
    }
    match magic & VFS_CAP_REVISION_MASK {
        VFS_CAP_REVISION_2 => value.len() == VFS_CAP_REVISION_2_SIZE,
        VFS_CAP_REVISION_3 => value.len() == VFS_CAP_REVISION_3_SIZE,
        _ => false,
    }
}

fn parse_canonical_u32(value: &[u8], radix: u32) -> Result<u32, ParseError> {
    let value = from_utf8(value).map_err(|_| ParseError)?;
    let parsed = u32::from_str_radix(value, radix).map_err(|_| ParseError)?;
    let canonical = match radix {
        8 => format!("{parsed:o}"),
        10 => parsed.to_string(),
        _ => unreachable!(),
    };
    if value != canonical {
        return Err(ParseError);
    }
    Ok(parsed)
}

fn parse_canonical_mode(value: &[u8]) -> Result<u32, ParseError> {
    let value = from_utf8(value).map_err(|_| ParseError)?;
    let digits = value.strip_prefix('0').ok_or(ParseError)?;
    let mode = parse_canonical_u32(digits.as_bytes(), 8)?;
    let kind = mode & libc::S_IFMT as u32;
    if kind != libc::S_IFREG as u32 && kind != libc::S_IFDIR as u32 && kind != libc::S_IFLNK as u32
    {
        return Err(ParseError);
    }
    if mode & !(libc::S_IFMT as u32 | 0o7777) != 0 {
        return Err(ParseError);
    }
    Ok(mode)
}

fn parse_capability(value: &[u8]) -> Result<Option<Vec<u8>>, ParseError> {
    if value == b"-" {
        return Ok(None);
    }
    if value.is_empty() || !value.len().is_multiple_of(2) {
        return Err(ParseError);
    }
    let mut decoded = Vec::with_capacity(value.len() / 2);
    for pair in value.chunks_exact(2) {
        if !pair
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
        {
            return Err(ParseError);
        }
        let pair = from_utf8(pair).map_err(|_| ParseError)?;
        decoded.push(u8::from_str_radix(pair, 16).map_err(|_| ParseError)?);
    }
    if !validate_capability(&decoded) {
        return Err(ParseError);
    }
    Ok(Some(decoded))
}

fn encode_hex(value: &[u8]) -> String {
    let mut encoded = String::with_capacity(value.len() * 2);
    for byte in value {
        write!(encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NameError {
    UnsupportedNamespace,
    TooLong,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v2_capability() -> Vec<u8> {
        let mut value = vec![0; VFS_CAP_REVISION_2_SIZE];
        value[..4].copy_from_slice(&(VFS_CAP_REVISION_2 | 1).to_le_bytes());
        value
    }

    #[test]
    fn identity_components_map_independently() {
        let mapping = IdentityMapping {
            host_uid: 502,
            host_gid: 20,
            guest_uid: 0,
            guest_gid: 0,
        };
        assert_eq!(mapping.guest_uid_for(502), 0);
        assert_eq!(mapping.guest_gid_for(80), OVERFLOW_ID);
        assert_eq!(mapping.guest_uid_for(501), OVERFLOW_ID);
        assert_eq!(mapping.guest_gid_for(20), 0);
    }

    #[test]
    fn complete_metadata_round_trips_canonically() {
        let metadata = GuestMetadata {
            uid: 123,
            gid: 456,
            mode: libc::S_IFREG as u32 | 0o751,
            capability: Some(v2_capability()),
        };
        assert_eq!(GuestMetadata::parse(&metadata.encode()), Ok(metadata));
    }

    #[test]
    fn malformed_or_partial_metadata_is_rejected() {
        for value in [
            &b"0:0:0100644"[..],
            &b"00:0:0100644:-"[..],
            &b"0:0:100644:-"[..],
            &b"0:0:0010644:-"[..],
            &b"0:0:020100644:-"[..],
            &b"0:0:0100644:ABCDEF"[..],
            &b"0:0:0100644:00"[..],
        ] {
            assert_eq!(GuestMetadata::parse(value), Err(ParseError), "{value:?}");
        }
        assert!(GuestMetadata::parse(b"4294967294:4294967294:0100644:-").is_ok());
        assert_eq!(
            GuestMetadata::parse(b"4294967295:0:0100644:-"),
            Err(ParseError)
        );
    }

    #[test]
    fn carrier_names_follow_the_virtiofs_prefix_convention() {
        assert_eq!(
            user_xattr_host_name(b"user.comment").unwrap(),
            b"user.virtiofs.user.comment\0"
        );
        assert_eq!(
            guest_name_from_carrier(b"user.virtiofs.user.comment"),
            Some(&b"user.comment"[..])
        );
    }

    #[test]
    fn carrier_names_enforce_the_macos_limit() {
        let longest = [b'x'; MAX_HOST_XATTR_NAME_LEN - USER_XATTR_CARRIER_PREFIX.len()];
        let mut guest = b"user.".to_vec();
        guest.extend_from_slice(&longest[guest.len()..]);
        assert!(user_xattr_host_name(&guest).is_ok());
        guest.push(b'x');
        assert_eq!(user_xattr_host_name(&guest), Err(NameError::TooLong));
    }

    #[test]
    fn capability_validation_accepts_only_linux_v2_and_v3_layouts() {
        assert!(validate_capability(&v2_capability()));
        let mut v3 = vec![0; VFS_CAP_REVISION_3_SIZE];
        v3[..4].copy_from_slice(&VFS_CAP_REVISION_3.to_le_bytes());
        assert!(validate_capability(&v3));
        v3[0] = 2;
        assert!(!validate_capability(&v3));
        assert!(!validate_capability(&[0; VFS_CAP_REVISION_2_SIZE]));
    }
}
