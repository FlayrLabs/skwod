//! Permission bitmask — ported verbatim from the original `packages/shared/src/permissions.ts`
//! (ADR-010: exact bit values carried over). The server enforces these on METADATA operations
//! only; content is ciphertext it can't read either way.

#![allow(dead_code)] // the full permission surface lands with the message relay + voice phases

pub const MANAGE_CHANNELS: i64 = 1;
pub const MANAGE_ROLES: i64 = 2;
pub const MANAGE_SERVER: i64 = 4;
pub const KICK_MEMBERS: i64 = 8;
pub const BAN_MEMBERS: i64 = 16;
pub const MANAGE_MESSAGES: i64 = 32;
pub const SEND_MESSAGES: i64 = 64;
pub const READ_MESSAGES: i64 = 128;
pub const ATTACH_FILES: i64 = 256;
pub const ADD_REACTIONS: i64 = 512;
pub const MANAGE_INVITES: i64 = 1024;
pub const CONNECT_VOICE: i64 = 2048;
pub const SPEAK_VOICE: i64 = 4096;
pub const ADMINISTRATOR: i64 = 8192;
pub const MENTION_EVERYONE: i64 = 16384;

/// Default permissions for the @everyone role.
pub const DEFAULT_PERMISSIONS: i64 =
    SEND_MESSAGES | READ_MESSAGES | ATTACH_FILES | ADD_REACTIONS | CONNECT_VOICE | SPEAK_VOICE;

pub const ALL_PERMISSIONS: i64 = MANAGE_CHANNELS
    | MANAGE_ROLES
    | MANAGE_SERVER
    | KICK_MEMBERS
    | BAN_MEMBERS
    | MANAGE_MESSAGES
    | SEND_MESSAGES
    | READ_MESSAGES
    | ATTACH_FILES
    | ADD_REACTIONS
    | MANAGE_INVITES
    | CONNECT_VOICE
    | SPEAK_VOICE
    | ADMINISTRATOR
    | MENTION_EVERYONE;

/// Administrator implies everything.
pub fn has_permission(permissions: i64, permission: i64) -> bool {
    if permissions & ADMINISTRATOR == ADMINISTRATOR {
        return true;
    }
    permissions & permission == permission
}

pub struct Override {
    pub allow: i64,
    pub deny: i64,
}

/// Effective permissions: owner → all; OR of role masks; administrator bypasses channel
/// overrides; otherwise overrides apply in order (deny stripped, then allow added) —
/// identical to the original `computePermissions`.
pub fn compute_permissions(is_owner: bool, role_permissions: &[i64], channel_overrides: &[Override]) -> i64 {
    if is_owner {
        return ALL_PERMISSIONS;
    }
    let mut permissions = role_permissions.iter().fold(0, |acc, p| acc | p);
    if permissions & ADMINISTRATOR == ADMINISTRATOR {
        return ALL_PERMISSIONS;
    }
    for o in channel_overrides {
        permissions &= !o.deny;
        permissions |= o.allow;
    }
    permissions
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bit_values_match_original_spec() {
        // packages/shared/src/permissions.ts, verbatim.
        assert_eq!(MANAGE_CHANNELS, 1);
        assert_eq!(ADMINISTRATOR, 8192);
        assert_eq!(MENTION_EVERYONE, 16384);
        assert_eq!(ALL_PERMISSIONS, 32767); // 15 contiguous bits
        assert_eq!(DEFAULT_PERMISSIONS, 64 | 128 | 256 | 512 | 2048 | 4096);
    }

    #[test]
    fn administrator_grants_all() {
        assert!(has_permission(ADMINISTRATOR, BAN_MEMBERS));
        assert!(!has_permission(DEFAULT_PERMISSIONS, BAN_MEMBERS));
    }

    #[test]
    fn owner_and_admin_bypass_overrides() {
        let deny_all = [Override { allow: 0, deny: ALL_PERMISSIONS }];
        assert_eq!(compute_permissions(true, &[], &deny_all), ALL_PERMISSIONS);
        assert_eq!(compute_permissions(false, &[ADMINISTRATOR], &deny_all), ALL_PERMISSIONS);
    }

    #[test]
    fn overrides_deny_then_allow_in_order() {
        let overrides = [
            Override { allow: 0, deny: SEND_MESSAGES },
            Override { allow: SEND_MESSAGES, deny: 0 },
        ];
        let p = compute_permissions(false, &[DEFAULT_PERMISSIONS], &overrides);
        assert!(has_permission(p, SEND_MESSAGES), "later allow wins over earlier deny");

        let p = compute_permissions(false, &[DEFAULT_PERMISSIONS], &[Override { allow: 0, deny: READ_MESSAGES }]);
        assert!(!has_permission(p, READ_MESSAGES));
    }
}
