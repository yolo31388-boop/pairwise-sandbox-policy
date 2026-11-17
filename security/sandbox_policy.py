"""Sandbox policy checks.

Each function is fail-closed: anything that cannot be positively verified as
safe is reported as unsafe.
"""

# Seccomp default actions that actually deny (or terminate) a syscall.  Only
# these count as "default deny"; SCMP_ACT_ALLOW and unknown actions do not.
_DENY_DEFAULT_ACTIONS = frozenset({
    'SCMP_ACT_ERRNO',
    'SCMP_ACT_KILL',
    'SCMP_ACT_KILL_PROCESS',
    'SCMP_ACT_KILL_THREAD',
    'SCMP_ACT_TRAP',
})


def seccomp_default(profile):
    """Return True when a seccomp profile's default action denies by default.

    A profile with a permissive (or missing) default action is not restrictive,
    no matter how many syscalls appear in its deny list: the default action is
    what applies to everything that was not explicitly listed.
    """
    if not isinstance(profile, dict):
        return False
    return profile.get('default') in _DENY_DEFAULT_ACTIONS


def _as_int(value):
    """Return *value* as an int, or None if it is not an exact integer."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    return None


def arg_filter_ok(rule, args):
    """Return True when a syscall argument filter matches the actual args.

    Comparisons use the full integer value.  Truncating to the low 32 bits is
    unsafe: 2**32 and 0 share their low 32 bits but are different arguments.
    """
    if not isinstance(rule, dict):
        return False
    # A single argument may be passed directly instead of a one-item sequence.
    if isinstance(args, int) and not isinstance(args, bool):
        args = [args]
    if not isinstance(args, (list, tuple)):
        return False

    index = rule.get('arg')
    if not isinstance(index, int) or isinstance(index, bool) or index < 0:
        return False
    if index >= len(args):
        return False

    expected = _as_int(rule.get('value'))
    actual = _as_int(args[index])
    if expected is None or actual is None:
        return False

    op = rule.get('op', 'eq')
    if op == 'eq':
        return actual == expected
    if op == 'ne':
        return actual != expected
    if op == 'lt':
        return actual < expected
    if op == 'le':
        return actual <= expected
    if op == 'gt':
        return actual > expected
    if op == 'ge':
        return actual >= expected
    if op == 'masked_eq':
        mask = _as_int(rule.get('mask'))
        if mask is None:
            return False
        return actual & mask == expected & mask
    # Unknown operator: cannot verify, so fail closed.
    return False


def _include_names(profile):
    """Return the include references of *profile* as a list of names."""
    includes = profile.get('include')
    if isinstance(includes, str):
        return [includes]
    if isinstance(includes, (list, tuple)):
        return list(includes)
    return []


def expand_includes(profile, profiles):
    """Return the transitive closure of the includes referenced by *profile*.

    Includes are followed recursively, and each referenced profile name is
    reported.  Cycles are handled by tracking visited names.
    """
    if not isinstance(profile, dict) or not isinstance(profiles, dict):
        return set()

    seen = set()
    pending = _include_names(profile)
    while pending:
        name = pending.pop()
        if not isinstance(name, str) or name in seen:
            continue
        seen.add(name)
        included = profiles.get(name)
        if isinstance(included, dict):
            pending.extend(_include_names(included))
        # A missing include is still reported: it was requested and cannot be
        # verified, so callers can reject it rather than silently ignore it.
    return seen


def capabilities_ok(granted, required):
    """Return True when every required capability is granted exactly.

    Capabilities are compared as an exact set: substring matching would let
    CAP_NET_RAW satisfy CAP_NET_RAW_ADMIN (and vice versa).
    """
    if not isinstance(granted, (set, frozenset, list, tuple)):
        return False
    if not isinstance(required, (set, frozenset, list, tuple)):
        return False
    return set(required) <= set(granted)


def no_new_privs_ok(profile):
    """Return True only if no_new_privs is enabled and privileges cannot grow.

    Subprocesses must not be able to regain privileges, so a profile that
    allows subprocess inheritance overrides a set no_new_privs flag.
    """
    if not isinstance(profile, dict):
        return False
    if profile.get('no_new_privs') is not True:
        return False
    if profile.get('allow_subprocess'):
        return False
    return True
