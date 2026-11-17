import pytest

from security.sandbox_policy import (
    seccomp_default,
    arg_filter_ok,
    expand_includes,
    capabilities_ok,
    no_new_privs_ok
)


def test_default_deny():
    assert seccomp_default({'default': 'SCMP_ACT_ERRNO'}) is True

def test_default_allow():
    assert seccomp_default({'default': 'SCMP_ACT_ALLOW'}) is False

def test_deny_syscall():
    assert seccomp_default({'default': 'SCMP_ACT_ALLOW', 'deny': ['execve']}) is False

def test_arg_full():
    assert arg_filter_ok({'arg': 0, 'op': 'eq', 'value': 4294967296}, [0]) is False

def test_arg_match():
    assert arg_filter_ok({'arg': 0, 'op': 'eq', 'value': 5}, [5]) is True

def test_include_recursive():
    assert expand_includes({'include': ['a']}, {'a': {'include': ['b']}, 'b': {'rules': ['x']}}) == {'a', 'b'}

def test_include_cycle():
    assert expand_includes({'include': ['a']}, {'a': {'include': ['b']}, 'b': {'include': ['a']}}) == {'a', 'b'}

def test_caps_exact():
    assert capabilities_ok({'CAP_NET_BIND_SERVICE'}, {'CAP_NET_BIND_SERVICE'}) is True

def test_caps_prefix():
    assert capabilities_ok({'CAP_NET_RAW'}, {'CAP_NET_RAW_ADMIN'}) is False

def test_nnp_true():
    assert no_new_privs_ok({'no_new_privs': True}) is True

def test_nnp_false():
    assert no_new_privs_ok({'no_new_privs': False}) is False

def test_empty_profile():
    assert seccomp_default({}) is False

def test_inherit():
    assert no_new_privs_ok({'no_new_privs': True, 'allow_subprocess': True}) is False

def test_unknown_cap():
    assert capabilities_ok({'CAP_UNKNOWN'}, {'CAP_UNKNOWN'}) is True

def test_apparmor():
    assert expand_includes({'include': ['base']}, {'base': {'rules': []}}) == {'base'}
