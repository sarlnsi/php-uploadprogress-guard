"""Explicit deployment profiles; the module is additional mitigation only."""
import re

MODULE_VERSION = '3.1.0-fork2'
PROFILES = {'7.3': {'api': '20180731', 'release': None},
            '7.4': {'api': '20190902', 'release': 33}}


def source_files(branch):
    if branch not in PROFILES:
        raise ValueError('Unsupported PHP branch: ' + str(branch))
    return ['hp_uploadprogress_guard.c', 'config.m4', 'rfc1867/rfc1867_copy-' + branch + '.c']


def valid_php(info, branch):
    profile = PROFILES[branch]
    release = info.get('release')
    base = branch + '.' + str(release)
    return (type(release) is int and release >= 0 and
            [info.get('major'), info.get('minor')] == list(map(int, branch.split('.'))) and
            (profile['release'] is None or release == profile['release']) and
            info.get('zts') == 0 and info.get('debug') == 0 and info.get('word_bytes') in (4, 8) and
            bool(re.fullmatch(re.escape(base) + r'(?:[-+].*)?', info.get('version', ''))))


def matches_runtime(version, expected):
    # Match the full vendor version as well as the branch/patch release.
    return version == expected.get('version')
