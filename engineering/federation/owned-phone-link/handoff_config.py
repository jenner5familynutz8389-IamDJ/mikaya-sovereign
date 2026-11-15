"""Read the owner's private identity configuration; never discover or default identities."""
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import uuid


class ConfigError(ValueError):
    pass


def _require(ok, why):
    if not ok:
        raise ConfigError(why)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result, 'Duplicate private configuration field')
        result[key] = value
    return result


def load_config():
    """Load a single owned, private, bounded, non-symlink configuration file."""
    directory = Path.home() / '.config/mikaya-owned-link-v1'
    path = directory / 'identity.json'
    for component in (path, *path.parents):
        _require(not component.is_symlink(), 'Symlink private configuration path refused')
    try:
        dfd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as error:
        raise ConfigError('Private identity configuration directory is unavailable') from error
    try:
        dst = os.fstat(dfd)
        _require(stat.S_ISDIR(dst.st_mode) and dst.st_uid == os.getuid()
                 and dst.st_mode & 0o077 == 0,
                 'Private identity configuration directory must be owned and mode 0700')
        try:
            fd = os.open('identity.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                         dir_fd=dfd)
        except OSError as error:
            raise ConfigError('Private identity configuration file is unavailable') from error
        with os.fdopen(fd, 'rb') as stream:
            before = os.fstat(stream.fileno())
            _require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
                     and before.st_mode & 0o077 == 0 and before.st_nlink == 1
                     and 0 < before.st_size <= 4096,
                     'Private identity configuration must be an owned private single-link file')
            raw = stream.read(4097)
            after = os.fstat(stream.fileno())
            fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_nlink',
                      'st_size', 'st_mtime_ns')
            _require(len(raw) == before.st_size and len(raw) <= 4096
                     and all(getattr(before, key) == getattr(after, key) for key in fields),
                     'Private identity configuration changed during read')
    finally:
        os.close(dfd)
    try:
        config = json.loads(raw.decode('utf-8'), object_pairs_hook=_unique_object)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ConfigError('Private identity configuration must be valid UTF-8 JSON') from error
    expected = {'schema', 'sender_node_id', 'controller_node_id',
                'target_usb_serial', 'ssh_source_address'}
    _require(type(config) is dict and set(config) == expected,
             'Exact private identity configuration fields required')
    _require(config['schema'] == 'mikaya.owned-phone-private-config.v1',
             'Unknown private identity configuration schema')
    for key in expected - {'schema'}:
        value = config[key]
        _require(type(value) is str and 0 < len(value) <= 128 and value == value.strip()
                 and not value.startswith(('REPLACE_', '<')),
                 'Missing, placeholder or malformed private identity value')
    for key in ('sender_node_id', 'controller_node_id'):
        try:
            value = uuid.UUID(config[key])
        except ValueError as error:
            raise ConfigError('Private node identity must be a canonical UUID') from error
        _require(value.int != 0 and str(value) == config[key],
                 'Private node identity must be a nonzero canonical UUID')
    _require(config['sender_node_id'] != config['controller_node_id'],
             'F110 and Motorola node identities must differ')
    _require(re.fullmatch(r'[A-Za-z0-9._:-]{1,128}', config['target_usb_serial']) is not None,
             'One exact USB serial is required; wildcards and shell text are refused')
    try:
        source = ipaddress.IPv4Address(config['ssh_source_address'])
    except ipaddress.AddressValueError as error:
        raise ConfigError('One canonical SSH source IPv4 address is required') from error
    _require(str(source) == config['ssh_source_address'] and not source.is_unspecified
             and not source.is_multicast and not source.is_loopback
             and source != ipaddress.IPv4Address('255.255.255.255'),
             'Wildcard, multicast, loopback or broadcast SSH sources are refused')
    return config
