#!/usr/bin/env python3

import collections
import itertools
import os
import pwd
import re
import stat
import subprocess
import sys
import typing
from typing import Any, Callable, Dict, Iterator, Iterable, List, Set, Tuple, Union

import yaml

Pid = typing.NewType('Pid', int)
Path = typing.NewType('Path', str)
UnitName = typing.NewType('UnitName', str)

MAP_REGEX = re.compile(r'^[\da-f]+-[\da-f]+ [r-][w-][x-][sp-] '
                       r'[\da-f]+ [\da-f]{2}:[\da-f]{2} '
                       r'(\d+) *(.+)( \(deleted\))?\n$')

PS_REGEX = re.compile('^ *(\d+) (.*)')


def warn(msg: str):
    sys.stderr.write('warning: {}\n'.format(msg))


def split_every(n, iterable):
    """
    https://stackoverflow.com/questions/1915170/split-a-generator-iterable-every-n-items-in-python-splitevery
    """
    it = iter(iterable)
    piece = list(itertools.islice(it, n))
    while piece:
        yield piece
        piece = list(itertools.islice(it, n))


def unit_names_for(pids: Iterable[Pid]) -> Dict[Pid, UnitName]:
    output = dict()  # type: Dict[Pid, UnitName]
    max_pids_per_call = 4096 // 8 - 32

    for chunk in split_every(max_pids_per_call, pids):
        args = ['ps', '-opid=,unit=']
        args.extend(str(pid) for pid in chunk)
        for line in subprocess.check_output(args).decode('utf-8').split('\n'):
            ma = PS_REGEX.match(line)
            if not ma:
                continue

            unit = UnitName(ma.group(2))
            if '-' == unit:
                continue

            output[Pid(ma.group(1))] = unit

    return output


def exe_paths_for(pids: Iterable[Pid]) -> Dict[Pid, Path]:
    output = dict()  # type: Dict[Pid, Path]
    for pid in pids:
        try:
            output[pid] = os.readlink('/proc/{}/exe'.format(pid))
        except OSError as e:
            warn('unable to find path of {}: {}'.format(pid, e))

    return output


class Tracker:
    def __init__(self):
        self.permission_errors = 0  # type: int


def load_maps(tracker: Tracker) -> Iterator[Tuple[Pid, List[str]]]:
    # scandir is not closeable in 3.5
    for entry in os.scandir('/proc'):
        if not entry.is_dir() or not entry.name.isdigit():
            continue
        try:
            with open('/proc/{}/maps'.format(entry.name)) as f:
                yield (Pid(entry.name), f.readlines())
        except IOError as e:
            if e is PermissionError:
                tracker.permission_errors += 1
            warn("reading details of pid {}: {}".format(entry.name, e))


def pids_using_files(tracker: Tracker, pre_filter: Callable[[Path], bool]) -> Dict[Path, Set[Pid]]:
    users = collections.defaultdict(set)  # type: Dict[Path, Set[Pid]]
    for (pid, lines) in load_maps(tracker):
        for line in lines:
            ma = MAP_REGEX.match(line)
            if not ma:
                warn('parse error for /proc/{}/maps: {}'.format(pid, repr(line)))

            inode = int(ma.group(1))
            if 0 == inode:
                continue

            path = ma.group(2)
            if path.endswith(' (deleted)'):
                path = path[0:-10]

            if not pre_filter(path):
                continue

            try:
                if os.stat(path)[stat.ST_INO] != inode:
                    users[path].add(pid)
            except FileNotFoundError:
                users[path].add(pid)
            except IOError as e:
                if e is PermissionError:
                    tracker.permission_errors += 1
                warn("failed to stat {} for {}: {}".format(path, pid, e))

    return users


def user_of(pid: Pid) -> str:
    uid = os.stat('/proc/{}'.format(pid))[stat.ST_UID]
    try:
        return '{} [{}]'.format(pwd.getpwuid(uid).pw_name, uid)
    except KeyError:
        return '??? [{}]'.format(uid)


def matcher(spec: Dict[str, Iterable[str]]) -> Callable[[str], bool]:
    prefixes = set(spec.pop('by_prefix', []))
    fulls = set(spec.pop('by_full', []))
    uncompiled_regexes = set(spec.pop('by_regex', []))

    if spec:
        raise Exception('unrecognised matcher keys: {}'.format(spec.keys()))

    regexes = [re.compile(item) for item in uncompiled_regexes]

    def match(what: str) -> bool:
        if not what:
            return False

        for prefix in prefixes:
            if what.startswith(prefix):
                return True

        for full in fulls:
            if what == full:
                return True

        for regex in regexes:
            if regex.fullmatch(what):
                return True

        return False

    return match


def parse_group_services(specs: List[Dict[str, Union[dict, str]]]) -> Callable[[str], str]:
    groups = []  # type: List[Tuple[Callable[[str], bool], str]]
    for spec in specs:
        name = spec.pop('group')
        ma = matcher(spec)
        groups.append((ma, name))

    def match(what: str) -> str:
        for group in groups:
            if group[0](what):
                return group[1]
        return 'other'

    return match


def main():
    with open('deleted.yml') as f:
        spec = yaml.safe_load(f)  # type: Dict[str, Any]
    ignore_paths = matcher(spec.pop('ignore_paths'))
    catchall_units = matcher(spec.pop('catchall_units'))
    group_services = parse_group_services(spec.pop('group_services'))

    if spec:
        print('unrecognised spec keys: {}'.format(sorted(spec.keys())))
        sys.exit(2)

    tracker = Tracker()
    path_pids = pids_using_files(tracker, lambda path: not ignore_paths(path))
    pid_paths = collections.defaultdict(set)  # type: Dict[Pid, Set[Path]]
    for (path, pids) in path_pids.items():
        for pid in pids:
            pid_paths[pid].add(path)

    all_pids = pid_paths.keys()
    pid_units = unit_names_for(all_pids)
    groups = collections.defaultdict(set)  # type: Dict[str, Set[UnitName]]
    non_units = False
    for unit in set(pid_units.values()):
        if catchall_units(unit):
            non_units = True
            continue
        groups[group_services(unit)].add(unit)

    for group, services in sorted(groups.items()):
        print(' * ' + group)
        print('   - sudo systemctl restart ' + ' '.join(sorted(services)))

    if not groups:
        print('No units need restarting.')

    if non_units:
        print('Some pids not associated with units need restarting.')

    pid_exes = exe_paths_for(all_pids)

    unit_paths = collections.defaultdict(set)  # type: Dict[UnitName, Set[Path]]
    by_exe = collections.defaultdict(set)  # type: Dict[Path, Set[Pid]]
    for (pid, paths) in pid_paths.items():
        unit = pid_units.get(pid)
        if unit and not catchall_units(unit):
            unit_paths[unit].update(paths)
            continue
        exe = pid_exes.get(pid)
        if not exe:
            warn('no unit and no exe for {}'.format(pid))
            continue
        by_exe[exe].add(pid)

    if unit_paths:
        print('These units need restarting:')
        for unit, paths in sorted(unit_paths.items()):
            print(' * ' + unit)
            for path in sorted(paths):
                print('   - ' + path)

    if by_exe:
        print('These executables have processes running outside of useful units:')
        for exe, pids in sorted(by_exe.items()):
            print(' * ' + exe)
            paths = set()
            for pid in pids:
                paths.update(pid_paths[pid])
            print('   - pids:')
            for pid in sorted(pids):
                print('     - {} ({})'.format(pid, user_of(pid)))

            print('   - paths:')
            for path in sorted(paths):
                print('     - ' + path)


if '__main__' == __name__:
    main()
