#!/usr/bin/env python3

import collections
import itertools
import os
import re
import stat
import subprocess
import sys
import typing

from typing import Callable, Dict, Iterator, Iterable, List, Set, Tuple

Pid = typing.NewType('Pid', int)
Path = typing.NewType('Path', str)
UnitName = typing.NewType('UnitName', str)

MAP_REGEX = re.compile(r'^[\da-f]+-[\da-f]+ [r-][w-][x-][sp-] '
                       r'[\da-f]+ [\da-f]{2}:[\da-f]{2} '
                       r'(\d+) *(.+)( \(deleted\))?\n$')

PS_REGEX = re.compile('^ *(\d+) (.*)')

USER_ID_SERVICE = re.compile('user@\d+\.service')

def warn(msg: str):
    sys.stderr.write('warning: {}\n'.format(msg))


def is_magic(path: Path) -> bool:
    return (path.startswith('[')
            or path.startswith('/[')
            or path.startswith('/anon_hugepage')
            or path.startswith('/dev/')
            or path.startswith('/drm')
            or path.startswith('/memfd')
            or path.startswith('/proc/')
            or path.startswith('/SYSV'))


def is_tmp(path: Path) -> bool:
    return (path.startswith('/dev/shm/')
            or path.startswith('/tmp')
            or path.startswith('/run')
            or path.startswith('/var/run'))


def is_catchall_unit(name: UnitName) -> bool:
    return (not name
            or name.endswith('.scope')
            or USER_ID_SERVICE.match(name))


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


def main():
    tracker = Tracker()
    path_pids = pids_using_files(tracker, lambda path: not is_magic(path) and not is_tmp(path))
    pid_paths = collections.defaultdict(set)  # type: Dict[Pid, Set[Path]]
    for (path, pids) in path_pids.items():
        for pid in pids:
            pid_paths[pid].add(path)

    all_pids = pid_paths.keys()
    pid_units = unit_names_for(all_pids)
    pid_exes = exe_paths_for(all_pids)

    unit_paths = collections.defaultdict(set)  # type: Dict[UnitName, Set[Path]]
    by_exe = collections.defaultdict(set)  # type: Dict[Path, Set[Pid]]
    for (pid, paths) in pid_paths.items():
        unit = pid_units.get(pid)
        if not is_catchall_unit(unit):
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
            print('   - pid{}: {}'.format('s' if 1 != len(pids) else '', ' '.join(pids)))
            for path in sorted(paths):
                print('   - ' + path)

if '__main__' == __name__:
    main()
