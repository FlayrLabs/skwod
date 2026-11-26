#!/usr/bin/env python3
"""Simulator check (build 51): the app lets go of its locks in the shared container when it is sent away.

A phone kills an app that is suspended while it holds a lock on a file in an app group container.
The simulator does not, but its processes are this Mac's, so the locks can be looked at from here:
`store.lock` with a non-blocking flock, the SQLite files with F_GETLK (which takes nothing).

    check-store-lock.py --udid UDID --bundle TEST.BUNDLE.ID --group TEST.GROUP.ID
    check-store-lock.py --selftest

Before: a TEST build (its own bundle and group ids, never the real ones) installed on a booted
simulator, signed in to a throwaway host that has since been stopped — so every dial is pending or
fails, which is the case that used to take the lock from behind.

1. in front: the lock must come to be HELD (else the rest would prove nothing);
2. launched, sent away after 3 s: at 15 s store.lock is free and no database lock is held, and no
   sample until 60 s finds one once SpringBoard has really put the app in the background (plus
   --grace) or suspended it. Those moments come from SpringBoard's own log, not from when the
   command to switch apps returned: on a loaded Mac the switch lands seconds later, and the app is
   still in front in between;
3. in front again: HELD again.
"""
import argparse, datetime, fcntl, glob, json, os, struct, subprocess, sys, tempfile, threading, time

REAL = {"com.skwod.app", "io.skwod.mac", "group.com.skwod.app"}
# struct flock on macOS: l_start, l_len, l_pid, l_type, l_whence
FLOCK = "qqihh"
PENDING, RANGE = 0x40000000, 512  # SQLite's lock bytes: pending, reserved, and 510 shared


def store_lock(directory):
    """'absent', 'free' or 'held'. Never creates the file; holds the lock for microseconds."""
    try:
        fd = os.open(os.path.join(directory, "store.lock"), os.O_RDWR)
    except FileNotFoundError:
        return "absent"
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(fd, fcntl.LOCK_UN)
        return "free"
    except BlockingIOError:
        return "held"
    finally:
        os.close(fd)


def database_locks(directory):
    """Which databases another process holds a lock on: [(file, pid, kind)]."""
    out = []
    for path in sorted(glob.glob(os.path.join(directory, "skwod-*.sqlite3"))):
        fd = os.open(path, os.O_RDWR)
        try:
            got = fcntl.fcntl(fd, fcntl.F_GETLK, struct.pack(FLOCK, PENDING, RANGE, 0, fcntl.F_WRLCK, os.SEEK_SET))
            start, _, pid, kind, _ = struct.unpack(FLOCK, got)
            if kind != fcntl.F_UNLCK:
                out.append((os.path.basename(path), pid, {fcntl.F_RDLCK: "shared", fcntl.F_WRLCK: "write"}.get(kind, kind)))
        finally:
            os.close(fd)
    return out


def springboard_event(line, pid=None):
    """('background' | 'suspended', unix time) from one ndjson line of SpringBoard's log, or None."""
    try:
        e = json.loads(line)
        msg = e["eventMessage"]
        when = datetime.datetime.strptime(e["timestamp"], "%Y-%m-%d %H:%M:%S.%f%z").timestamp()
    except (ValueError, KeyError, TypeError):
        return None
    if pid is not None and f":{pid}]" not in msg and f"pid: {pid};" not in msg:
        return None
    if "Setting process visibility to: Background" in msg:
        return ("background", when)
    if "taskState: Suspended" in msg:
        return ("suspended", when)
    return None


def judge(samples, background, suspended, grace):
    """Samples taken while the app was behind that found a lock: [(t, state, dbs)].
    `samples` are (unix time, store.lock state, database locks). Behind means from `background` +
    `grace`, or from `suspended` (the moment a phone would kill it), whichever comes first."""
    if background is None:
        raise ValueError("SpringBoard never put the app in the background: the check proves nothing")
    behind = min(background + grace, suspended if suspended is not None else float("inf"))
    return [(t, st, dbs) for t, st, dbs in samples if t >= behind and (st == "held" or dbs)]


def selftest():
    """The probes see what they are meant to see."""
    line = lambda ts, m: json.dumps({"timestamp": ts, "eventMessage": m})
    assert springboard_event(line("2026-11-25 23:17:46.750000-0500", "[app<x.app>:83828] Setting process visibility to: Background"), 83828) == ("background", 1795666666.75)
    assert springboard_event(line("2026-11-25 23:17:47.216000-0500", "state changed for x.app: <SBApplicationProcessState: 0x1; pid: 83828; taskState: Suspended"), 83828)[0] == "suspended"
    assert springboard_event(line("2026-11-25 23:17:46.750000-0500", "[app<x.app>:1] Setting process visibility to: Background"), 83828) is None
    assert springboard_event("not json") is None
    held = (10.0, "held", [])
    assert judge([held], 10.5, None, 1) == []          # still in front: the switch had not landed
    assert judge([held], 9.5, None, 1) == []           # inside the grace after background
    assert judge([held], 8.0, None, 1) == [held]       # behind, held: fail
    assert judge([held], 9.5, 9.8, 1) == [held]        # suspended before the grace ran out: fail
    assert judge([(10.0, "free", [("a", 1, "shared")])], 8.0, None, 1) != []
    try:
        judge([held], None, None, 1); raise AssertionError("no background must not pass")
    except ValueError:
        pass
    with tempfile.TemporaryDirectory() as d:
        assert store_lock(d) == "absent"
        lock, db = os.path.join(d, "store.lock"), os.path.join(d, "skwod-x.sqlite3")
        for p in (lock, db):
            open(p, "w").close()
        assert store_lock(d) == "free" and database_locks(d) == []
        child = subprocess.Popen([sys.executable, "-c", (
            "import fcntl,os,struct,sys\n"
            "a=os.open(sys.argv[1],os.O_RDWR); fcntl.flock(a,fcntl.LOCK_EX)\n"
            "b=os.open(sys.argv[2],os.O_RDWR); fcntl.fcntl(b,fcntl.F_SETLK,struct.pack('qqihh',0x40000001,1,0,fcntl.F_WRLCK,0))\n"
            "print('ok',flush=True); sys.stdin.read()"), lock, db], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        assert child.stdout.readline().strip() == b"ok"
        assert store_lock(d) == "held", store_lock(d)
        locks = database_locks(d)
        assert len(locks) == 1 and locks[0][1] == child.pid and locks[0][2] == "write", locks
        child.stdin.close(); child.wait()
        assert store_lock(d) == "free" and database_locks(d) == []
    print("selftest ok")


def simctl(*args, check=True):
    return subprocess.run(["xcrun", "simctl", *args], check=check, capture_output=True, text=True).stdout.strip()


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--udid"); p.add_argument("--bundle"); p.add_argument("--group")
    p.add_argument("--front-wait", type=float, default=25, help="seconds to wait for the lock in front")
    p.add_argument("--grace", type=float, default=1, help="seconds after SpringBoard backgrounds the app before a held lock fails")
    p.add_argument("--selftest", action="store_true")
    a = p.parse_args()
    if a.selftest:
        return selftest()
    if not (a.udid and a.bundle and a.group):
        p.error("--udid, --bundle and --group are needed")
    if REAL & {a.bundle, a.group}:
        p.error("not with the real bundle or group id: use a test build")
    selftest()
    directory = simctl("get_app_container", a.udid, a.bundle, a.group)
    if not os.path.isdir(directory):
        sys.exit(f"no group container: {directory!r}")

    def front():
        simctl("launch", a.udid, a.bundle)

    def away():
        simctl("launch", a.udid, "com.apple.Preferences")

    def wait_held(what):
        deadline = time.time() + a.front_wait
        while time.time() < deadline:
            if store_lock(directory) == "held":
                print(f"ok    {what}: store.lock is held")
                return
            time.sleep(0.25)
        sys.exit(f"FAIL  {what}: store.lock is {store_lock(directory)} — the check proves nothing (no account? no group container?)")

    simctl("terminate", a.udid, a.bundle, check=False)
    time.sleep(1)
    front()
    wait_held("control, in front")

    simctl("terminate", a.udid, a.bundle, check=False)
    time.sleep(2)
    if store_lock(directory) != "free":
        sys.exit("FAIL  the lock is held with the app not running: something else has it")
    events = {}
    def watch(stream, pid):
        for raw in stream:
            got = springboard_event(raw, pid)
            if got and got[1] >= left:
                events.setdefault(got[0], got[1])
    start = time.time()
    front()
    pid = simctl("spawn", a.udid, "launchctl", "list", check=False)
    pid = next((l.split()[0] for l in pid.splitlines() if f"UIKitApplication:{a.bundle}[" in l), None)
    if not (pid and pid.isdigit()):
        sys.exit("FAIL  could not find the app's pid in the simulator")
    log = subprocess.Popen(["xcrun", "simctl", "spawn", a.udid, "log", "stream", "--style", "ndjson",
                            "--predicate", f'process == "SpringBoard" AND eventMessage CONTAINS "{a.bundle}"'],
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    left = float("inf")
    threading.Thread(target=watch, args=(log.stdout, pid), daemon=True).start()
    time.sleep(max(0, 3 - (time.time() - start)))
    left = time.time()
    away()
    samples, reported = [], False
    while time.time() - start < 60:
        now, state, dbs = time.time(), store_lock(directory), database_locks(directory)
        samples.append((now, state, dbs))
        if now - start >= 15 and not reported:
            reported = True
            print(f"{'ok   ' if state != 'held' and not dbs else 'FAIL '} at 15 s (sent away at {left - start:.1f} s): store.lock {state}, database locks {dbs}")
        time.sleep(0.25)
    log.terminate()
    bg, sus = events.get("background"), events.get("suspended")
    rel = lambda t: f"{t - start:.2f} s" if t is not None else "never"
    print(f"info  pid {pid}; sent away {rel(left)}; SpringBoard: background {rel(bg)}, suspended {rel(sus)}; {len(samples)} samples")
    last_held = max((t for t, st, d in samples if st == "held" or d), default=None)
    first_free = next((t for t, st, d in samples if t > (last_held or 0) and st != "held" and not d), None)
    print(f"info  last sample with a lock {rel(last_held)}, first free after it {rel(first_free)}")
    try:
        bad = judge(samples, bg, sus, a.grace)
    except ValueError as e:
        sys.exit(f"FAIL  {e}")
    if bad:
        sys.exit(f"FAIL  held from behind in {len(bad)} samples, first {rel(bad[0][0])} {bad[0][1:]}, last {rel(bad[-1][0])} {bad[-1][1:]}")
    print("ok    nothing held from behind for 60 s")
    front()
    wait_held("control, in front again")


if __name__ == "__main__":
    main()
