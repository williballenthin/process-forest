import logging
import datetime
from collections import namedtuple

import pytz
import json
import iso8601
from lxml import etree
from lxml.etree import XMLSyntaxError

from Evtx.Evtx import Evtx
from Evtx.Views import evtx_file_xml_view


g_logger = logging.getLogger("process-forest.global")


def to_lxml(record_xml):
    """
    @type record: Record
    """
    return etree.fromstring("<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\" ?>%s" %
            record_xml.replace("xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"", ""))


class Process(object):
    NOTE_FAKE_PARENT = "Fake Parent: This is a faked process created since a ppid didn't exist"
    NOTE_END_LOST = "Lost End Timestamp: This end timestamp is suspect, because it collided with another process"
    def __init__(self, pid, ppid, path, user, domain, logonid, computer):
        super(Process, self).__init__()
        self.pid = pid
        self.ppid = ppid
        self.path = path
        self.user = user
        self.domain = domain
        self.logonid = logonid
        self.computer = computer
        self.begin = datetime.datetime.min
        self.end = datetime.datetime.min
        self.parent = None
        self.children = []
        self.notes = None
        self.id = None  # set by analyzer, unique with analyzer session

    def __str__(self):
        return "Process(%s, pid=%x, ppid=%x, begin=%s, end=%s" % (
                self.path, self.pid, self.ppid,
                self.begin.isoformat(), self.end.isoformat())

    # TODO: move serialize, deserialize here


def create_fake_parent_process(pid):
    p = Process(pid, 0, "UNKNOWN", "UNKNOWN", "UNKNOWN", "UNKNOWN", "UNKNOWN")
    p.notes = Process.NOTE_FAKE_PARENT
    return p


class NotAProcessEventError(Exception):
    pass


class Entry(object):
    def __init__(self, xml, record):
        super(Entry, self).__init__()
        self._xml = xml
        self._record = record
        self._node = to_lxml(self._xml)
        self._logger = logging.getLogger("process-forest.Entry")

    def get_xpath(self, path):
        return self._node.xpath(path)[0]

    def get_eid(self):
        return int(self.get_xpath("/Event/System/EventID").text)

    def get_timestamp(self):
        return self._record.timestamp()

    def is_process_created_event(self):
        return self.get_eid() == 4688

    def is_process_exited_event(self):
        return self.get_eid() == 4689

    def get_process_from_4688_event(self):
        path = self.get_xpath("/Event/EventData/Data[@Name='NewProcessName']").text
        pid = int(self.get_xpath("/Event/EventData/Data[@Name='NewProcessId']").text, 0x10)
        ppid = int(self.get_xpath("/Event/EventData/Data[@Name='ProcessId']").text, 0x10)
        user = self.get_xpath("/Event/EventData/Data[@Name='SubjectUserName']").text
        domain = self.get_xpath("/Event/EventData/Data[@Name='SubjectDomainName']").text
        logonid = self.get_xpath("/Event/EventData/Data[@Name='SubjectLogonId']").text
        computer = self.get_xpath("/Event/System/Computer").text
        p = Process(pid, ppid, path, user, domain, logonid, computer)
        p.begin = self._record.timestamp()
        return p

    def get_process_from_4689_event(self):
        path = self.get_xpath("/Event/EventData/Data[@Name='ProcessName']").text
        pid = int(self.get_xpath("/Event/EventData/Data[@Name='ProcessId']").text, 0x10)
        ppid = int(self.get_xpath("/Event/System/Execution").get("ProcessID"), 10)
        user = self.get_xpath("/Event/EventData/Data[@Name='SubjectUserName']").text
        domain = self.get_xpath("/Event/EventData/Data[@Name='SubjectDomainName']").text
        logonid = self.get_xpath("/Event/EventData/Data[@Name='SubjectLogonId']").text
        computer = self.get_xpath("/Event/System/Computer").text
        p = Process(pid, ppid, path, user, domain, logonid, computer)
        p.end = self._record.timestamp()
        return p

    def get_process_from_event(self):
        if self.is_process_created_event():
            return self.get_process_from_4688_event()
        elif self.is_process_exited_event():
            return self.get_process_from_4689_event()
        else:
            raise NotAProcessEventError()


def get_entries(evtx):
    """
    @rtype: generator of Entry
    """
    for xml, record in evtx_file_xml_view(evtx.get_file_header()):
        try:
            yield Entry(xml, record)
        except etree.XMLSyntaxError as e:
            continue


def get_entries_with_eids(evtx, eids):
    """
    @type eids: iterable of int
    @rtype: generator of Entry
    """
    for entry in get_entries(evtx):
        if entry.get_eid() in eids:
            yield entry


class ProcessTreeAnalyzer(object):
    def __init__(self):
        super(ProcessTreeAnalyzer, self).__init__()
        self._defs = {}
        self._roots = []
        self._logger = logging.getLogger("process-forest.analyzer")

    def analyze(self, entries):
        """
        @type entries: iterable of Entry
        """
        open_processes = {}
        closed_processes = []
        for entry in entries:
            if entry.is_process_created_event():
                process = entry.get_process_from_event()
                if process.pid in open_processes:
                    self._logger.warning("collision on pid: %x", process.pid)
                    other = open_processes[process.pid]
                    other.notes = Process.NOTE_END_LOST
                    other.end = entry.get_timestamp()
                    closed_processes.append(other)
                open_processes[process.pid] = process

                if process.ppid in open_processes:
                    process.parent = open_processes[process.ppid]
                    process.parent.children.append(process)
                else:
                    self._logger.warning("parent process %x not captured for new process %x", process.ppid, process.pid)
                    # open a faked parent
                    process.parent = create_fake_parent_process(process.ppid)
                    open_processes[process.ppid] = process.parent

            elif entry.is_process_exited_event():
                process = entry.get_process_from_event()
                if process.pid in open_processes:
                    # use existing process instance, if it exists
                    existing_process = open_processes[process.pid]
                    if existing_process.notes == Process.NOTE_FAKE_PARENT:
                        # if we faked it, have to be careful not to lose the children
                        process.children = existing_process.children
                        # discard the faked entry, cause we'll have better info now
                    else:
                        process = existing_process
                    process.end = entry.get_timestamp()
                    del(open_processes[process.pid])
                    closed_processes.append(process)
                else:
                    self._logger.warning("missing start event for exiting process: %x", process.pid)
                    # won't be able to guess parent, since it's PID may have been recycled
                    closed_processes.append(process)
            else:
                self._logger.debug("unexpected entry type: %s", entry)

        i = 0
        for process_set in [open_processes.values(), closed_processes]:
            for process in process_set:
                process.id = i
                i += 1
                self._defs[process.id] = process
                if process.parent is None:
                    self._roots.append(process.id)

        for process in self._defs.values():
            if process.parent is not None:
                process.parent = process.parent.id
            process.children = [c.id for c in process.children]

    def get_roots(self):
        """
        @rtype: list of Node
        """
        ret = []
        # TODO: move this outside analyzer
        def get_children_nodes(analyzer, node):
            # TODO: still need this hacky check?
            if isinstance(node, int):
                n = Node(node, None, [])
                p = n.get_process(analyzer)
                n.parent = p.parent
            else:
                n = node
                p = node.get_process(analyzer)
            return [Node(c, n, get_children_nodes(analyzer, c)) for c in p.children]

        for root in self._roots:
            if root is None:
                continue
            ret.append(Node(root, None, get_children_nodes(self, root)))
        return ret

    def get_processes(self):
        """
        note, Entry.parent/.children are IDs, not references to Entry instances
        @rtype: list of Entry
        """
        return self._defs.values()

    def get_process(self, id):
        return self._defs[id]

    def serialize(self, f):
        def simplify_process(process):
            return {
                "id": process.id,
                "pid": process.pid,
                "ppid": process.ppid,
                "path": process.path,
                "user": process.user,
                "domain": process.domain,
                "logonid": process.logonid,
                "computer": process.computer,
                "begin": process.begin.isoformat(),
                "end": process.end.isoformat(),
                "parent": process.parent,
                "children": process.children,
                "notes": process.notes,
            }

        data = {
                "definitions": {p.id:simplify_process(p) for p in self._defs.values()},
                "roots": self._roots,
        }
        s = json.dumps(data)
        f.write(s)

    def deserialize(self, f):
        s = f.read()
        data = json.loads(s)

        def complexify_process(p):
            process = Process(p["pid"], p["ppid"], p["path"], p["user"], p["domain"], p["logonid"], p["computer"])
            process.begin = iso8601.parse_date(p["begin"]).replace(tzinfo=None)
            process.end = iso8601.parse_date(p["end"]).replace(tzinfo=None)
            process.parent = p["parent"]
            process.children = p["children"]
            process.notes = p["notes"]
            process.id = p["id"]
            return process

        self._defs = {p["id"]:complexify_process(p) for p in data["definitions"].values()}
        self._roots = data["roots"]


class Node(object):
    def __init__(self, id, parent, children):
        self._id = id
        self._parent = parent  # type: Node
        self._children = children  # type: list of Node

    def get_process(self, analyzer):
        """
        @rtype: Process
        """
        return analyzer.get_process(self._id)

    def get_children(self):
        """
        @rtype: list of Node
        """
        return self._children

    def get_parent(self):
        """
        @rtype: Node
        """
        return self._parent


def format_node(analyzer, node):
    p = node.get_process(analyzer)
    s = str(p)
    if p.notes is not None and len(p.notes) > 0:
        s += ": " + p.notes
    return s


def draw_tree(analyzer, node, indent=0):
    print("  " * indent + format_node(analyzer, node))
    for c in node.get_children():
        draw_tree(analyzer, c, indent=indent + 1)


def summarize_processes(processes):
    try:
        first_process = min(filter(lambda p:p.begin != datetime.datetime.min, processes), key=lambda p:p.begin)
        print("first event: %s" % (first_process.begin.isoformat()))
    except ValueError:
        print("first event: unknown")
    try:
        last_process = max(filter(lambda p:p.begin != datetime.datetime.min, processes), key=lambda p:p.begin)
        print("last event: %s" % (last_process.begin.isoformat()))
    except ValueError:
        print("last event: unknown")
    print("-------------------------")

    counts = {}  # map from path to count
    for process in processes:
        if process.path not in counts:
            counts[process.path] = 0
        counts[process.path] += 1

    print("path counts")
    for (path, count) in sorted(counts.items(), key=lambda p:p[1], reverse=True):
        print("  - %s: %d" % (path, count))
    print("-------------------------")

    # TODO: seems to be broken due to timezones?
    #
    #ONE_DAY = datetime.timedelta(1)
    #period = ONE_DAY
    #period_start = first_process.begin
    #ps = filter(lambda p: p.begin != datetime.datetime.min, processes)
    #
    #while period_start <= last_process.begin:
    #    period_count = 0
    #    period_end = period_start + period
    #    while len(ps) > 0 and ps[0].begin < period_end:
    #        period_count += 1
    #        p = ps.pop(0)
    #        print(p.begin.isoformat())
    #
    #    print("  - %s to %s: %d new processes" % (period_start.isoformat(), period_end.isoformat(), period_count))
    #    period_start += period


def main():
    import argparse
    logging.basicConfig(level=logging.DEBUG)
    logging.getLogger("iso8601.iso8601").setLevel(logging.WARNING)

    parser = argparse.ArgumentParser(
        description="Print the record numbers of EVTX log entries "
                    "that match the given EID.")
    parser.add_argument("input_file", type=str,
                        help="Path to the Windows EVTX file or .pt file")

    subparsers = parser.add_subparsers(dest="cmd")

    ts_parser = subparsers.add_parser("ts")
    ts_parser.add_argument("ts", type=str, default="",
                        help="iso8601 timestamp with which to filter")

    summary_parser = subparsers.add_parser("summary")

    serialize_parser = subparsers.add_parser("serialize")
    serialize_parser.add_argument("pt", type=str, default="state.pt",
                        help=".pt file to serialize parsed trees")

    args = parser.parse_args()

    analyzer = ProcessTreeAnalyzer()
    if args.input_file.lower().endswith(".pt"):
        g_logger.info("using serialized file")
        with open(args.input_file, "rb") as f:
            analyzer.deserialize(f)
    else:
        g_logger.info("using evtx log file")
        with Evtx(args.input_file) as evtx:
            analyzer.analyze(get_entries_with_eids(evtx, set([4688, 4689])))
            pass

    if args.cmd == "summary":
        summarize_processes(analyzer.get_processes())
    elif args.cmd == "ts":
        if args.ts == "all":
            for root in analyzer.get_roots():
                draw_tree(analyzer, root)
        else:
            g_logger.error("query trees not yet supported")
    elif args.cmd == "serialize":
        if not args.pt.lower().endswith(".pt"):
            g_logger.error("serialize output file must have .pt extension")
        else:
            with open(args.pt, "wb") as f:
                analyzer.serialize(f)
    else:
        g_logger.error("unknown command: %s", args.cmd)


if __name__ == "__main__":
    main()
