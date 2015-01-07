purpose
=======

`process-forest` is a tool that processes Microsoft Windows
EVTX event logs that contain process accounting events and
reconstructs the historical process heirarchies. That is,
it displays the parent-child relationships among programs.
When using this tool during an incident response engagement,
identifying a reverse shell process quickly leads to the
processes launched by the operator, and insight into how
it may be maintaining persistence.


technique
=========

`process-forest` relies on the process accounting events that 
may be enabled and captured in the Security event log. When a
new process is spawned, the event logs capture event 4688
that includes the process path, username information, PID
and parent PID, etc. Events with EID 4689 signal that a process has
exited. By walking these events in order, keeping track
of PID "liveness", and watching PID/PPID links, this tool
reconstructs the relationships among all processes captured
in the event log.


example usage
==============

Summarize process lifetime events:

    > python process_forest.py SECURITY.evtx summary

    first event: 2014-11-26T18:16:27.004395
    last event: 2014-12-23T19:18:54.895493
    -------------------------
    path counts
      - C:\Windows\System32\conhost.exe: 4256
      - C:\Windows\System32\wbem\WmiPrvSE.exe: 2930
      - C:\Windows\SysWOW64\CCM\SMSCliUI.exe: 1725
      - C:\Windows\System32\taskeng.exe: 1298
      ...


Display process trees for all process lifetime events:


    > python process_forest.py SECURITY.evtx ts all

    Process(C:\Windows\Temp\googletalk.exe, pid=1b2c, ppid=0, begin=2014-12-14T06:31:37.479113+00:00, end=2014-11-26T22:21:33.096178+00:00
      Process(C:\Windows\System32\cmd.exe, pid=2510, ppid=1b2c, begin=2014-12-15T02:01:17.479113+00:00, end=2014-12-15T02:03:04.685062+00:00
        Process(C:\Windows\System32\HOSTNAME.EXE, pid=13a8, ppid=2510, begin=2014-12-15T02:01:33.375921+00:00, end=2014-12-15T02:01:33.453922+00:00
        Process(C:\Windows\System32\sc.exe, pid=694, ppid=2510, begin=2014-12-15T02:01:40.037292+00:00, end=2014-12-15T02:01:40.068493+00:00
        Process(C:\Windows\Temp\conhost.exe, pid=1cb8, ppid=2510, begin=2014-12-15T02:02:43.546520+00:00, end=2014-12-15T02:02:43.671322+00:00
          Process(C:\Windows\System32\cmd.exe, pid=23ac, ppid=1cb8, begin=2014-12-15T02:02:43.671322+00:00, end=2014-12-15T02:02:47.758629+00:00
            Process(C:\Windows\System32\PING.EXE, pid=18d4, ppid=23ac, begin=2014-12-15T02:02:43.686924+00:00, end=2014-12-15T02:02:47.758629+00:00
            Process(C:\Windows\System32\cmd.exe, pid=2928, ppid=23ac, begin=2014-12-15T02:02:47.758629+00:00, end=2014-12-15T02:02:47.758629+00:00
        Process(C:\Windows\System32\sc.exe, pid=1990, ppid=2510, begin=2014-12-15T02:02:50.441896+00:00, end=2014-12-15T02:02:50.457497+00:00
        Process(C:\Windows\System32\sc.exe, pid=28bc, ppid=2510, begin=2014-12-15T02:02:57.368475+00:00, end=2014-12-15T02:02:57.368475+00:00
      Process(C:\Windows\System32\cmd.exe, pid=2c2c, ppid=1b2c, begin=2014-12-15T02:13:39.496538+00:00, end=2014-12-15T02:14:11.258953+00:00
        Process(C:\Windows\Temp\flashupdate.exe, pid=d2c, ppid=2c2c, begin=2014-12-15T02:14:02.647532+00:00, end=2014-11-27T07:46:00.072481+00:00
          Process(C:\Windows\System32\cmd.exe, pid=d14, ppid=d2c, begin=2014-12-15T02:18:21.473768+00:00, end=2014-11-28T17:31:04.396505+00:00
      Process(C:\Windows\System32\cmd.exe, pid=b74, ppid=1b2c, begin=2014-12-15T02:18:00.538031+00:00, end=2014-12-15T02:23:11.251200+00:00
        Process(C:\Windows\System32\HOSTNAME.EXE, pid=1414, ppid=b74, begin=2014-12-15T02:19:15.607157+00:00, end=2014-12-15T02:19:15.622757+00:00
        Process(C:\Windows\System32\sc.exe, pid=2dd8, ppid=b74, begin=2014-12-15T02:21:36.431967+00:00, end=2014-12-15T02:21:36.447567+00:00
        Process(C:\Windows\System32\sc.exe, pid=2ea8, ppid=b74, begin=2014-12-15T02:21:36.447567+00:00, end=2014-12-15T02:21:36.447567+00:00
        Process(C:\Windows\System32\sc.exe, pid=130c, ppid=b74, begin=2014-12-15T02:21:36.447567+00:00, end=2014-12-15T02:21:36.447567+00:00
        Process(C:\Windows\System32\reg.exe, pid=2604, ppid=b74, begin=2014-12-15T02:21:36.478769+00:00, end=2014-12-15T02:21:41.361694+00:00
        Process(C:\Windows\System32\sc.exe, pid=2a10, ppid=b74, begin=2014-12-15T02:21:50.394325+00:00, end=2014-12-15T02:21:50.409925+00:00
        Process(C:\Windows\System32\sc.exe, pid=2fb8, ppid=b74, begin=2014-12-15T02:21:56.400480+00:00, end=2014-12-15T02:21:56.400480+00:00
        Process(C:\Windows\System32\sc.exe, pid=2988, ppid=b74, begin=2014-12-15T02:21:56.400480+00:00, end=2014-12-15T02:21:56.416079+00:00
        Process(C:\Windows\System32\sc.exe, pid=2e44, ppid=b74, begin=2014-12-15T02:21:56.416079+00:00, end=2014-12-15T02:21:56.416079+00:00
        Process(C:\Windows\System32\reg.exe, pid=2ebc, ppid=b74, begin=2014-12-15T02:21:56.416079+00:00, end=2014-12-15T02:21:56.431681+00:00
        Process(C:\Windows\System32\reg.exe, pid=14d4, ppid=b74, begin=2014-12-15T02:21:56.431681+00:00, end=2014-12-15T02:21:56.447281+00:00
        Process(C:\Windows\System32\net.exe, pid=2540, ppid=b74, begin=2014-12-15T02:21:56.462881+00:00, end=2014-12-15T02:21:58.646936+00:00
          Process(C:\Windows\System32\net1.exe, pid=2390, ppid=2540, begin=2014-12-15T02:21:56.540882+00:00, end=2014-12-15T02:21:58.646936+00:00
        Process(C:\Windows\System32\sc.exe, pid=ee0, ppid=b74, begin=2014-12-15T02:21:58.646936+00:00, end=2014-12-15T02:21:58.646936+00:00
        Process(C:\Windows\System32\HOSTNAME.EXE, pid=27ec, ppid=b74, begin=2014-12-15T02:22:03.545464+00:00, end=2014-12-15T02:22:03.561064+00:00
      Process(C:\Windows\System32\cmd.exe, pid=2884, ppid=1b2c, begin=2014-12-15T06:39:23.869759+00:00, end=2014-12-15T06:39:40.998999+00:00
        Process(C:\Windows\Rar.exe, pid=2748, ppid=2884, begin=2014-12-15T06:39:25.663805+00:00, end=2014-12-15T06:39:25.882210+00:00
      Process(C:\Windows\System32\cmd.exe, pid=23e8, ppid=1b2c, begin=2014-12-16T01:25:11.214762+00:00, end=2014-12-16T01:30:26.982456+00:00
        Process(C:\Windows\System32\net.exe, pid=d48, ppid=23e8, begin=2014-12-16T01:29:22.849215+00:00, end=2014-12-16T01:29:23.114420+00:00
        Process(C:\Windows\System32\net.exe, pid=22c4, ppid=23e8, begin=2014-12-16T01:30:21.974730+00:00, end=2014-12-16T01:30:21.990330+00:00
        Process(C:\Windows\System32\HOSTNAME.EXE, pid=1d7c, ppid=23e8, begin=2014-12-16T01:30:25.406816+00:00, end=2014-12-16T01:30:25.516020+00:00
        ...


For large EVTX files, the parsing can take a while (due to the implementation in Python).
To save time as you explore the tool, you can preprocess the log file into
a ".pt" (Process Tree) file, which speeds up subsequent invokations.
Use the .pt file instead of the EVTX file, and the tool will handle
the details.

Here's the time it takes to process a 20MB EVTX file on one computer:


    > time python process_forest.py SECURITY.evtx ts all
    ... snip ...
    python process_forest.py ts all:  38.85s user 0.55s system 97% cpu 40.375 total


To speed multiple future invocations up, we precompute some data and
save it off:


    > python process_forest.py SECURITY.evtx serialize SECURITY.pt


Now when we run the listings again, it goes much faster:


    > time python process_forest.py SECURITY.pt ts all
    ... snip ...
    python process_forest.py ts all:  3.04s user 0.49s system 76% cpu 4.610 total


limitations
===========

  - this tool currently only supports Security.EVTX files. EVT support is coming later.
  - this tool only captures information from the event log. If important entries
    are missing, then it can only do a best-effort job to reconstruct the process
    trees. For example:
       - if a log does not span the time since a system was starting, it will not
         contain the creation event for the core Windows processes.
       - if a portion of the log was cleared, or events missing, then there may
         be collisions in process "liveness". That is, the tool may identify two
         processes with the same PID at the same time.
    The tool alerts the user when data is missing.
