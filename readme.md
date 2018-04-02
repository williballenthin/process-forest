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
may be enabled and captured in the Security event log or Sysmon Operational log. When a
new process is spawned, the event logs capture event 4688 (Security) or 1 (Sysmon)
that includes the process path, username information, PID
and parent PID, etc. Events with EID 4689 (Security) or 5 (Sysmon) signal that a process has
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

    Process(C:\Windows\explorer.exe, cmd=UNKNOWN, hashes=UNKNOWN, pid=3304, ppid=0, begin=0001-01-01T00:00:00, end=0001-01-01T00:00:00: Fake Parent: This is a faked process created since a ppid didn't exist
      Process(C:\Windows\System32\cmd.exe, cmd="C:\Windows\system32\cmd.exe" , hashes=UNKNOWN, pid=2408, ppid=3304, begin=2016-03-19T20:47:43.846725, end=0001-01-01T00:00:00
        Process(C:\Windows\System32\conhost.exe, cmd=\??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1, hashes=UNKNOWN, pid=4272, ppid=2408, begin=2016-03-19T20:47:43.930553, end=0001-01-01T00:00:00
        Process(C:\Windows\System32\PING.EXE, cmd=ping  192.168.2.2, hashes=UNKNOWN, pid=5112, ppid=2408, begin=2016-03-19T20:47:48.418451, end=2016-03-19T20:47:51.509247
        Process(C:\Windows\System32\net.exe, cmd=net  time, hashes=UNKNOWN, pid=2936, ppid=2408, begin=2016-03-19T20:47:53.295649, end=2016-03-19T20:48:00.207243
          Process(C:\Windows\System32\net1.exe, cmd=C:\Windows\system32\net1  time, hashes=UNKNOWN, pid=3852, ppid=2936, begin=2016-03-19T20:47:53.306993, end=2016-03-19T20:48:01.142002
        Process(C:\Windows\System32\calc.exe, cmd=calc, hashes=UNKNOWN, pid=2336, ppid=2408, begin=2016-03-19T20:48:29.693279, end=2016-03-19T20:48:32.034391
        Process(C:\Windows\System32\notepad.exe, cmd=notepad, hashes=UNKNOWN, pid=3348, ppid=2408, begin=2016-03-19T20:48:35.440413, end=0001-01-01T00:00:00
    Process(C:\Windows\System32\svchost.exe, cmd=UNKNOWN, hashes=UNKNOWN, pid=2084, ppid=0, begin=0001-01-01T00:00:00, end=0001-01-01T00:00:00: Fake Parent: This is a faked process created since a ppid didn't exist
      Process(C:\Windows\System32\dllhost.exe, cmd=C:\Windows\system32\DllHost.exe /Processid:{AB8902B4-09CA-4BB6-B78D-A8F59079A8D5}, hashes=UNKNOWN, pid=4128, ppid=2084, begin=2016-03-19T20:47:43.038507, end=2016-03-19T20:47:48.193815
      Process(C:\Windows\System32\ApplicationFrameHost.exe, cmd=C:\Windows\system32\ApplicationFrameHost.exe -Embedding, hashes=UNKNOWN, pid=1656, ppid=2084, begin=2016-03-19T20:48:30.616486, end=0001-01-01T00:00:00
      Process(C:\Program Files\WindowsApps\Microsoft.WindowsCalculator_10.1601.49020.0_x64__8wekyb3d8bbwe\Calculator.exe, cmd="C:\Program Files\WindowsApps\Microsoft.WindowsCalculator_10.1601.49020.0_x64__8wekyb3d8bbwe\Calculator.exe" -ServerName:App.AppXsm3pg4n7er43kdh1qp4e79f1j7am68r8.mca, hashes=UNKNOWN, pid=960, ppid=2084, begin=2016-03-19T20:48:31.711050, end=0001-01-01T00:00:00
        ...

    > python process_forest.py Microsoft-Windows-Sysmon%4Operational.evtx ts all
    
    Process(C:\Windows\System32\services.exe, cmd=UNKNOWN, hashes=UNKNOWN, pid=500, ppid=0, begin=0001-01-01T00:00:00, end=0001-01-01T00:00:00: Fake Parent: This is a faked process created since a ppid didn't exist
      Process(C:\Windows\Sysmon.exe, cmd=C:\Windows\Sysmon.exe, hashes=MD5=2E5F6BB9692F7FF20CFCFC9AF097D9FC,IMPHASH=CDFE7352C4CC5D5EFCFFAAAC26E91D60, pid=2560, ppid=500, begin=2016-03-23T17:07:58.651699, end=0001-01-01T00:00:00
      Process(C:\Windows\System32\taskhost.exe, cmd=taskhost.exe $(Arg0), hashes=MD5=639774C9ACD063F028F6084ABF5593AD,IMPHASH=D9C431646227DBA4B6B2A1313802ED63, pid=1424, ppid=500, begin=2016-03-23T18:00:30.337669, end=2016-03-23T18:02:30.478363
      Process(C:\Windows\System32\taskhost.exe, cmd=taskhost.exe SYSTEM, hashes=MD5=639774C9ACD063F028F6084ABF5593AD,IMPHASH=D9C431646227DBA4B6B2A1313802ED63, pid=2252, ppid=500, begin=2016-03-23T18:07:09.324966, end=2016-03-23T18:07:09.340567
      Process(C:\Windows\System32\taskhost.exe, cmd=taskhost.exe $(Arg0), hashes=MD5=639774C9ACD063F028F6084ABF5593AD,IMPHASH=D9C431646227DBA4B6B2A1313802ED63, pid=2620, ppid=500, begin=2016-03-23T19:03:00.504421, end=2016-03-23T19:05:00.646055
      Process(C:\Windows\System32\taskhost.exe, cmd=taskhost.exe $(Arg0), hashes=MD5=639774C9ACD063F028F6084ABF5593AD,IMPHASH=D9C431646227DBA4B6B2A1313802ED63, pid=1252, ppid=500, begin=2016-03-23T20:05:47.669977, end=2016-03-23T20:07:47.810583
      Process(C:\Windows\System32\taskhost.exe, cmd=taskhost.exe $(Arg0), hashes=MD5=639774C9ACD063F028F6084ABF5593AD,IMPHASH=D9C431646227DBA4B6B2A1313802ED63, pid=1192, ppid=500, begin=2016-03-24T00:06:11.779625, end=2016-03-24T00:08:16.182283
      Process(C:\Windows\System32\taskhost.exe, cmd=taskhost.exe $(Arg0), hashes=MD5=639774C9ACD063F028F6084ABF5593AD,IMPHASH=D9C431646227DBA4B6B2A1313802ED63, pid=1200, ppid=500, begin=2016-03-24T01:09:20.788097, end=2016-03-24T01:11:20.913534
    Process(C:\Windows\System32\winlogon.exe, cmd=UNKNOWN, hashes=UNKNOWN, pid=444, ppid=0, begin=0001-01-01T00:00:00, end=0001-01-01T00:00:00: Fake Parent: This is a faked process created since a ppid didn't exist
      Process(C:\Windows\System32\taskmgr.exe, cmd=taskmgr.exe /2 , hashes=MD5=09F7401D56F2393C6CA534FF0241A590,IMPHASH=68E56344CAB250384904953E978B70A9, pid=1424, ppid=444, begin=2016-03-23T17:17:34.770151, end=2016-03-23T17:17:46.470600
    Process(C:\Windows\System32\csrss.exe, cmd=UNKNOWN, hashes=UNKNOWN, pid=408, ppid=0, begin=0001-01-01T00:00:00, end=0001-01-01T00:00:00: Fake Parent: This is a faked process created since a ppid didn't exist
      Process(C:\Windows\System32\conhost.exe, cmd=\??\C:\Windows\system32\conhost.exe "-2596793011012622666521040507-794026175-12198051332145736009-124749138470921422", hashes=MD5=94C5B49D3E89CE9E02A6D6133A4F4321,IMPHASH=BA6498D069813141251615FFFC2A69D3, pid=1824, ppid=408, begin=2016-03-23T17:09:55.095173, end=2016-03-23T17:14:32.319595
    Process(C:\Windows\System32\svchost.exe, cmd=UNKNOWN, hashes=UNKNOWN, pid=612, ppid=0, begin=0001-01-01T00:00:00, end=0001-01-01T00:00:00: Fake Parent: This is a faked process created since a ppid didn't exist
      Process(C:\Windows\System32\mobsync.exe, cmd=C:\Windows\System32\mobsync.exe -Embedding, hashes=MD5=509E88FF7B257885775791FAF0965D6A,IMPHASH=F714D092385CEE7898887F01B2072F4B, pid=2044, ppid=612, begin=2016-03-23T21:03:26.431755, end=2016-03-24T00:06:37.388523
      Process(C:\Windows\System32\mobsync.exe, cmd=C:\Windows\System32\mobsync.exe -Embedding, hashes=MD5=509E88FF7B257885775791FAF0965D6A,IMPHASH=F714D092385CEE7898887F01B2072F4B, pid=2280, ppid=612, begin=2016-03-24T00:16:23.524853, end=2016-03-24T00:16:41.803833
      Process(C:\Windows\System32\dllhost.exe, cmd=C:\Windows\system32\DllHost.exe /Processid:{AB8902B4-09CA-4BB6-B78D-A8F59079A8D5}, hashes=MD5=A8EDB86FC2A4D6D1285E4C70384AC35A,IMPHASH=3D806EF1101283F4E5D20F0C4F83B8FD, pid=1920, ppid=612, begin=2016-03-24T01:56:11.389832, end=0001-01-01T00:00:00
    Process(C:\Windows\System32\SearchIndexer.exe, cmd=UNKNOWN, hashes=UNKNOWN, pid=2528, ppid=0, begin=0001-01-01T00:00:00, end=0001-01-01T00:00:00: Fake Parent: This is a faked process created since a ppid didn't exist
      Process(C:\Windows\System32\SearchProtocolHost.exe, cmd="C:\Windows\system32\SearchProtocolHost.exe" Global\UsGthrFltPipeMssGthrPipe12_ Global\UsGthrCtrlFltPipeMssGthrPipe12 1 -2147483646 "Software\Microsoft\Windows Search" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT; MS Search 4.0 Robot)" "C:\ProgramData\Microsoft\Search\Data\Temp\usgthrsvc" "DownLevelDaemon" , hashes=MD5=D9E21CBF9E6A87847AFFD39EA3FA28EE,IMPHASH=3E21C2C0BFB7FA9AAD5C782DBF401846, pid=2948, ppid=2528, begin=2016-03-23T17:11:58.822676, end=2016-03-23T17:13:08.917692
      Process(C:\Windows\System32\SearchFilterHost.exe, cmd="C:\Windows\system32\SearchFilterHost.exe" 0 516 520 528 65536 524 , hashes=MD5=49A3AD5CE578CD77F445F3D244AEAB2D,IMPHASH=48476C179FBF9FC0CC7AE2A8A5FB1073, pid=2400, ppid=2528, begin=2016-03-23T17:11:58.838276, end=2016-03-23T17:13:08.917692
    Process(C:\Windows\System32\svchost.exe, cmd=UNKNOWN, hashes=UNKNOWN, pid=748, ppid=0, begin=0001-01-01T00:00:00, end=0001-01-01T00:00:00: Fake Parent: This is a faked process created since a ppid didn't exist
      Process(C:\Windows\System32\audiodg.exe, cmd=C:\Windows\system32\AUDIODG.EXE 0x1a4, hashes=MD5=6E974F1C384615DEB0710E44F4847351,IMPHASH=2A6BF191EDFE97CC30EBB8D1AEB3A6B6, pid=1640, ppid=748, begin=2016-03-24T01:56:09.687605, end=0001-01-01T00:00:00
    Process(C:\Windows\explorer.exe, cmd=UNKNOWN, hashes=UNKNOWN, pid=1448, ppid=0, begin=0001-01-01T00:00:00, end=0001-01-01T00:00:00: Fake Parent: This is a faked process created since a ppid didn't exist
      Process(C:\Windows\System32\cmd.exe, cmd="C:\Windows\system32\cmd.exe" , hashes=MD5=5746BD7E255DD6A8AFA06F7C42C1BA41,IMPHASH=D0058544E4588B1B2290B7F4D830EB0A, pid=1100, ppid=1448, begin=2016-03-23T17:09:55.095173, end=2016-03-23T17:14:32.319595
        Process(C:\Windows\System32\notepad.exe, cmd=notepad, hashes=MD5=B32189BDFF6E577A92BAA61AD49264E6,IMPHASH=FCCD5E915D9C361A1F0ECCBF0B8B66ED, pid=940, ppid=1100, begin=2016-03-23T17:09:58.152889, end=2016-03-23T17:10:03.936321
        Process(C:\Windows\System32\calc.exe, cmd=calc, hashes=MD5=10E4A1D2132CCB5C6759F038CDB6F3C9,IMPHASH=CA7337BD1DFA93FD45FF30B369488A37, pid=2004, ppid=1100, begin=2016-03-23T17:10:02.099840, end=2016-03-23T17:10:05.168768
        Process(C:\Windows\System32\net.exe, cmd=net  time, hashes=MD5=63DD6FBAABF881385899FD39DF13DCE3,IMPHASH=96B4B43C2313DC3C3237F7C32A9F8812, pid=1676, ppid=1100, begin=2016-03-23T17:10:07.290449, end=2016-03-23T17:10:24.107897
          Process(C:\Windows\System32\net1.exe, cmd=C:\Windows\system32\net1  time, hashes=MD5=3B6928BC39E5530CEAD1E99269E7B1EE,IMPHASH=72AA515B1963995C201E36DE48594F61, pid=2272, ppid=1676, begin=2016-03-23T17:10:07.290449, end=2016-03-23T17:10:24.107897
        Process(C:\Windows\System32\ipconfig.exe, cmd=ipconfig, hashes=MD5=CF45949CDBB39C953331CDCB9CEC20F8,IMPHASH=BBBA00511B8BEF70143B0EEBBB337273, pid=1304, ppid=1100, begin=2016-03-23T17:11:37.542912, end=2016-03-23T17:11:37.558514
        Process(C:\Windows\System32\mstsc.exe, cmd=mstsc, hashes=MD5=8E75B1112C374EBDF18FD640DA2F0655,IMPHASH=A4508E6BF5CA8E66A9003310D569E036, pid=2712, ppid=1100, begin=2016-03-23T17:11:58.760271, end=2016-03-23T17:12:01.459244
        Process(C:\Windows\System32\cmd.exe, cmd=cmd  /c ipconfig, hashes=MD5=5746BD7E255DD6A8AFA06F7C42C1BA41,IMPHASH=D0058544E4588B1B2290B7F4D830EB0A, pid=2956, ppid=1100, begin=2016-03-23T17:12:21.085302, end=2016-03-23T17:12:21.116505
          Process(C:\Windows\System32\ipconfig.exe, cmd=ipconfig, hashes=MD5=CF45949CDBB39C953331CDCB9CEC20F8,IMPHASH=BBBA00511B8BEF70143B0EEBBB337273, pid=1536, ppid=2956, begin=2016-03-23T17:12:21.100903, end=2016-03-23T17:12:21.116505
        Process(C:\Windows\System32\PING.EXE, cmd=ping  192.168.2.2, hashes=MD5=5FB30FE90736C7FC77DE637021B1CE7C,IMPHASH=33BEE540593D1AD78C69C59B9D26DECF, pid=1668, ppid=1100, begin=2016-03-23T17:12:28.994989, end=2016-03-23T17:12:32.037167
        Process(C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe, cmd=powershell.exe  Invoke-Command -ScriptBlock {Get-Help Invoke-Command -full}, hashes=MD5=852D67A27E454BD389FA7F02A8CBE23F,IMPHASH=F2C0E8A5BD10DBC167455484050CD683, pid=2980, ppid=1100, begin=2016-03-23T17:13:53.551691, end=2016-03-23T17:13:54.940161
      Process(C:\Program Files\Windows Media Player\wmpnscfg.exe, cmd="C:\Program Files\Windows Media Player\wmpnscfg.exe", hashes=MD5=6699A112A3BDC9B52338512894EBA9D6,IMPHASH=CE1A36A2A999517CA9B1C36DF3B7E240, pid=764, ppid=1448, begin=2016-03-23T21:03:26.993387, end=2016-03-23T21:03:27.040190
    ...

To display PID and PPID values in hexidecimal, use the `-X` (`--hexpids`) option:


    > python process_forest.py --hexpids SECURITY.evtx ts all

    Process(C:\Windows\explorer.exe, cmd=UNKNOWN, hashes=UNKNOWN, pid=0xce8, ppid=0x0, begin=0001-01-01T00:00:00, end=0001-01-01T00:00:00: Fake Parent: This is a faked process created since a ppid didn't exist
      Process(C:\Windows\System32\cmd.exe, cmd="C:\Windows\system32\cmd.exe" , hashes=UNKNOWN, pid=0x968, ppid=0xce8, begin=2016-03-19T20:47:43.846725, end=0001-01-01T00:00:00
        Process(C:\Windows\System32\conhost.exe, cmd=\??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1, hashes=UNKNOWN, pid=0x10b0, ppid=0x968, begin=2016-03-19T20:47:43.930553, end=0001-01-01T00:00:00
        Process(C:\Windows\System32\PING.EXE, cmd=ping  192.168.2.2, hashes=UNKNOWN, pid=0x13f8, ppid=0x968, begin=2016-03-19T20:47:48.418451, end=2016-03-19T20:47:51.509247
        Process(C:\Windows\System32\net.exe, cmd=net  time, hashes=UNKNOWN, pid=0xb78, ppid=0x968, begin=2016-03-19T20:47:53.295649, end=2016-03-19T20:48:00.207243
          Process(C:\Windows\System32\net1.exe, cmd=C:\Windows\system32\net1  time, hashes=UNKNOWN, pid=0xf0c, ppid=0xb78, begin=2016-03-19T20:47:53.306993, end=2016-03-19T20:48:01.142002
        Process(C:\Windows\System32\calc.exe, cmd=calc, hashes=UNKNOWN, pid=0x920, ppid=0x968, begin=2016-03-19T20:48:29.693279, end=2016-03-19T20:48:32.034391
        Process(C:\Windows\System32\notepad.exe, cmd=notepad, hashes=UNKNOWN, pid=0xd14, ppid=0x968, begin=2016-03-19T20:48:35.440413, end=0001-01-01T00:00:00
    Process(C:\Windows\System32\svchost.exe, cmd=UNKNOWN, hashes=UNKNOWN, pid=0x338, ppid=0x0, begin=0001-01-01T00:00:00, end=0001-01-01T00:00:00: Fake Parent: This is a faked process created since a ppid didn't exist
      Process(C:\Windows\System32\dllhost.exe, cmd=C:\Windows\system32\DllHost.exe /Processid:{AB8902B4-09CA-4BB6-B78D-A8F59079A8D5}, hashes=UNKNOWN, pid=0x1020, ppid=0x338, begin=2016-03-19T20:47:43.038507, end=2016-03-19T20:47:48.193815
      Process(C:\Windows\System32\ApplicationFrameHost.exe, cmd=C:\Windows\system32\ApplicationFrameHost.exe -Embedding, hashes=UNKNOWN, pid=0x678, ppid=0x338, begin=2016-03-19T20:48:30.616486, end=0001-01-01T00:00:00
      Process(C:\Program Files\WindowsApps\Microsoft.WindowsCalculator_10.1601.49020.0_x64__8wekyb3d8bbwe\Calculator.exe, cmd="C:\Program Files\WindowsApps\Microsoft.WindowsCalculator_10.1601.49020.0_x64__8wekyb3d8bbwe\Calculator.exe" -ServerName:App.AppXsm3pg4n7er43kdh1qp4e79f1j7am68r8.mca, hashes=UNKNOWN, pid=0x3c0, ppid=0x338, begin=2016-03-19T20:48:31.711050, end=0001-01-01T00:00:00
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

  - this tool currently only supports Security.EVTX and Microsft-Windows-Sysmon%4Operational.evtx files. EVT support is coming later.
  - this tool only captures information from the event log. If important entries
    are missing, then it can only do a best-effort job to reconstruct the process
    trees. For example:
       - if a log does not span the time since a system was starting, it will not
         contain the creation event for the core Windows processes.
       - if a portion of the log was cleared, or events missing, then there may
         be collisions in process "liveness". That is, the tool may identify two
         processes with the same PID at the same time.
    The tool alerts the user when data is missing.
