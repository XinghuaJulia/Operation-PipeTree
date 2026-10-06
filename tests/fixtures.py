SYSMON_EVENT_1 = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System>
<Provider Name="Microsoft-Windows-Sysmon"/>
<EventID>1</EventID>
<TimeCreated SystemTime="2026-09-16T14:10:06.6324262Z"/>
<Computer>LAB-HOST</Computer>
</System>
<EventData>
<Data Name="User">LAB\\analyst</Data>
<Data Name="ProcessGuid">{child-guid}</Data>
<Data Name="ProcessId">616</Data>
<Data Name="Image">C:\\Windows\\System32\\curl.exe</Data>
<Data Name="CommandLine">curl.exe https://example.test/file</Data>
<Data Name="Hashes">MD5=AABB,SHA1=CCDD,SHA256=EEFF,IMPHASH=1122</Data>
<Data Name="ParentProcessGuid">{parent-guid}</Data>
<Data Name="ParentProcessId">6940</Data>
<Data Name="ParentImage">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
<Data Name="ParentCommandLine">powershell.exe</Data>
</EventData>
</Event>"""


SECURITY_EVENT_4688 = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System>
<Provider Name="Microsoft-Windows-Security-Auditing"/>
<EventID>4688</EventID>
<TimeCreated SystemTime="2026-09-16T14:10:06.6182525Z"/>
<Computer>LAB-HOST</Computer>
</System>
<EventData>
<Data Name="SubjectUserName">analyst</Data>
<Data Name="SubjectDomainName">LAB</Data>
<Data Name="NewProcessId">0x268</Data>
<Data Name="NewProcessName">C:\\Windows\\System32\\curl.exe</Data>
<Data Name="ProcessId">0x1b1c</Data>
<Data Name="ParentProcessName">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
<Data Name="CommandLine">curl.exe https://example.test/file</Data>
</EventData>
</Event>"""


SYSMON_EVENT_3 = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System>
<Provider Name="Microsoft-Windows-Sysmon"/>
<EventID>3</EventID>
<TimeCreated SystemTime="2026-09-16T14:11:00.0000000Z"/>
<Computer>LAB-HOST</Computer>
</System>
<EventData>
<Data Name="User">LAB\\analyst</Data>
<Data Name="ProcessGuid">{child-guid}</Data>
<Data Name="ProcessId">616</Data>
<Data Name="Image">C:\\Windows\\System32\\curl.exe</Data>
<Data Name="Protocol">tcp</Data>
<Data Name="Initiated">true</Data>
<Data Name="SourceIp">10.0.0.5</Data>
<Data Name="SourceHostname">LAB-HOST</Data>
<Data Name="SourcePort">51000</Data>
<Data Name="DestinationIp">203.0.113.10</Data>
<Data Name="DestinationHostname">example.test</Data>
<Data Name="DestinationPort">443</Data>
</EventData>
</Event>"""
