{ config, lib, ... }: {

  config = lib.mkIf config.programs.wazuh.enable {
    # Comming from https://github.com/sametsazak/sysmon
    environment.etc."wazuh/config/local_rules.xml".text = ''
      <!--
      Rules from https://github.com/Neo23x0/sigma/tree/master/rules/windows/sysmon
      @smtszk

      updated by @nissy34
      -->

      <!-- Sysmon Wazuh Rules version 1.0-->

      <group name="sysmon,sysmon_process-anomalies,">
          <rule id="255000" level="12">
              <if_group>sysmon_event1</if_group>
              <field name="win.eventdata.image">\\powershell.exe||\\.ps1||\\.ps2</field>
              <description>Sysmon - Event 1: Powershell or Script Execution: $(win.eventdata.image)</description>
          </rule>

          <rule id="255001" level="0">
              <field name="win.eventdata.Image">\\rundll32.exe</field>
              <description>Sysmon - rundll32.exe</description>
          </rule>

          <rule id="255002" level="12">
              <if_sid>255001</if_sid>
              <field name="win.eventdata.ImageLoaded">\\vaultcli.dll</field>
              <description>Possible Mimikatz Running In-Memory Detection</description>
          </rule>

          <rule id="255003" level="12">
              <if_sid>255001</if_sid>
              <field name="win.eventdata.ImageLoaded">\\wlanapi.dll</field>
              <description>Possible Mimikatz In-Memory Detection</description>
          </rule>

          <rule id="255004" level="0">
              <if_group>sysmon_event1</if_group>
              <field name="win.eventdata.parentImage">\\mshta.exe</field>
              <description>Sysmon - mshta.exe</description>
          </rule>

          <rule id="255005" level="12">
              <if_sid>255004</if_sid>
              <field name="win.eventdata.Image">\\cmd.exe||\\powershell.exe||\\wscript.exe||\\cscript.exe||\\sh.exe||\\bash.exe||\\reg.exe||\\regsvr32.exe||\\BITSADMIN*</field>
              <description>Detection a Windows command line executable started from MSHTA</description>
          </rule>

          <rule id="255006" level="0">
              <if_group>sysmon_event1</if_group>
              <field name="win.eventdata.ParentImage">\\WINWORD.EXE||\\EXCEL.EXE||\\POWERPNT.exe||\\MSPUB.exe||\\VISIO.exe</field>
              <description>Sysmon - MS Word - Ms EXCEL run</description>
          </rule>

          <rule id="255007" level="12">
              <if_sid>255006</if_sid>
              <field name="win.eventdata.Image">\\cmd.exe</field>
              <description>Possible Office Macro Started : $(win.eventdata.image)</description>
          </rule>

          <rule id="255008" level="12">
              <if_sid>255006</if_sid>
              <field name="win.eventdata.Image">\\cmd.exe||\\powershell.exe||\\wscript.exe||\\cscript.exe||\\sh.exe||\\bash.exe||\\scrcons.exe||\\schtasks.exe||\\regsvr32.exe||\\hh.exe</field>
              <description>Microsoft Office Product Spawning Windows Shell</description>
          </rule>

          <rule id="255009" level="0">
              <if_group>sysmon_event8</if_group>
              <field name="win.eventdata.TargetImage">\\lsass.exe</field>
              <description>sysmon</description>
          </rule>

          <rule id="255010" level="12">
              <if_sid>255009</if_sid>
              <field name="win.eventdata.startModule">null</field>
              <description>Password Dumper Remote Thread in LSASS</description>
          </rule>

          <rule id="255011" level="12">
              <if_sid>255000</if_sid>
              <field name="win.eventdata.commandline">DownloadString||downloadfile</field>
              <description>PowerShell scripts that download content from the Internet</description>
          </rule>

          <rule id="255016" level="12">
              <if_sid>255000</if_sid>
              <field name="win.eventdata.commandline">EncodedCommand||-w hidden||-window hidden||-windowstyle hidden||-enc||-noni||noninteractive</field>
              <description>Detects suspicious PowerShell invocation command parameters</description>
          </rule>

          <rule id="255017" level="0">
              <if_group>sysmon_event3</if_group>
              <field name="win.eventdata.image">rundll32.exe</field>
              <description>Rundll32 Internet Connection</description>
          </rule>

          <rule id="255018" level="12">
              <if_sid>255017</if_sid>
              <match>!192.</match>
              <description>Detects a rundll32 that communicates with public IP addresses</description>
          </rule>

          <rule id="255020" level="0">
              <if_group>sysmon_event1</if_group>
              <field name="win.eventdata.image">certutil.exe</field>
              <description>Detetcs a suspicious Microsoft certutil execution with sub commands</description>
          </rule>

          <rule id="255021" level="12">
              <if_sid>255020</if_sid>
              <field name="win.eventdata.commandline">URL||decode||decodehex||urlcache||ping</field>
              <description>Detetcs a suspicious Microsoft certutil execution with sub commands</description>
          </rule>

          <rule id="255023" level="12">
              <if_sid>255000</if_sid>
              <field name="win.eventdata.currentDirectory">AppData</field>
              <description>Detects a suspicious command line execution that includes an URL and AppData</description>
          </rule>

          <rule id="255024" level="0">
              <if_group>sysmon_event1</if_group>
              <field name="win.eventdata.parentImage">\\System32\\control.exe</field>
              <description>Detects suspicious Rundll32 execution from control.exe as used by Equation Group and Exploit Kits</description>
          </rule>

          <rule id="255025" level="12">
              <if_sid>255024</if_sid>
              <field name="win.eventdata.commandline">\\rundll32.exe</field>
              <description>Detects suspicious Rundll32 execution from control.exe as used by Equation Group and Exploit Kits</description>
          </rule>

          <rule id="255026" level="12">
              <if_group>sysmon_event6</if_group>
              <field name="win.eventdata.imageLoaded">\\Temp</field>
              <description>Detects a driver load from a temporary directory</description>
          </rule>

          <rule id="255027" level="12">
              <if_group>sysmon_event1</if_group>
              <field name="win.eventdata.image">C:\\PerfLogs\\||C:\$Recycle.bin\\||C:\\Intel\\Logs\\||C:\\Users\\Default\\||C:\\Users\\Public\\||C:\\Users\\NetworkService\\||C:\\Windows\\Fonts\\C:\\Windows\\Debug\\||C:\\Windows\\Media\\||C:\\Windows\\Help\\||C:\\Windows\\addins\\||C:\\Windows\\repair\\||C:\\Windows\\security\\||\\RSA\\MachineKeys\\||C:\\Windows\\system32\\config\\systemprofile</field>
              <description>Detects process starts of binaries from a suspicious folder</description>
          </rule>

          <rule id="255028" level="0">
              <if_group>sysmon_event1</if_group>
              <field name="win.eventdata.parentImage">\\mmc.exe</field>
              <description>Processes started by MMC could by a sign of lateral movement using MMC application COM object</description>
          </rule>

          <rule id="255029" level="12">
              <if_sid>255028</if_sid>
              <field name="win.eventdata.image">\\cmd.exe</field>
              <description>Processes started by MMC could by a sign of lateral movement using MMC application COM object</description>
          </rule>

          <!-- https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/-->
          <rule id="255030" level="0">
              <if_group>sysmon_event1</if_group>
              <field name="win.eventdata.parentImage">\\net.exe||\\net1.exe</field>
              <description>Detects execution of Net.exe, whether suspicious or benign.</description>
          </rule>

          <rule id="255031" level="12">
              <if_sid>255030</if_sid>
              <field name="win.eventdata.commandline">group||localgroup||user||view||share||accounts||use</field>
              <description>Detects execution of Net.exe, whether suspicious or benign</description>
          </rule>

          <rule id="255032" level="0">
              <if_group>sysmon_event1</if_group>
              <field name="win.eventdata.parentImage">\\wscript.exe||\\cscript.exe</field>
              <description>Sysmon - wscript/cscript.exe</description>
          </rule>

          <rule id="255033" level="12">
              <if_sid>255032</if_sid>
              <field name="win.eventdata.Image">\\powershell.exe</field>
              <description>Detects suspicious powershell invocations from interpreters or unusual programs</description>
          </rule>

          <rule id="255034" level="12">
              <if_sid>255030</if_sid>
              <field name="win.eventdata.commandline">net group "domain admins" /domain||net localgroup administrators||net1 group "domain admins" /domain||net1 localgroup administrators</field>
              <description>Detects suspicious command line activity on Windows systems</description>
          </rule>

          <rule id="255035" level="0">
              <if_group>sysmon_event1</if_group>
              <field name="win.eventdata.image">\\regsvr32.exe</field>
              <description>Detects various anomalies in relation to regsvr32.exe</description>
          </rule>

          <rule id="255036" level="12">
              <if_sid>255035</if_sid>
              <field name="win.eventdata.commandline">\\Temp</field>
              <description>Detects various anomalies in relation to regsvr32.exe</description>
          </rule>

          <rule id="255037" level="12">
              <if_sid>255035</if_sid>
              <field name="win.eventdata.parentImage">powershell.exe</field>
              <description>Detects various anomalies in relation to regsvr32.exe</description>
          </rule>

          <rule id="255038" level="12">
              <if_sid>255035</if_sid>
              <field name="win.eventdata.commandline">scrobj.dll</field>
              <description>Detects various anomalies in relation to regsvr32.exe</description>
          </rule>

          <rule id="255039" level="0">
              <if_group>sysmon_event1</if_group>
              <field name="win.eventdata.image">\\schtasks.exe</field>
              <description>Detects the creation of scheduled tasks in user session</description>
          </rule>

          <rule id="255040" level="12">
              <if_sid>255039</if_sid>
              <field name="win.eventdata.commandline">/create</field>
              <description>Detects the creation of scheduled tasks in user session</description>
          </rule>

          <rule id="255041" level="0">
              <if_group>sysmon_event1</if_group>
              <field name="win.eventdata.image">\\wscript.exe||\\cscript.exe</field>
              <description>Detects various anomalies in relation to wscriptcscript</description>
          </rule>

          <rule id="255042" level="12">
              <if_sid>255041</if_sid>
              <field name="win.eventdata.commandline">jse||vbe||js||vba</field>
              <description>Detects suspicious file execution by wscript and cscript</description>
          </rule>

          <rule id="255043" level="0">
              <if_group>sysmon_event1</if_group>
              <field name="win.eventdata.parentImage">\\svchost.exe</field>
              <description>Suspicious Svchost Process</description>
          </rule>

          <rule id="255044" level="12">
              <if_sid>255041</if_sid>
              <field name="win.eventdata.image">\\services.exe</field>
              <description>Detects a suspicious scvhost process start</description>
          </rule>

          <rule id="255045" level="12">
              <if_group>sysmon_event1</if_group>
              <field name="win.eventdata.commandline">vssadmin.exe Delete Shadows||vssadmin create shadow||GLOBALROOT||vssadmin delete shadows||reg SAVE HKLM\\SYSTEM||\\windows\\ntds\\ntds.dit</field>
              <description>Detects suspicious commands that could be related to activity that uses volume shadow copy</description>
          </rule>

          <rule id="255046" level="0">
              <if_group>sysmon_event1</if_group>
              <field name="win.eventdata.image">\\wmic.exe</field>
              <description>Detects WMI executing suspicious commands</description>
          </rule>

          <rule id="255047" level="12">
              <if_sid>255046</if_sid>
              <field name="win.eventdata.commandline">process call create||AntiVirusProduct get||FirewallProduct get||shadowcopy delete</field>
              <description>Detects WMI executing suspicious commands</description>
          </rule>

          <rule id="255048" level="12">
              <if_group>sysmon_event1</if_group>
              <field name="win.eventdata.commandline">transport=dt_socket,address=</field>
              <description>Detects a JAVA process running with remote debugging allowing more than just localhost to connect</description>
          </rule>

          <rule id="255049" level="0">
              <if_group>sysmon_event1</if_group>
              <field name="win.eventdata.ParentImage">\\WINWORD.EXE</field>
              <description>Sysmon - MS Word</description>
          </rule>

          <rule id="255050" level="12">
              <if_group>sysmon_event1</if_group>
              <field name="win.eventdata.image">\\csc.exe</field>
              <description>Detects Winword starting uncommon sub process csc.exe as used in exploits</description>
          </rule>

          <rule id="255051" level="0">
              <if_group>sysmon_event1</if_group>
              <field name="win.eventdata.ParentImage">\\apache||\\tomcat||\\w3wp.exe||\\php-cgi.exe||\\nginx.exe||\\httpd.exe</field>
              <description>Sysmon - Webshell detection</description>
          </rule>

          <rule id="255052" level="0">
              <if_sid>255051</if_sid>
              <field name="win.eventdata.commandline">whoami||net user||ping -n||systeminfo</field>
              <description>Sysmon - Webshell detection</description>
          </rule>

          <rule id="255053" level="0">
              <if_group>sysmon_event1</if_group>
              <field name="win.eventdata.image">bitsadmin.exe</field>
              <description>Sysmon Bitsadmin.exe detection</description>
          </rule>

          <rule id="255054" level="12">
              <if_sid>255053</if_sid>
              <field name="win.eventdata.commandline">/transfer</field>
              <description>Detects usage of bitsadmin downloading a file</description>
          </rule>

          <rule id="254056" level="12">
              <if_sid>255000</if_sid>
              <field name="win.eventdata.commandline">AppData</field>
              <description>Detects a suspicious command line execution that includes an URL and AppData</description>
          </rule>

          <rule id="255057" level="12">
              <if_sid>255028</if_sid>
              <field name="win.eventdata.image">\\powershell.exe</field>
              <description>Processes started by MMC could by a sign of lateral movement using MMC application COM object</description>
          </rule>

          <rule id="255058" level="12">
              <if_sid>255032</if_sid>
              <field name="win.eventdata.Image">\\cmd.exe</field>
              <description>Detects suspicious powershell invocations from interpreters or unusual programs</description>
          </rule>

          <rule id="255059" level="0">
              <if_sid>184666</if_sid>
              <match>MsMpEng.exe</match>
              <description>Exclude</description>
          </rule>

          <rule id="254060" level="0">
              <if_sid>254056</if_sid>
              <match>WindowsVersionTempFile.txt</match>
              <description>Exclude</description>
          </rule>

          <rule id="255061" level="0">
              <if_sid>255025</if_sid>
              <match>timedate.cpl</match>
              <description>Exclude</description>
          </rule>
          <rule id="255062" level="0">
              <if_sid>255033</if_sid>
              <match>getfilecounts.vbs</match>
              <description>Exclude</description>
          </rule>
         <rule id="255063" level="0">
              <if_sid>255050</if_sid>
              <match>xj6r_ru4.cmdline</match>
              <description>Exclude</description>
          </rule>
         <rule id="255065" level="0">
              <if_group>sysmon_event1</if_group>
              <field name="win.eventdata.Image">conhost.exe</field>
              <description>Mimikatz Detection Parent Image $(win.eventdata.parentimage)</description>
          </rule>
         <rule id="255066" level="12">
              <if_sid>255065</if_sid>
              <field name="win.eventdata.ParentImage">mimikatz.exe</field>
              <description>Mimikatz Detection Image: $(win.eventdata.parentimage)</description>
          </rule>
         <rule id="255067" level="12">
              <if_sid>255032</if_sid>
              <field name="win.eventdata.currentDirectory">AppData</field>
              <description>Detects a suspicious command line execution that includes an URL and AppData</description>
          </rule>
         <rule id="255068" level="12">
              <if_sid>255041</if_sid>
              <field name="win.eventdata.currentDirectory">AppData</field>
              <description>Detects a suspicious command line execution that includes an URL and AppData</description>
          </rule>
      <!--
          <rule id="255069" level="12">
              <if_sid>255017</if_sid>
              <match>!172.</match>
              <description>Detects a rundll32 that communicates with public IP addresses</description>
          </rule>
          <rule id="255070" level="12">
              <if_sid>255017</if_sid>
              <match>!10.</match>
              <description>Detects a rundll32 that communicates with public IP addresses</description>
          </rule>
      -->
          <rule id="255071" level="12">
              <if_group>sysmon_event1</if_group>
              <field name="win.eventdata.commandline">AppData</field>
              <description>Detects a suspicious command line execution that includes an URL and AppData</description>
          </rule>
          
          <rule id="255072" level="12">
              <if_group>sysmon_event1</if_group>
              <field name="win.eventdata.Image">\\mshta.exe</field>
              <description>Sysmon - mshta.exe</description>
          </rule>
      </group>
    '';
  };
}
