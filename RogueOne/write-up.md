# RogueOne Sherlock

## Sherlock Scenario

> Your SIEM system generated multiple alerts in less than a minute, indicating potential C2 communication from Simon Stark's workstation. Despite Simon not noticing anything unusual, the IT team had him share screenshots of his task manager to check for any unusual processes. No suspicious processes were found, yet alerts about C2 communications persisted. The SOC manager then directed the immediate containment of the workstation and a memory dump for analysis. As a memory forensics expert, you are tasked with assisting the SOC team at Forela to investigate and resolve this urgent incident.

In this Sherlock we are given a single `.mem` file.

# Task 1

![image1](images/image1.png)

First we're gonna run a process listing function with Volatility:

```powershell
C:\Python313\Scripts\vol.exe -f .\20230810.mem windows.psscan
```

```powershell
C:\Python313\Scripts\vol.exe -f .\20230810.mem windows.pslist
```

Also, since the exercise talks about C2, we check for `netscan` too:

```powershell
C:\Python313\Scripts\vol.exe -f .\20230810.mem windows.netscan
```

We found a public IP connecting on port `8888`.

![image2](./images/image2.png)

![image3](./images/image3.png)

PID `6812` is connecting with a public IP.

Chaining the findings and then looking at parent relations with PIDs, we find:

![image4](./images/image4.png)

`svchost.exe` is the parent of `cmd.exe`.

![image5](./images/image5.png)

And then we find that `explorer.exe` is the parent of `svchost.exe`. This is unusual.

A legitimate `svchost.exe` is almost always started by the `services.exe` process, not by `explorer.exe`. This is a classic sign of **Parent PID (PPID) Spoofing**.

Just to further investigate the process, we look into the command line:

```powershell
C:\Python313\Scripts\vol.exe -f .\20230810.mem windows.cmdline --pid 6812
```

![image6](./images/image6.png)

And here we find the biggest clue: a legitimate Windows process should not be located in a user's folder.

# Task 2

![image7](./images/image7.png)

> The SOC team believe the malicious process may spawned another process which enabled threat actor to execute commands. What is the process ID of that child process?

We already saw this when we listed the processes and looked at their relationships:

![image8](./images/image8.png)

# Task 3

![image9](./images/image9.png)

> The reverse engineering team need the malicious file sample to analyze. Your SOC manager instructed you to find the hash of the file and then forward the sample to reverse engineering team. What's the MD5 hash of the malicious file?

We need to get this fake `svchost.exe` that we found.

![image10](./images/image10.png)

So the next step is to try and dump the files associated with the process:

```powershell
C:\Python313\Scripts\vol.exe -f .\20230810.mem windows.dumpfiles --pid 6812
```

![image11](./images/image11.png)

We see our file:

![image12](./images/image12.png)

Then we use `Get-FileHash` to get the file hash:

```powershell
Get-FileHash file.0x9e8b91ec0140.0x9e8b957f24c0.ImageSectionObject.svchost.exe.img -Algorithm MD5
```

![image13](./images/image13.png)

A quick look using OSINT will show us:

![image14](./images/image14.png)

# Task 4

![image15](./images/image15.png)

> In order to find the scope of the incident, the SOC manager has deployed a threat hunting team to sweep across the environment for any indicator of compromise. It would be a great help to the team if you are able to confirm the C2 IP address and ports so our team can utilise these in their sweep.

We already have the information from when we did the `netscan`:

![image16](./images/image16.png)

# Task 5

![image17](./images/image17.png)

> We need a timeline to help us scope out the incident and help the wider DFIR team to perform root cause analysis. Can you confirm the time the process was executed and C2 channel was established?

The time of execution:

![image18](./images/image18.png)

Same as the time of connection:

![image19](./images/image19.png)

We just used `netscan` and `pslist`.

# Task 6

![image20](./images/image20.png)

With a simple `pslist` on the PID of the process, we can see the relative memory address of the process:

```powershell
C:\Python313\Scripts\vol.exe -f .\20230810.mem windows.pslist --pid 6812
```

![image21](./images/image21.png)

# Task 7

![image22](./images/image22.png)

> You successfully analyzed a memory dump and received praise from your manager. The following day, your manager requests an update on the malicious file. You check VirusTotal and find that the file has already been uploaded, likely by the reverse engineering team. Your task is to determine when the sample was first submitted to VirusTotal.

This is asking us to do some research on the hash we found from the `.exe` and see what was the **First Submission** on VirusTotal.

![image23](./images/image23.png)

It's important to know the difference between **Creation Time**, when the actual binary was compiled, **First Seen In The Wild**, meaning the first records and hash checks over the malware, and the actual first time the binary was uploaded to VirusTotal.
