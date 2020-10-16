#Background
This script seeks to save on time and make both the customer's and our workflow more efficient by automating the collection of logs and information relevant to troubleshooting Log Collector Containers running on **LINUX** servers. Very little background in the Linux Command Line is necessary to be able to effectively execute this script the important things to know are:

wget - A web download utility that fetches file from a specified URL
chmod - Modify permissions on a file
sudo  - Execute a command as the system administrator, or root in the Linux world.

First we will download the script from a shared, internet accessible location. By doing things in this manner we can remove the need for the customer to work through DTM to access the script and transfer it over to the Linux server. This script contains no IP and leverages utilities already found on Linux computers. 

Next we will set the permissions on the downloaded file so that we can execute it. The important thing to note is the chmod command which will be required to modify the permission set. The Linux permission system is set up in such a way that a user, group, and everyone can be assigned specific permissions. In our case, the permissions will be represented by 755, or rwxr-xr-x. This enables the script to be executed on the host machine. 

Finally we will run the command with elevated permissions using the sudo command. This is required as the docker service is run by a system-level account. 

Once the diag script is complete, the customer will have a tar.gz file which they will need to provide to support engineers through DTM. Once received, we will need to unpack the tarball through whatever your preferred shell is (CMD, PoSH, or WSL).

The extracted file will contain a few files and folders. The details of such are annotated below:

File Name - LogGrabberDiag_DateTime
- Container<ContainerIDs>
    - Logs
        - columbus
            - log-archive
                - various rotated logs
            - dbwrites.log
            - events.log
            - info.log
            - trace.log
            - error.log
            - headers.log
        - columbusInstaller
            - dbwrites.log
            - events.log
            - info.log
            - trace.log
            - error.log
            - headers.log
    - ColumbusConfig
        - columbusInstaller.cfg
        - columbusUser.cfg
    - <ContainerID>Diag.txt - output of collector_status command
    - <ContainerID>_Syslog.txt - Syslog debug log
- SysInfo.txt - Operating system information
- RunningProc.txt - Processes on the system at script run time
- NetChecks.txt - Output of checks to various azure resources. 
- DNSConfig.txt - Contents of DNS configuration of host machine. 
- DockerInfo.txt - Docker Version Info
- HostInfo.txt - List of currently running LogGrabber Containers
- HostNetworkInfo.txt - Docker host networking info
- FirewallConfig.txt - Output of firewall rules
- InstalledPackages.txt - List of installed applications on a linux server.


#Step-By-Step

1. Have the customer copy the following command and enter into the terminal or ssh session of their linux server hosting docker:

        wget -O CASLogGrabberDiag.sh https://raw.githubusercontent.com/iamchristmas/tools/master/CASLogGrabberDiag.sh

2. Change file permissions to allow for execution

        chmod -R a+x CASLogGrabberDiag.sh

3. Execute the script

        sudo ./CASLogGrabberDiag.sh

4. Allow the script to run. Should take ~1 minute to complete to allow for the collection of Syslog debug data.
5. User will now have a tarball located in the /tmp/ directory of their Linux server. Have them transfer it from their host computer using WinSCP or the SCP command line utility.

        scp <user>@<ip/hostname of linux server>:/tmp/LogGrabberDiag_<DateTime> .

6. Download the file to your computer for analysis.
7. Extract the files

        tar -zxf  LogGrabberDiag_<DateTime>

#Reference

https://dev.azure.com/SupportabilityWork/Azure%20Security/_wiki/wikis/Cloud%20App%20Security%20wiki/1980/HOW-TO-Log-Collector-Diagnostic-Script