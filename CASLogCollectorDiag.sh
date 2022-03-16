#! /bin/bash
# Written by Christopher Smith squire of the shell and keeper of the scrolls
# Quick diag script to collect and package system information for analysis
# This script is not supported by Microsoft so use at your own risk

# Root Check
if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

OS=`cat /etc/os-release | grep PRETTY_NAME | sed -n 's/.*\(SUSE\|Ubuntu\|Red Hat\|CentOS\).*/\1/p'`

# Make report directory
# Time in UTC, date format yyyymmdd
folderPath=/tmp/
fileName=LogCollecterDiag_$(date -u +%Y%m%d_%H%M)
mkdir $folderPath$fileName && cd $folderPath$fileName

############################ System Info

uname -a > SysInfo.txt 
ps -e -u root --forest > RunningProc.txt #process info

#Grab installed packages
if [ "${OS,,}" == "ubuntu" ]; then
    apt list --installed > InstalledPackages.txt
elif [ "${OS,,}" == "red hat" ]; then
    yum list installed || dnf list installed > InstalledPackages.txt
elif [ "${OS,,}" == "centos" ]; then
    dnf list installed > InstalledPackages.txt
elif [ "${OS,,}" == "suse" ]; then
    zypper se --installed-only > InstalledPackages.txt
fi

############################ End system info
############################ Network Checks

#Pull the DNS config
cp /etc/resolv.conf ./DNSConfig.txt

# FIREWALL inspection
if [ "${OS,,}" == "ubuntu" ]; then
    ufw status verbose > FirewallConfig.txt
elif [ "${OS,,}" == "red hat" ]; then
    firewall-cmd --list-all > FirewallConfig.txt
elif [ "${OS,,}" == "centos" ]; then
    firewall-cmd --list-all > FirewallConfig.txt
elif [ "${OS,,}" == "suse" ]; then
    iptables -L INPUT > FirewallConfig.txt
fi

#resource url checks
touch NetChecks.txt
urlsToCheck=(
"portal.cloudappsecurity.com"
"cdn.cloudappsecurity.com"
"adaproddiscovery.azureedge.net"
"dev.virtualearth.net"
"cloudappsecurity.com"
"flow.microsoft.com"
"static2.sharepointonline.com"
"dc.services.visualstudio.com"
"adaprodconsole.blob.core.windows.net"
"prod03use2console1.blob.core.windows.net"
"prod5usw2console1.blob.core.windows.net"
"prod02euwconsole1.blob.core.windows.net"
"prod4uksconsole1.blob.core.windows.net"
)
for i in "${urlsToCheck[@]}"; do 
  if nc -dvzw1 $i 443 2>/dev/null; 
    then echo "Connection to $i succeeded" >> NetChecks.txt
    else 
      echo "Unable to connect. Netcat may not be present. Check your firewall settings to ensure that a connection to $i is permitted."
      echo "Connection to $i failed" >> NetChecks.txt 
  fi
done

#Cert validation check
ocspUrls=(
"crl3.digicert.com"
"crl4.digicert.com"
"ocsp.digicert.com"
"www.d-trust.net"
"root-c3-ca2-2009.ocsp.d-trust.net"
"crl.microsoft.com"
"oneocsp.microsoft.com"
"ocsp.msocsp.com"
"www.microsoft.com/pkiops"
)
for i in "${ocspUrls[@]}"; do
  if curl -v $i 2>&1 | grep 'Connection refused'; then #Just checking for connectivity to the endpoint!
    echo "Error connecting to ocsp provider ${i}" >> NetChecks.txt
    else echo "Connection to $i succeeded" >> NetChecks.txt
  fi
done

############################ End Network Checks
############################ Docker Specific Info 

#TODO: Impelement logic to handle docker on snapd

echo "Grabbing some container information..."

docker version >> DockerInfo.txt

containerIDs=()
for i in $(sudo docker ps -a -f "ancestor=mcr.microsoft.com/mcas/logcollector" -f status=running --format "{{.ID}}")  
  do containerIDs+=($i)
done

docker ps -a -f "ancestor=mcr.microsoft.com/mcas/logcollector" -f status=running --format "table {{.Names}}\t{{.Ports}}\t{{.Mounts}}\t{{.Networks}}" > HostInfo.txt

#Grab host docker networking info
docker network ls --filter "driver=bridge" > HostNetworkInfo.txt
docker network inspect bridge > HostNetworkInfo.txt

# Grab Collector Status from containers
for i in "${containerIDs[@]}" 
do
    cd $folderPath$fileName # return to base directory 
    containerPath=Container${i}
    mkdir $containerPath && cd $containerPath
    sudo docker exec -it  $i collector_status -p > ${i}Diag.txt

    docker cp $i:/var/log/adallom/ ./Logs
    docker cp $i:/etc/adallom/config/ ./ColumbusConfig/

    echo "Bringing down the syslog daemon for debugging"
    sudo docker exec $i bash -c "service 'stop rsyslog'; service 'start rsyslog-debug'"

    echo "Pausing script to collect some syslog debug info"
    sleep 1m

    echo "Reverting back to normal syslog operations"
    sudo docker exec  $i bash -c "service 'stop rsyslog-debug'; service 'start rsyslog'"
    docker cp $i:/var/log/syslog.debug ./${i}_Syslog.txt
done

############################ End Docker

tar -czf /tmp/$fileName.tar.gz $folderPath$fileName

echo "Archive created for engineer."
echo "File path: $folderPath$fileName.tar.gz"

##TODO: Generate the SCP command for the customer