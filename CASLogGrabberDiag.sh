#! /bin/bash
# Quick diag script to collect and package system information for analysis
# This script is not supported by Microsoft so use at your own risk

# Root Check
if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

# Make report directory
# Time in UTC, date format yyyymmdd
folderPath=/tmp/LogCollecterDiag_$(date -u +%Y%m%d_%H%M%S)
mkdir $folderPath && cd $folderPath

############################ System Info

uname -a > SysInfo.txt 
ps -e -u root --forest > RunningProc.txt #process info

############################ Network Checks

touch NetChecks.txt
urlsToCheck=(
"portal.cloudappsecurity.com"
"cdn.cloudappsecurity.com"
"adaproddiscovery.azureedge.net"
"s-microsoft.com"
"msecnd.net"
"dev.virtualearth.net"
"cloudappsecurity.com"
"flow.microsoft.com"
"static2.sharepointonline.com"
"dc.services.visualstudio.com"
"blob.core.windows.net"
)
for i in "${urlsToCheck[@]}"; do 
  if nc -dvzw1 $i 443 2>/dev/null; 
    then echo "Connection to $i succeeded" >> NetChecks.txt
    else 
      echo "Check you firewall settings to ensure that a connection to $i is permitted."
      echo "Connection to $i failed" >> NetChecks.txt # not sure if all of these should work over https...need to double check 
  fi
done

############################ Docker Specific Info 

# Grab active containers
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
    containerPath=Container${i}
    mkdir $containerPath && cd $containerPath
    docker exec -it  $i collector_status -p > ${i}Diag.txt

    docker cp $i:/var/log/adallom/ ./Logs
    docker cp $i:/etc/adallom/config/ ./ColumbusConfig/

    echo "Bringing down the syslog daemon for debugging"
    sudo docker exec $i bash -c "service 'stop rsyslog'; service 'start rsyslog-debug'"

    echo "Pausing script to collect some syslog debug info"
    sleep 5m

    echo "Reverting back to normal syslog operations"
    sudo docker exec  $i bash -c "service 'stop rsyslog-debug'; service 'start rsyslog'"
    docker cp $i:/var/log/syslog ./${i}_Syslog.txt
done

