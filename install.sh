#!/bin/bash

VERSION="1.0"
BASE="/opt/vicisoc"
ENV="$BASE/vicisoc.env"

GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[1;33m"
NC="\033[0m"


ok(){
echo -e "${GREEN}[OK]${NC} $1"
}

warn(){
echo -e "${YELLOW}[WARN]${NC} $1"
}

fail(){
echo -e "${RED}[FAIL]${NC} $1"
}


pause(){
echo
read -p "Press Enter..."
}


root_check(){

if [ "$EUID" -ne 0 ]; then
echo "Run with sudo"
exit
fi

}


init(){

mkdir -p $BASE/modules
mkdir -p $BASE/logs

touch $ENV

}


status(){

clear

echo "======================================"
echo "        ViciSOC Security Console"
echo "              Version $VERSION"
echo "======================================"
echo


if [ -d /var/ossec ]; then
ok "Wazuh Agent Installed"
else
fail "Wazuh Missing"
fi


if [ -d /etc/asterisk ] || [ -d /var/www/html/vicidial ]; then
ok "Vicidial/Asterisk Detected"
else
warn "Dialer Not Detected"
fi


grep -q SLACK_WEBHOOK $ENV && \
ok "Slack Configured" || warn "Slack Not Configured"


grep -q VT_API_KEY $ENV && \
ok "VirusTotal Configured" || warn "VirusTotal Not Configured"


echo
}


system_check(){

clear

echo "========= SYSTEM CHECK ========="


hostname

uname -a

df -h /

free -h


pause

}



slack(){

clear

echo "========= SLACK CONFIGURATION ========="


if grep -q SLACK_WEBHOOK $ENV
then

echo "Slack already configured"

source $ENV

echo $SLACK_WEBHOOK

else


read -p "Enter Slack Webhook URL: " WEB


echo "SLACK_WEBHOOK=\"$WEB\"" >> $ENV


curl -s \
-X POST \
-H "Content-Type: application/json" \
-d "{\"text\":\"ViciSOC Slack Connected\"}" \
$WEB


ok "Slack Enabled"


fi


pause

}




virustotal(){

clear


echo "========= VIRUSTOTAL ========="


if grep -q VT_API_KEY $ENV

then

echo "VirusTotal already configured"

else


read -s -p "Enter VirusTotal API Key: " KEY

echo

echo "VT_API_KEY=\"$KEY\"" >> $ENV


fi


ok "Saved"


pause

}



logs(){

clear


echo "========= LOG MONITORING ========="


if [ ! -f /var/ossec/etc/ossec.conf ]
then

fail "Wazuh not installed"

pause

return

fi


cp /var/ossec/etc/ossec.conf \
/var/ossec/etc/ossec.conf.backup


cat >> /var/ossec/etc/ossec.conf <<EOF


<!-- ViciSOC Monitoring -->

<localfile>
<location>/var/log/secure</location>
<log_format>syslog</log_format>
</localfile>


<localfile>
<location>/var/log/asterisk/messages</location>
<log_format>syslog</log_format>
</localfile>


EOF


systemctl restart wazuh-agent


ok "Logs Added"


pause

}



fim(){

clear


echo "========= FILE INTEGRITY ========="


cp /var/ossec/etc/ossec.conf \
/var/ossec/etc/ossec.conf.fim.backup


cat >> /var/ossec/etc/ossec.conf <<EOF


<syscheck>

<directories realtime="yes">/etc/ssh</directories>

<directories realtime="yes">/etc/asterisk</directories>

<directories realtime="yes">/root</directories>

<directories realtime="yes">/var/www/html</directories>

</syscheck>


EOF



systemctl restart wazuh-agent


ok "FIM Enabled"


pause

}




active(){

clear


echo "========= ACTIVE RESPONSE ========="


mkdir -p /var/ossec/active-response/bin


cat > /var/ossec/active-response/bin/unblock-ip.sh <<EOF

#!/bin/bash

IP=\$1

iptables -D INPUT -s \$IP -j DROP

echo "\$(date) UNBLOCK \$IP" >> /var/ossec/logs/active-responses.log

echo "Removed block \$IP"


EOF



chmod +x /var/ossec/active-response/bin/unblock-ip.sh


ok "Unblock Script Installed"


pause

}





verify(){

clear


echo "========= VERIFY ========="


ls -l /var/ossec/etc/ossec.conf


systemctl status wazuh-agent --no-pager


pause

}





menu(){


while true

do


clear

status


echo "===================================="
echo "1  System Check"
echo "2  Slack Setup"
echo "3  VirusTotal Setup"
echo "4  Log Monitoring"
echo "5  File Integrity Monitoring"
echo "6  Active Response Tools"
echo "7  Verify Installation"
echo "0  Exit"
echo "===================================="


read -p "Select: " OP


case $OP in


1)
system_check
;;


2)
slack
;;


3)
virustotal
;;


4)
logs
;;


5)
fim
;;


6)
active
;;


7)
verify
;;


0)
exit
;;


*)
echo "Invalid"
sleep 2

;;

esac


done


}



root_check

init

menu