#!/bin/bash -

# Parke
# 04/28/2026
# CSC3026: Final Project
# Description: This script is meant to be used in cybersecurity operations.
#	       It automates the following 3 tasks:
#		 Network Device Management
#		 User Management on local system
#		 Credential Management
#
#	       This script uses Whiptail to create a TUI. It uses a while true; do
#	       loop which displays a menu for the user to pick from. They can either
#	       check for new devices on their local subnet, check for new user's
#	       created on the system since the script has begun running, check a
#	       potential password for strength/complexity, or simply exit.


# BEGIN BASH syntax for block comment.
: << 'WARNING'
Whiptail sends the users input to stderr. Yes, you read that correctly: stderr, and not stdout,
which is where you pick up the user's input to consume it in the script. The way around this issue
is to reverse the redirection so that the user's input goes to stdout. Wild, I know. The reasoning
for this choice is purely technical though. Whiptail needs stdout to draw the menu itself from your
terminal. The phrase below essentially creates a backup of the current stdout file descriptor and stores
it in a custom file descriptor ('3' here). It then redirects the actual stdout to stderr, and redirects
the stderr, which is where the user input will be placed, back to our custom file descriptor, '3'.
Here is the phrase for clarity:

	3>&1 1>&2 2>&3

Explanation:

    Create a file descriptor, '3', that points to 1 (stdout)
    Redirect 1 (stdout) to 2 (stderr)
    Redirect 2 (stderr) to the custom file descriptor 3, which is pointed to stdout

You will see this used throughout the script in this manner.

WARNING
# END BASH syntax for block comment.


# SCRIPT ENTRY POINT.

# Script needs root privileges. Exit if not ran as root.
if [ "$EUID" -ne 0 ]; then
	echo "Please run script as root (use sudo)."
	exit 1
fi

# Check for required tools, exit if not installed.
for tool in arp-scan whiptail ifconfig; do
	if ! command -v "$tool" &> /dev/null; then
		echo -e "\e[31mError: $tool is not installed. Please install it to continue. The pre-reqs for this script to run are arp-scan, whiptail, and ifconfig.\e[0m"
		echo
		echo -e "\e[32mTo install all pre-reqs you can run the following command: sudo apt-get install whiptail arp-scan net-tools -y\e[0m"
		exit 1
	fi
done

# Setup logging and log file. Redirect stdout (1) and stderr (2)
# to the log file and show on screen (tee).
log_file="script_actions.log"
exec > >(tee -a "$log_file") 2>&1


######################################################################
# Function: Create new arp-scan file. Diff with previously generated #
#	    scan file, display differences/new devices connected to  #
#	    network since last check for the end user.  	     #
#								     #
# Param(s): $current_network_hosts variable so we know which hosts   #
#	    were already present from last scan. $interface_choice   #
#	    variable so we know which network to scan.		     #
#								     #
# Return: None							     #
######################################################################
scan_and_compare_network_maps() {
	# Create temporary timestamped file for next arp-scan.
	tmp_scan_file="tmp_network_hosts_$(date +'%Y-%m-%d_%H-%M-%S').txt"

	# Print info to user and run arp-scan. Store in temporary timestamped file.
	echo
	echo -e "\e[32mExecuting subsequent ARP scan & comparing results to most recent scan.\n\e[31mWarning: This can take ~30-60 seconds on an average network with a /24 subnet mask. Please wait . . .\e[0m"
	sudo arp-scan -I "$2" --localnet --retry=4 --interval=50 --backoff=1 -gx --timeout=100 | sort -Vu | cut  -f 1 > "$tmp_scan_file"

	# Run diff between the two files and grep for just the IP addresses
	# preceded by the > symbol, which represents devices that weren't present
	# in the last scan, and store in a variable.
	devices_that_joined_network=$(diff "$1" "$tmp_scan_file" | \
	grep -Po "^> [0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" | \
	cut -d '>' -f  2)

	# Run diff between the two files and grep for just the IP addresses
	# preceded by the < symbol, which represents devices that were present
	# in the last scan, but are no longer connected to the network.
	devices_that_left_network=$(diff "$1" "$tmp_scan_file" | \
	grep -Po "^< [0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" | \
	cut -d '<' -f 2)

	# Display new and past device IP's for end user. Finally, move our temporary
	# file into our original, passed as an argument to the function, to prepare
	# for the next network check the user runs.
	whiptail --title "Newly Discovered Network Devices" --msgbox "Any devices that have joined the network since the last scan are listed below. If none are listed, no new devices were found.\n\n$devices_that_joined_network\n\nAny devices that have left the network since the last scan are listed below. If none are listed, no devices left.\n\n$devices_that_left_network" 40 65 3>&1 1>&2 2>&3
	mv -f "$tmp_scan_file" "$1"
}


######################################################################
# Function: Create new user list file taken from /etc/passwd. Diff   #
#	    with previously generated user file, display differences #
#	    in user lists since last check for the end user.	     #
#                                                                    #
# Param(s): $current_user_list variable so we know which users	     #
#	    already exist  					     #
#                                                                    #
# Return: None                                                       #
######################################################################
check_for_new_users_on_system() {
	# Create temporary timestamped file for next user list check.
	# Print user list from /etc/passwd and store in file.
	tmp_user_list="tmp_user_list_$(date +'%Y-%m-%d_%H-%M-%S').txt"
	cat /etc/passwd | cut -d ':' -f 1 > "$tmp_user_list"

	# Run diff between the two files and grep for just the users who are no longer
	# present on the system, followed by the users who are new to the system. We grep
	# for the < and > symbol, respectively, to determine this.
	deleted_users_if_exist=$(diff "$tmp_user_list" "$1" | grep '>' | cut -d '>' -f 2)
	new_users_if_exist=$(diff "$tmp_user_list" "$1" | grep '<' | cut -d '<' -f 2)

	# Display new and past users, move temporary user list into original,
	# passed as an argument to the funcntion, to prepare for the next
	# check the user runs.
	whiptail --title "Newly Discovered Users" --msgbox \
	"Any new users that have been detected since the last check are listed below. If nothing is listed, no new users were found.\n\n$new_users_if_exist\n\nAny users that have been removed from the system since the last check are listed below. If none are listed, no users have been removed.\n\n$deleted_users_if_exist" \
	30 60 3>&1 1>&2 2>&3

	mv -f "$tmp_user_list" "$1"
}


########################################################################
# Function: Take potential password from user input, use Regex to      #
#	    determine if the password is strong enough for production  #
#	    use. A password is considered strong enough for production #
#	    use if it has AT LEAST the following: 1 number, 1 special  #
#	    character, 1 lowercase character, 1 uppercase character,   #
#	    and have a minimum length of 12 characters.		       #
#								       #
# Param(s): None						       #
#								       #
# Return: None							       #
########################################################################
credential_strength_checker() {
	pw=$(whiptail --title "Check Potential Password" --passwordbox "Enter a potential password you're thinking about using to check its strength!" 30 60 3>&1 1>&2 2>&3)
	pw_length="${#pw}"
	lowercase_char_found=$(echo "$pw" | grep -o '[a-z]')
	uppercase_char_found=$(echo "$pw" | grep -o '[A-Z]')
	num_found=$(echo "$pw" | grep -o '[0-9]')
	special_char_found=$(echo "$pw" | grep -o '[^A-Za-z0-9]')

	if [[ -z "$lowercase_char_found" || -z "$uppercase_char_found" || -z "$num_found" || -z "$special_char_found" || "$pw_length" -lt 12 ]]; then
		whiptail --title "Password not strong enough!" --msgbox \
		"Your potential password is not strong enough! Please do not use this in a production environment! A password is considered strong if it contains AT LEAST the following:\n\nLength Greater than 12 Characters\n1 Uppercase Character\n1 Lowercase Character\n1 Special Character\n1 Number\n\nPlease create a new password that meets these requirements before using in any system." \
		30 60 3>&1 1>&2 2>&3

	else
		whiptail --title "Strong Password!" --msgbox "The entered password meets all strength and complexity requirements. It is deemed safe to be used in a production environment :)" 30 60 3>&1 1>&2 2>&3
	fi
}


#######################################################################
# Function: Simply cleanup, display exiting message, and exit program #
#                                                                     #
# Param(s): None                                            	      #
#                                                                     #
# Return: None                                                        #
#######################################################################
exit_program() {
	echo
	echo -e "\e[32mExiting . . . Goodbye $username!\e[0m"
	exit 0
}


# Get user's preferred username
username=$(whiptail --inputbox "What is your name?" 8 39 --title "Getting to know you" 3>&1 1>&2 2>&3)

# Create variables with RegEx to determine specific devices network interfaces.
interface_option_menu_args=()
interfaces=($(ifconfig | grep -oE '^[a-z0-9]+'))
number_of_interfaces=${#interfaces[@]}

# C-Style loop through interfaces array to build proper syntax-based
# arguments for following whiptail command.
for (( i = 0 ; i < "$number_of_interfaces" ; i++ )); do
	interface_option_menu_args+=("${interfaces[$i]}" "")
done

# Get user's choice for network interface they would like to scan.
interface_choice=$(whiptail --title "Network Selection" --menu \
"Pick the interface you would like to perform an initial scan on. We have detected the following interfaces you are connected to. This initial scan will be used to determine if new devices are connected to your network later on in the script, whenever you decide to check. Please note that arp-scan may potentially error out for virtual interfaces, such as VPN or Docker interfaces, since they lack a MAC address. We recommend choosing your wireless interface or ethernet interface if you're hard wired in." \
30 60 "$number_of_interfaces" "${interface_option_menu_args[@]}" 3>&1 1>&2 2>&3)

# Run initial arp-scan command here and store
# in file for later processing with diff.
current_network_hosts="current_network_hosts_$(date +'%Y-%m-%d_%H-%M-%S').txt"
echo -e "\e[32mExecuting initial ARP scan to determine baseline of network hosts.\n\e[31mWarning: This can take ~30-60 seconds on an average network with a /24 subnet mask. Please wait . . .\e[0m"
sudo arp-scan -I "$interface_choice" --localnet --retry=4 --interval=50 --backoff=1 -gx --timeout=100 | sort -Vu | cut  -f 1 > "$current_network_hosts"

# Place initial user list, taken from /etc/passwd, into
# a variable for later comparisons to determine whether
# new users have been created or deleted since last check.
current_user_list="current_user_list_$(date +'%Y-%m-%d_%H-%M-%S').txt"
cat /etc/passwd | cut -d ':' -f 1 > "$current_user_list"

# MASTER LOOP ENTRY
while true; do

	# Main Menu. Displays options user can perform with the script.
	userchoice=$(whiptail --title "What action do you want to perform?" --menu "Choose an Option" 15 60 4 \
	"1" "Network Check" \
	"2" "User Check" \
	"3" "Password Check" \
	"4" "Exit" 3>&1 1>&2 2>&3)

	# Grab exit status from previous command
	# for input validation.
	exitstatus=$?

	# Validate user input, then run function in switch case statement
	# based on the chosen option.
	if [ "$exitstatus" = 0 ]; then
		case "$userchoice" in
			1) scan_and_compare_network_maps "$current_network_hosts" "$interface_choice" ;;
			2) check_for_new_users_on_system "$current_user_list" ;;
			3) credential_strength_checker ;;
			4) exit_program ;;
			*) echo "Invalid Selection. Please try again." ;;
		esac
	else
		echo "User canceled input."
	fi

done
