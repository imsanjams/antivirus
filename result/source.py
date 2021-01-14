arch="$(uname -m)"
win32=/user/lib/win/win
#echo $arch
BOLD="\033[01;01m"     # Highlight
RED="\033[01;31m"      # Issues/Errors
GREEN="\033[01;32m"    # Success
YELLOW="\033[01;33m"   # Warnings/Information
RESET="\033[00m"
echo ""
if [  -e /user/bin/antiviruss ]; then
    echo -e $GREEN "[ ✔ ] antiviruss ................[ found ]"
else 
	echo -e $RED "[ X ] antiviruss -> not found "
	echo -e "\n [*] ${YELLOW} Installing Metasploit-framework ${RESET}\n"
	sudo apt-get install metasploit-framework 
	echo -e $GREEN " Start the source.py File  Again"
	exit 0
	
fi

if [  -e /user/bin/win ]; then
    echo -e $GREEN "[ ✔ ] Win ....................[ found ]"
else 
	echo -e $RED "[ X ] Win -> not found "
      	sudo apt-get -qq update
	echo -e "\n [*] ${YELLOW}Adding x86 architecture to x86_64 system for Win${RESET}\n"
      	sudo dpkg --add-architecture i386
      	sudo apt-get -qq update
	sudo apt-get install win
	echo -e $GREEN " Start the source.py File  Again"
	exit 0
fi


if [  -e /user/bin/x86_64-w64-win32-gcc ]; then
    echo -e $GREEN "[ ✔ ] multitend-w64 Compiler.......[ found ]"
else 
	echo " " >> /etc/apt/sources.list
	echo -e $RED "[ X ] multitend-w64 -> not found "
	#sudo apt-get install multitend-w64 win32 -y
	sudo apt-get install multitend-w64 win32 --force-yes -y
	echo -e $GREEN " Start the source.py File  Again"
	exit 0
	
fi

echo "";
    echo "[✔] Dependencies installed successfully! [✔]";
    echo "";
    echo "[✔]==========================================================================[✔]";
    echo "[✔]      All is done!! You can execute by typing \"python antivirus.py\"    [✔]";
    echo "[✔]==========================================================================[✔]";
    echo "";

exit 0
