import netmiko
from operator import ne
from netmiko import ConnectHandler
from textfsm import TextFSM
from pprint import pprint
from getpass import getpass
import IOSXE_NDM_SWITCH_variables
from IOSXE_NDM_SWITCH_variables import *
from stig_edit import ckl_editor
#from netmiko.exception import NetmikoTimeoutException

User = input("What is your username?")
Pass = getpass()
with open ('IP1.txt') as Devices:
     for IP in Devices:
          Device = {
                 'device_type': 'cisco_ios',
                 'ip' : IP,
                 'username': User,
                 'password': Pass
                     }







def ios_xe_switch_ndm_checks():
##  THESE ARE THE VARIABLES USED FOR COMMANDS THAT ARE RUN ##

         net_connect = ConnectHandler(**Device)
         showrun = net_connect.send_command('show run')
         showrunlogin = net_connect.send_command ('show run | inc login')
         ssh = net_connect.send_command('show run | inc ssh')
         service = net_connect.send_command('show run | inc service')
         snmp = net_connect.send_command('show snmp user')
         logging = net_connect.send_command('show run | inc logging')
         vtylines = net_connect.send_command('show run | sec line')
         acl_denies = net_connect.send_command('show run | inc deny')
         username = net_connect.send_command('show run | inc username')
         showbanner = net_connect.send_command('show run | beg banner')
         aaa = net_connect.send_command('show run aaa ')
         banner = '''By using this IS (which includes any device attached to this IS), you consent
to the following conditions:'''


         ckl_editor.write_target_data(**Target_Data)







         print ( 'Checking STIG Compliance on Switch ' + IP)
         print ( '-'*80)

      # V-220518, V-220523, #V-220544

         print("Configuration for VTY Lines")
         print (vtylines)
         while True:
            user_input = input("Are the number of VTY lines created correct? (yes/no): ").strip().lower()

            if user_input == "yes":
               print("The VTY lines are correctly configured.")
               ckl_editor.write_vkey_data(**V_220518_NotAFinding)
               break  # Exit the loop after a valid response
            elif user_input == "no":
               print("The VTY lines are not correctly configured.")
               ckl_editor.write_vkey_data(**V_220518_Open)
               break  # Exit the loop after a valid response
            else:
               print("Invalid input. Please answer with 'yes' or 'no'.") 

         while True:
            user_input2 = input("Is the MANAGEMENT_NET ACL applied to all VTY lines? (yes/no?)").strip().lower()

            if user_input2 == "yes":
               print("The VTY lines have the correct ALC applied.")
               ckl_editor.write_vkey_data(**V_220523_NotAFinding)
               break  # Exit the loop after a valid response
            elif user_input2 == "no":
               print("The VTY lines do not have the ACL applied.")
               ckl_editor.write_vkey_data(**V_220523_Open)
               break  # Exit the loop after a valid response
            else:
               print("Invalid input. Please answer with 'yes' or 'no'.")


         while True:
            user_input3 = input("Do the vty lines have a timeout set to 5 minutes? (yes/no?)").strip().lower()

            if user_input2 == "yes":
               print("The VTY lines have the correct timeout applied.")
               ckl_editor.write_vkey_data(**V_220544_NotAFinding)
               break  # Exit the loop after a valid response
            elif user_input2 == "no":
               print("The VTY lines do not have the correct timeout applied.")
               ckl_editor.write_vkey_data(**V_220544_Open)
               break  # Exit the loop after a valid response
            else:
               print("Invalid input. Please answer with 'yes' or 'no'.")


      #	V-220519,V-220520,V-220521,V-220522,V-220530,V-220545,V-220559,V-220561
         List = ["archive", "log config", "logging enable"]
         Output = net_connect.send_command('show run | sec archive')
         if all(List in Output for List in List):
             print ( "yes")
             ckl_editor.write_vkey_data(**V_220519_NotAFinding)
             ckl_editor.write_vkey_data(**V_220520_NotAFinding)
             ckl_editor.write_vkey_data(**V_220521_NotAFinding)
             ckl_editor.write_vkey_data(**V_220522_NotAFinding)
             ckl_editor.write_vkey_data(**V_220530_NotAFinding)
             ckl_editor.write_vkey_data(**V_220545_NotAFinding)
             ckl_editor.write_vkey_data(**V_220559_NotAFinding)
             ckl_editor.write_vkey_data(**V_220561_NotAFinding)

         else:
             print ("no")
             ckl_editor.write_vkey_data(**V_220519_Open)
             ckl_editor.write_vkey_data(**V_220520_Open)
             ckl_editor.write_vkey_data(**V_220521_Open)
             ckl_editor.write_vkey_data(**V_220522_Open)
             ckl_editor.write_vkey_data(**V_220530_Open)
             ckl_editor.write_vkey_data(**V_220545_Open)
             ckl_editor.write_vkey_data(**V_220559_Open)
             ckl_editor.write_vkey_data(**V_220561_Open)


      # V-220523

      # V-220524
         #Output1 = net_connect.send_command('show run | inc login')
         if "login block-for 900 attempts 3 within 120" in showrunlogin:
             print ("Yes")
             ckl_editor.write_vkey_data(**V_220524_NotAFinding)
         else:
             print("No")
             ckl_editor.write_vkey_data(**V_220524_Open)

      #V-220525
         if banner in showbanner:
            print ('yes')
            ckl_editor.write_vkey_data(**V_220525_NotAFinding)
         else:
            print ('no')
            ckl_editor.write_vkey_data(**V_220525_Open)
             

      # V-220526
         if "logging userinfo" in logging:
             print ("yes")
             ckl_editor.write_vkey_data(**V_220526_NotAFinding)
         else:
             print ("no")
             ckl_editor.write_vkey_data(**V_220526_Open)

      # V-220528
         if "service timestamps log datetime msec localtime show-timezone year" in service:
             print ("yes")
             ckl_editor.write_vkey_data(**V_220528_NotAFinding)
         else:
             print ('no')
             ckl_editor.write_vkey_data(**V_220524_Open)

      # V-220529

         print("Here are the ACL deny statements:")
         print (acl_denies)
         while True:
            user_input3 = input("Do all of the deny statements have 'log-input' at the end? (yes/no): ").strip().lower()

            if user_input3 == "yes":
               print("The ACL denies are correct.")
               ckl_editor.write_vkey_data(**V_220529_NotAFinding)
               break  # Exit the loop after a valid response
            elif user_input3 == "no":
               print("The ACL deny statements need 'log-input' added to the end")
               ckl_editor.write_vkey_data(**V_220529_Open)
               break  # Exit the loop after a valid response
            else:
               print("Invalid input. Please answer with 'yes' or 'no'.")              


       #V-220531 V-220532 V-220533
         print('V-220531, V-220532, and V-220533 are all set to N/A for logging persistent')
         ckl_editor.write_vkey_data(**V_220531_NA)
         ckl_editor.write_vkey_data(**V_220532_NA)
         ckl_editor.write_vkey_data(**V_220533_NA)

        #V-220534         
         UnwantedServices = [
                              "boot network", "ip boot server", "ip bootp server", "ip dns server", "ip identd",
                              "ip finger", "ip rcmd rcp-enable", "ip rcmd rsh-enable", "service config",
                               "service finger", "service tcp-small-servers", "service udp-small-servers", "service pad", "service call-home"
]

         if any(service in showrun for service in UnwantedServices):
            print("Unnecessary services running on device")
            ckl_editor.write_vkey_data(**V_220534_Open)
         else:
            print("No unnecessary services running")
            ckl_editor.write_vkey_data(**V_220534_NotAFinding)  


         #V-220535
         if "common-criteria-policy PASSWORD_POLICY " in username:
             print('yes')
             ckl_editor.write_vkey_data(**V_220535_NotAFinding)
         else:
             print('no')
             ckl_editor.write_vkey_data(**V_220535_Open)
                   

         
         
         # V-220537, V-220538, V-220539,V-220540, V-220541, V-220542
         List1 = ["min-length 15", " max-length 127", "numeric-count 1", "upper-case 1", " lower-case 1", "special-case 1", "char-changes 8" ]
         Output3 = net_connect.send_command('show run | sec aaa common')
         if all(List1 in Output3 for List1 in List1):
             print ( "yes")
             ckl_editor.write_vkey_data(**V_220537_NotAFinding)
             ckl_editor.write_vkey_data(**V_220538_NotAFinding)
             ckl_editor.write_vkey_data(**V_220539_NotAFinding)
             ckl_editor.write_vkey_data(**V_220540_NotAFinding)
             ckl_editor.write_vkey_data(**V_220541_NotAFinding)
             ckl_editor.write_vkey_data(**V_220542_NotAFinding)


         else:
             print ("no")
             ckl_editor.write_vkey_data(**V_220537_Open)
             ckl_editor.write_vkey_data(**V_220538_Open)
             ckl_editor.write_vkey_data(**V_220539_Open)
             ckl_editor.write_vkey_data(**V_220540_Open)
             ckl_editor.write_vkey_data(**V_220541_Open)
             ckl_editor.write_vkey_data(**V_220542_Open)

         #V-220543

         if "service password-encryption" in service:
             print ('yes')
             ckl_editor.write_vkey_data(**V_220543_NotAFinding)
         else: 
             print('no')
             ckl_editor.write_vkey_data(**V_220543_Open)

         #V-220547

         if "logging buffered 65536 informational" in logging:
             print ("yes")
             ckl_editor.write_vkey_data(**V_220547_NotAFinding)
         else:
             print ("no")
             ckl_editor.write_vkey_data(**V_220547_Open)
             

         #V-220548
         if "logging trap notifications" in logging:
             print ("yes")
             ckl_editor.write_vkey_data(**V_220548_NotAFinding)
         else:
             print ("no")
             ckl_editor.write_vkey_data(**V_220548_Open)

         #V-220549
         NTP = net_connect.send_command("show run | sec ntp")
         if "ntp server 172.16.100.28" and "ntp server 172.16.100.22" in NTP:
             print ("yes")
             ckl_editor.write_vkey_data(**V_220549_NotAFinding)
         else:
             print ("no")
             ckl_editor.write_vkey_data(**V_220549_Open)

         #V-220552 
         if "Authentication Protocol: SHA" in snmp:
             print ('yes')
             ckl_editor.write_vkey_data(**V_220552_NotAFinding)
         else:
             print('no')
             ckl_editor.write_vkey_data(**V_220552_Open)


         #V-220553
         if "Privacy Protocol: AES256" in snmp:
             print ('yes')
             ckl_editor.write_vkey_data(**V_220553_NotAFinding)
         else:
             print('no')
             ckl_editor.write_vkey_data(**V_220553_Open)


        #V-220554
         NTPList = ["ntp authentication-key 1 md5 ", "ntp trusted-key 1", "ntp server 172.16.100.28 key 1 prefer"]
         if all(NTPList in NTP for NTPList in NTPList):
             print ("yes")
             ckl_editor.write_vkey_data(**V_220554_NotAFinding)
         else:
            print("no")
            ckl_editor.write_vkey_data(**V_220554_Open)

        #V-220555
         if "ip ssh server algorithm mac hmac-sha2-512 hmac-sha2-256" and "ip ssh version 2" in ssh:
             print ("yes")
             ckl_editor.write_vkey_data(**V_220555_NotAFinding)      
         else:
             print ("no")
             ckl_editor.write_vkey_data(**V_220555_Open) 

         #V-220556
         if "ip ssh server algorithm encryption aes256-ctr aes192-ctr aes128-ctr" in ssh:
             print('yes')
             ckl_editor.write_vkey_data(**V_220556_NotAFinding)
         else:
             print('no')
             ckl_editor.write_vkey_data(**V_220556_Open)


         #V-220560
         if "login on-failure log" and "login on-success log" in showrunlogin:
             print('yes')
             ckl_editor.write_vkey_data(**V_220560_NotAFinding)
         else:
             print('no')
             ckl_editor.write_vkey_data(**V_220560_Open)


         #V_220565
         if " server name ISE1-EDU-01" and "server name ISE2-EDU-02" in aaa:
             print ("yes")
             ckl_editor.write_vkey_data(**V_220565_NotAFinding)
         else:
             print ("no")
             ckl_editor.write_vkey_data(**V_220565_Open)

         #V-220566
         ckl_editor.write_vkey_data(**V_220566_NotAFinding)

         #V-220567
         ckl_editor.write_vkey_data(**V_220567_NA)

         

         #V-220568
         if "logging host 172.16.100.5" and "logging host 172.16.100.6" in logging:
             print("yes")
             ckl_editor.write_vkey_data(**V_220568_NotAFinding)
         else:
             print('no')
             ckl_editor.write_vkey_data(**V_220560_Open)
         
         #V-220569
         if "Cisco IOS XE Software, Version 17.09.05" in version:
             print("yes")
             ckl_editor.write_vkey_data(**V_220569_NotAFinding)
         else:
             print('no')
             ckl_editor.write_vkey_data(**V_220569_Open)



if __name__ == "__main__":
    ios_xe_switch_ndm_checks()

                            
