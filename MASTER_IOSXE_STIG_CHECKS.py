import netmiko
from operator import ne
from netmiko import ConnectHandler
from textfsm import TextFSM
from pprint import pprint
from getpass import getpass
#from netmiko.exception import NetmikoTimeoutException
import re

#User = input("What is your username?")
#Pass = getpass()
with open ('IP.txt') as Devices:
     for IPs in Devices:
         Device = {
                 'device_type': 'cisco_ios',
                 'ip' : IPs,
                 'username': 'User',
                 'password': "Pass"
                     }





##  THESE ARE THE VARIABLES USED FOR COMMANDS THAT ARE RUN ##
         net_connect = ConnectHandler(**Device)
         showrun = net_connect.send_command('show run')
         showruninterface = net_connect.send_command('show run | sec int')
         showint = net_connect.send_command('show interfaces status')
         vtp = net_connect.send_command ('show vtp status', use_textfsm=True)
         dhcp = net_connect.send_command("show run | inc dhcp")
         ssh = net_connect.send_command('show run | inc ssh')
         service = net_connect.send_command('show run | inc service')
         snmp = net_connect.send_command('show snmp user')
         login = net_connect.send_command('show run | inc login')
         vtylines = net_connect.send_command('show run | sec line')
         deny = net_connect.send_command('show run | inc deny')
         NTP = net_connect.send_command("show run | sec ntp")
         username = net_connect.send_command('show run | inc username')
         showbanner = net_connect.send_command('show run | beg banner')
         aaa = net_connect.send_command('show run aaa ')
         spanningtree= net_connect.send_command("show run | inc spanning")
         sourceguard = net_connect.send_command("show run | inc source")
         arp = net_connect.send_command("show run | inc arp")
         stormcontrol = net_connect.send_command("show run | inc storm")
         udld = net_connect.send_command("show run | inc udld")
         negotiation = net_connect.send_command("show int switchport | inc Negotiation")
         interfacestatus = net_connect.send_command("show int status")
         showinttrunk = net_connect.send_command("show int trunk")
         vlans = net_connect.send_command("show vlan br", use_textfsm= True)
         nativevlan = net_connect.send_command("show run | inc native")
         stormstrings = ["storm-control action shutdown",
                        "storm-control broadcast level 100.00",
                        "storm-control multicast level 100.00",
                        "storm-control unicast level 100.00"]
         
         aaastrings = ["authentication order mab dot1x",
                      "authentication priority mab dot1x",
                      "mab",
                      "aaa group server radius ISE-RADIUS",
                      "server name ISE1-EDU-01",
                      "server name ISE2-EDU-02" ]
         
         Archive = net_connect.send_command('show run | sec archive')
         PasswordPolicy = net_connect.send_command('show run | sec PASSWORD_POLICY')
         showrunlogin = net_connect.send_command ('show run | inc login')
         service = net_connect.send_command('show run | inc service')
         snmp = net_connect.send_command('show snmp user')
         logging = net_connect.send_command('show run | inc logging')
         vtylines = net_connect.send_command('show run | sec line')
         acl_denies = net_connect.send_command('show run | inc deny')
         username = net_connect.send_command('show run | inc username')
         showbanner = net_connect.send_command('show run | beg banner')
         aaa = net_connect.send_command('show run aaa ')
         version = net_connect.send_command('show version')
         banner = '''By using this IS (which includes any device attached to this IS), you consent
to the following conditions:'''

         report = []
         all_access_compliant = True   







         print('Checking STIG Compliance on Switch ' + IPs)
         print('-'*80)

 
      #V-220649
         if all(list in showrun for list in aaastrings):
            print("V-220649 is not a finding.")
         else:
            print("V-220649 is an open finding. configure aaa")  

       # V-220650
 
         for i in vtp:
             if i["mode"] == 'Off':
                 print("V-220650 is not a finding")
             else:
                 print("V-220650 is open. Please set VTP mode to off")


      #V-220651
        # if "class-map" in showrun and "policy-map" in showrun:
        #      print("V-220651 is not a finding")
         #else:
         #     print("V-220651 is an open finding. Please configure Qos")

         print("V-220651 is open, no QoS configured. No voice or video traffic, so we feel it is not needed.")

    #V-220655
         if "spanning-tree guard root" in spanningtree:
              print("V-220655 is not a finding")
         else:
              print("V-220655 is an open finding. Please configure root guard")

    #V-220656
         if "spanning-tree bpduguard enable" in spanningtree:
              print("V-220656 is not a finding")
         else:
              print("V-220656 is an open finding. Please configure BPDU guard")

    #V-220657
         if "spanning-tree loopguard default" in spanningtree:
              print("V-220657 is not a finding")
         else:
              print("V-220657 is an open finding. Please configure loopguard")
 
    #V-220658
         if "switchport block unicast" in showrun:
              print("V-220658 is not a finding")
         else:
              print("V-220658 is an open finding. Please configure Unknown Unicast Flood Blocking (UUFB)")
 
    #V-220659  
         if "ip dhcp snooping" and "ip dhcp snooping vlan 556,565" in dhcp:
              print("V-220659 is not a finding")
         else:
              print("V-220659 is an open finding. Please configure DHCP snooping for all user VLANs")

    #V-220660
         for port in range(1, 49):
            interface = f"GigabitEthernet1/0/{port}"
            # Regex to find the interface block in the config
            interface_block_pattern = rf"interface {interface}\n(.*?)(?=\ninterface|\n!|\Z)"
            interface_block_match = re.search(interface_block_pattern, showrun, re.DOTALL)

            if not interface_block_match:
                report.append(f"{interface}: Not found or not configured")
                continue

            interface_config = interface_block_match.group(1)

            # Check if the interface is in access mode
            is_access = "switchport mode access" in interface_config

            if is_access:
                # Check for ip verify source
                has_ip_verify = "ip verify source" in interface_config
                if has_ip_verify:
                    report.append(f"{interface}: Compliant (Access mode, ip verify source configured)")
                else:
                    all_access_compliant = False
                    report.append(f"{interface}: Non-compliant (Access mode, ip verify source not configured)")
            else:
                report.append(f"{interface}: Skipped (Not in access mode)")
         print("V-220660 is not a finding" if all_access_compliant else "V-220660 is an Open Finding \nPlease configure IP source guard on all access ports.")
              
    #V-220661
         if "ip arp inspection vlan 556,565" in arp:
              print("V-220661 is not a finding")
         else:
              print("V-220661 is an open finding. Please configure ARP inspection for all user vlans")

    #V-220662
         for port in range(1, 49):
            interface = f"GigabitEthernet1/0/{port}"
            # Regex to find the interface block in the config
            interface_block_pattern = rf"interface {interface}\n(.*?)(?=\ninterface|\n!|\Z)"
            interface_block_match = re.search(interface_block_pattern, showrun, re.DOTALL)

            if not interface_block_match:
                report.append(f"{interface}: Not found or not configured")
                continue

            interface_config = interface_block_match.group(1)

            # Check if the interface is in access mode
            is_access = "switchport mode access" in interface_config

            if is_access:
                # Check for ip verify source
                has_storm_control = all(stormstring in interface_config for stormstring in stormstrings)
                if has_storm_control:
                    report.append(f"{interface}: Compliant (Access mode, Storm Control configured)")
                else:
                    all_access_compliant = False
                    report.append(f"{interface}: Non-compliant (Please configure storm control on access ports)")
            else:
                report.append(f"{interface}: Skipped (Not in access mode)")

         # Disconnect from the device
         net_connect.disconnect()

         # Print the report
 #       print(f"\nInterface Compliance Report for {IPs.strip()}:")
 #       print("-" * 50)
 #       for line in report:
 #           print(line)
 #       print("-" * 50)
         print("V-220662 is not a finding" if all_access_compliant else "V-220662 is an Open Finding \nPlease configure Storm Control on all access ports.")

    #V-220663
         if "no ip igmp snooping" in showrun:
              print("V-220663 is an open finding. Please reeanble ip igmp snooping.")
         else:
              print("V-220663 is not a finding")

    #V-220664
         if "spanning-tree mode rapid-pvst" in spanningtree:
              print("V-220664 is not a finding")
         else:
              print("V-220664 is an open finding. Please ensure you are running spanning-tree mode rapid-pvst")

    #V-220665
         if "udld enable" in udld:
              print("V-220665 is not a finding")
         else:
              print("V-220665 is an open finding. Please configure UDLD")

    #V-220666
         if 'Negotiation of Trunking: On' in negotiation:
            print ('V-220666 is an open finding. Please disable all trunk negotiations.')
         else:
            print ('V-220666 is not a finding')
    
    #V-220667
         for port in range(1, 49):
            interface = f"GigabitEthernet1/0/{port}"
            # Regex to find the interface block in the config
            interface_block_pattern = rf"interface {interface}\n(.*?)(?=\ninterface|\n!|\Z)"
            interface_block_match = re.search(interface_block_pattern, showrun, re.DOTALL)

            if not interface_block_match:
                report.append(f"{interface}: Not found or not configured")
                continue

            interface_config = interface_block_match.group(1)

            # Check if the interface is in access mode
            is_disabled = is_disabled = bool(re.search(r"^\s*shutdown\s*$", interface_config, re.MULTILINE))

            if is_disabled:
                has_vlan_999 = "switchport access vlan 999" in interface_config
                if has_vlan_999:
                    report.append(f"{interface}: Compliant (Access mode, ip verify source configured)")
                else:
                    all_access_compliant = False
                    report.append(f"{interface}: Non-compliant (Access mode, ip verify source not configured)")
            else:
                report.append(f"{interface}: Skipped (Not in access mode)")
         print("V-220667 is not a finding" if all_access_compliant else "V-220667 is an Open Finding \nPlease configure all disabled access ports to be in vlan 999.")


#V-220668
         
         vlan1_compliant = True
         vlan1_ports = []

# Parse the output
         lines = showint.strip().split('\n')
         for line in lines:
                # Match interface lines with flexible spacing (e.g., "Gi1/0/24 notconnect 1 auto auto 10/100/1000BaseTX")
                match = re.match(r'^(Gi\d+/\d+/\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+.*$', line)
                if match:
                    port, status, vlan, duplex, speed = match.groups()
                    if vlan == '1':  # Check if VLAN is 1
                        vlan1_compliant = False
                        vlan1_ports.append(port)
                        report.append(f"Port {port}: Non-compliant (assigned to VLAN 1, Status: {status})")

                if not vlan1_ports:
                 report.append("No ports assigned to VLAN 1")

                # Print the report
                print(f"\nVLAN 1 Compliance Report for {IPs.strip()}:")
                print("-" * 50)
                for line in report:
                 print(line)
                print("-" * 50)
                print("V-220668 is not a finding." if vlan1_compliant 
                    else "V-220668 is an open finding. Please ensure no ports are assigned to VLAN 1.")



    #V-220669
         print(showinttrunk)
         while True:
            Trunk = input("Is VLAN 1 pruned from all trunks? yes/no")

            if Trunk == "yes":
               print("V-220667 is not a finding")
               break  
            elif status2 == "yes":
               print("V-220667 is an open finding. Please ensure VLAN 1 is pruned from all trunks.")
               break  # Exit the loop after a valid response
            else:
               print("Invalid input. Please answer with 'yes' or 'no'.")


    #V-220670
         def check_vlans(vlans):
            for i in vlans:
                if i["vlan_id"] == "300" and i["vlan_name"] == "EDU-NMGMT":
                        return True
            return False

         if check_vlans(vlans):
            print("V-220670 is not a finding")
         else:
            print("V-220670 is an open finding")

    #V-220671
         print(interfacestatus)
         while True:
            Intstatus = input("Are there any user facing ports set to trunk? yes/no")

            if Intstatus == "no":
               print("V-220671 is not a finding")
               break  
            elif Intstatus == "yes":
               print("V-220671 is an open finding. Please ensure all user facing ports are access ports.")
               break  # Exit the loop after a valid response
            else:
               print("Invalid input. Please answer with 'yes' or 'no'.")


     #V-220672
         report = []
         all_trunks_compliant = True
         non_compliant_ports = []

        # Parse the output for trunk ports
         lines = showinttrunk.strip().split('\n')
         for line in lines:
            # Match lines with trunk port details (e.g., "Te1/1/1 on 802.1q trunking 333")
            match = re.match(r'^(\S+)\s+\S+\s+\S+\s+\S+\s+(\d+)$', line)
            if match:
                port, native_vlan = match.groups()
                if native_vlan == '1':  # Check if native VLAN is 1
                    all_trunks_compliant = False
                    non_compliant_ports.append(port)
                    report.append(f"Port {port}: Non-compliant (Native VLAN is 1)")
                else:
                    report.append(f"Port {port}: Compliant (Native VLAN is {native_vlan})")

         if not non_compliant_ports and not any(re.match(r'^\S+\s+\S+\s+\S+\s+\S+\s+\d+$', line) for line in lines):
            report.append("No trunk ports found")


        # Print the report
         print(f"\nNative VLAN Compliance Report for {IPs.strip()}:")
         print("-" * 50)
         for line in report:
                print(line)
         print("-" * 50)
         print("V-220672 is not a finding" if all_trunks_compliant 
                    else "V-220672 is an open finding. Please change native VLAN from 1 to another VLAN.")
         

             #V-220673
         while True:
            Intstatus2 = input("Are any of the ports assigned to the native vlan, 333? yes/no")

            if Intstatus2 == "no":
               print("V-220671 is not a finding")
               break  
            elif Intstatus2 == "yes":
               print("V-220671 is an open finding. Please ensure all user facing ports are access ports.")
               break  # Exit the loop after a valid response
            else:
               print("Invalid input. Please answer with 'yes' or 'no'.")

             # V-220518, V-220523, #V-220544

         print("Configuration for VTY Lines")
         print (vtylines)
         while True:
            user_input = input("Are the number of VTY lines created correct? (yes/no): ").strip().lower()

            if user_input == "yes":
               print("The VTY lines are correctly configured.")
               break  # Exit the loop after a valid response
            elif user_input == "no":
               print("The VTY lines are not correctly configured.")
               break  # Exit the loop after a valid response
            else:
               print("Invalid input. Please answer with 'yes' or 'no'.") 

         while True:
            user_input2 = input("Is the MANAGEMENT_NET ACL applied to all VTY lines? (yes/no?)").strip().lower()

            if user_input2 == "yes":
               print("The VTY lines have the correct ALC applied.")
               break  # Exit the loop after a valid response
            elif user_input2 == "no":
               print("The VTY lines do not have the ACL applied.")
               break  # Exit the loop after a valid response
            else:
               print("Invalid input. Please answer with 'yes' or 'no'.")


         while True:
            user_input3 = input("Do the vty lines have a timeout set to 5 minutes? (yes/no?)").strip().lower()

            if user_input2 == "yes":
               print("The VTY lines have the correct timeout applied.")
               break  # Exit the loop after a valid response
            elif user_input2 == "no":
               print("The VTY lines do not have the correct timeout applied.")
               break  # Exit the loop after a valid response
            else:
               print("Invalid input. Please answer with 'yes' or 'no'.")


      #	V-220519,V-220520,V-220521,V-220522,V-220530,V-220545,V-220559,V-220561
         List = ["archive", "log config", "logging enable"]
         if all(List in Archive for List in List):
             print ( "V-220519 is not a finding.")

         else:
             print ("V-220519 is an open finding.")

         #V-220520
         List = ["archive", "log config", "logging enable"]
         if all(List in Archive for List in List):
             print ( "V-220520 is not a finding")

         else:
             print ("V-220520 is an open finding.")

         #V-220521
         List = ["archive", "log config", "logging enable"]
         if all(List in Archive for List in List):
             print ( "V-220521 is not a finding")

         else:
             print ("V-220521 is an open finding.")    

         #V-220522
         List = ["archive", "log config", "logging enable"]
         if all(List in Archive for List in List):
             print ( "V-220522 is not a finding")

         else:
             print ("V-220522 is an open finding.")    


      # V-220523

      # V-220524
         if "login block-for 900 attempts 3 within 120" in login:
             print ("V-220524 is not a finding")
         else:
             print("V-220524 is an open finding. Please configure login block-for 900 attempts 3 within 120")

      #V-220525
         if banner in showbanner:
            print ('yes')
         else:
            print ('no')
             

      # V-220526
         if "logging userinfo" in logging:
             print ("V-220526 is not a finding")
         else:
             print ("V-220526 is an open finding. Please configure logging userinfo")

      # V-220528
         if "service timestamps log datetime msec localtime show-timezone year" in service:
             print ("V-220528 is not a finding")
         else:
             print ('V-220528 is an open finding. Please configure service timestamps log datetime msec localtime show-timezone year')

       # V-220529

         report = []
         all_denies_compliant = True

                # Split output into lines and process each deny statement
         deny_lines = deny.strip().split('\n')

         for line in deny_lines:
            # Clean the line and check if it's a valid deny statement
            line = line.strip()
            if line and 'deny' in line:  # Ensure the line contains a deny statement
                # Check if the line ends with 'log-input'
                has_log_input = line.strip().endswith('log-input')
                if has_log_input:
                    report.append(f"ACL Line: '{line}' - Compliant (ends with log-input)")
                else:
                    all_denies_compliant = False
                    report.append(f"ACL Line: '{line}' - Non-compliant (missing log-input)")

        # Print the report
        #print(f"\nACL Deny Statement Compliance Report for {IPs.strip()}:")
        #print("-" * 60)
        #if not deny_lines or not any('deny' in line for line in deny_lines):
        #    print("No deny statements found in the configuration.")
        #else:
         for line in report:
                print(line)
         print("-" * 60)
         print("V-220539 is not a finding." if all_denies_compliant 
                else "V-220539 is an open finding. Some deny statements are missing log-input. Please add log-input to non-compliant statements.")


        #V-220530
         List = ["archive", "log config", "logging enable"]
         if all(List in Archive for List in List):
             print ( "V-220530 is not a finding")

         else:
             print ("V-220530 is an open finding.")    

       #V-220531 V-220532 V-220533
         print('V-220531, V-220532, and V-220533 are all set to N/A for logging persistent')

        #V-220534         
         UnwantedServices = [
                              "boot network", "ip boot server", "ip bootp server", "ip dns server", "ip identd",
                              "ip finger", "ip rcmd rcp-enable", "ip rcmd rsh-enable", "service config",
                               "service finger", "service tcp-small-servers", "service udp-small-servers", "service pad", "service call-home"
]

         if any(service in showrun for service in UnwantedServices):
            print("Unnecessary services running on device")
         else:
            print("No unnecessary services running")


         #V-220535
         usernamecount = len([line for line in username.splitlines() if 'username' in line.lower()])

        #print(usernamecount)

         if usernamecount == 1 and " common-criteria-policy PASSWORD_POLICY" in username:
            print("V-220535 is not a finding.")
         else:
            print("V-220535 is an open finding, please only configure 1 local account and make sure it points to the password policy.")
                   

        #V-220537
         if "min-length 15" in PasswordPolicy:
                print("V-220537 is not a finding")
         else:
                print("V-220537is an open finding. Please configure the password policy to have a minimum length of 15 characters.")  
        #         #V-220538
         if "upper-case 1" in PasswordPolicy:
                print("V-220538 is not a finding")
         else:
                print("V-220538 is an open finding. Please configure the password policy to have a requirement of 1 upper case character.")

        #         #V-220539 
         if "lower-case 1" in PasswordPolicy:
                print("V-220539 is not a finding") 
         else:   
                print("V-220539 is an open finding. Please configure the password policy to have a requirement of 1 lower case character.")

        #         #V-220540
         if "numeric-count 1" in PasswordPolicy:
                print("V-220540 is not a finding")      
         else:
                print("V-220540 is an open finding. Please configure the password policy to have a requirement of 1 number.")
        #         #V-220541
         if "special-case 1" in PasswordPolicy:
                print("V-220541 is not a finding")
         else:
                print("V-220541 is an open finding. Please configure the password policy to have a requirement of 1 special character.")
        #         #V-220542
         if "char-changes 8" in PasswordPolicy:
                print("V-220542 is not a finding")  
         else:
                print("V-220542 is an open finding. Please configure the password policy to have char-changes 8.")

#V-220543

         if "service password-encryption" in service:
                    print ('V-220543 is not a finding')
         else: 
                    print('V-220543 is an open finding. Please configure service password-encryption to encrypt all passwords in the config.')

         #V-220545
         List = ["archive", "log config", "logging enable"]
         if all(List in Archive for List in List):
             print ( "V-220545 is not a finding")
         else:
             print ("V-220545 is an open finding.")    
         #V-220547

         if "logging buffered 65536 informational" in logging:
             print ("V-220547 is not a finding")
         else:
             print ("V-220547 is an open finding. Please configure logging buffered 65536 informational")
             

         #V-220548
         if "logging trap notifications" in logging:
             print ("V-220548 is not a finding")
         else:
             print ("V-220548 is an open finding. Please configure logging trap notifications")

         #V-220549
         if "ntp server 172.16.100.28" and "ntp server 172.16.100.22" in NTP:
             print ("V-220549 is not a finding")
         else:
             print ("V-220549 is an open finding. Please configure 2 NTP servers")

         #V-220552 
         if "Authentication Protocol: SHA" in snmp:
             print ('V-220552 is not a finding')
         else:
             print('V-220552 is an open finding. Please configure SNMP to use SHA authentication protocol to be FIPS Compliant.')


         #V-220553
         if "Privacy Protocol: AES256" in snmp:
             print ('V-220553 is not a finding')
         else:
             print('V-220553 is an open finding. Please configure SNMP to use AES256 privacy protocol to be FIPS Compliant.')


        #V-220554
         NTPList = ["ntp authentication-key 1 md5 ", "ntp trusted-key 1", "ntp server 172.16.100.28 key 1 prefer", "ntp server 172.16.100.22 key 650"]
         if all(NTPList in NTP for NTPList in NTPList):
             print ("V-220554 is not a finding")
         else:
            print("V-220554 is an open finding. Please configure NTP authentication and trusted keys.")

        #V-220555
         if "ip ssh server algorithm mac hmac-sha2-512 hmac-sha2-256" and "ip ssh version 2" in ssh:
             print ("V-220555 is not a finding")
         else:
             print ("V-220555 is an open finding. Please configure SSH to use the correct HMAC and version.")

         #V-220556
         sshlist = ["aes256-ctr", "aes192-ctr", "aes128-ctr"]
         if all (List in showrun for List in sshlist):
             print('V-220556 is not a finding')
         else:
             print('V-220556 is an open finding. Please configure SSH to use the correct encryption and version.')

         #V-220559
         List = ["archive", "log config", "logging enable"]
         if all(List in Archive for List in List):
             print ( "V-220559 is not a finding")
         else:
             print ("V-220559 is an open finding.")  


         #V-220560
         if "login on-failure log" and "login on-success log" in login:
             print('V-220560 is not a finding')
         else:
             print('V-220560 is an open finding. Please configure login on-failure log and login on-success log in the config.')

         #V-220561
         List = ["archive", "log config", "logging enable"]
         if all(List in Archive for List in List):
             print ( "V-220561 is not a finding")
         else:
             print ("V-220561 is an open finding.")  


         #V_220565
         if " radius server ISE1-EDU-01" and "radius server ISE2-EDU-02" in aaa:
             print ("V-220565 is not a finding")
         else:
             print ("V-220565 is an open finding. Please configure 2 radius servers for client authentication.")

         #V-220566

         #V-220567
         print("V-220567 is set to N/A, certificates are not used in this environment.")

         

         #V-220568
         if "logging host 172.16.100.5" and "logging host 172.16.100.6" in logging:
             print("V-220568 is not a finding")
         else:
             print('V-220568 is an open finding. Please configure logging to the syslog servers')
         
         #V-220569
         if "Cisco IOS XE Software, Version 17.12.05" in version:
             print("V-220569 is not a finding")
         else:
             print('V-220569 is an open finding. Please ensure you are running the correct IOS XE version.')










        

         
         


         






#if __name__ == "__main__":
#ios_xe_switch_l2_checks()
