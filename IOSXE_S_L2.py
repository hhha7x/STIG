import netmiko
from operator import ne
from netmiko import ConnectHandler
from textfsm import TextFSM
from pprint import pprint
from getpass import getpass
import IOSXE_L2_SWITCH_variables
from IOSXE_L2_SWITCH_variables import *
from stig_edit import ckl_editor
#from netmiko.exception import NetmikoTimeoutException
import re

#User = input("What is your username?")
Pass = getpass()
with open ('IP1.txt') as Devices:
     for IPs in Devices:
          Device = {
                 'device_type': 'cisco_ios',
                 'ip' : IPs,
                 'username': 'jimmy.alston.na',
                 'password': Pass
                     }






def ios_xe_switch_l2_checks():
##  THESE ARE THE VARIABLES USED FOR COMMANDS THAT ARE RUN ##

         net_connect = ConnectHandler(**Device)
         showrun = net_connect.send_command('show run')
         vtp = net_connect.send_command ('show vtp status', use_textfsm=True)
         dhcp = net_connect.send_command("show run | inc dhcp")
         ssh = net_connect.send_command('show run | inc ssh')
         service = net_connect.send_command('show run | inc service')
         snmp = net_connect.send_command('show snmp user')
         logging = net_connect.send_command('show run | inc logging')
         vtylines = net_connect.send_command('show run | sec line')
         acl_denies = net_connect.send_command('show run | inc deny')
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
         trunk_configurations = net_connect.send_command("show int trunk")
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







         print('Checking STIG Compliance on Switch ' + IPs)
         print('-'*80)

 
      #V-220649
         if all(list in showrun for list in aaastrings):
            print("V-220649 is not a finding.")
            ckl_editor.write_vkey_data(**V_220649_NotAFinding)
         else:
            print("V-220649 is an open finding. configure aaa")
            ckl_editor.write_vkey_data(**V_220649_Open)

     

 
 
      # V-220650
 
         for i in vtp:
             if i["mode"] == 'Off':
                 print("V-220650 is not a finding")
                 ckl_editor.write_vkey_data(**V_220650_NotAFinding)
             else:
                 print("V-220650 is open. Please set VTP mode to off")
                 ckl_editor.write_vkey_data(**V_220650_Open)


      #V-220651
         if "class-map" in showrun and "policy-map" in showrun:
              print("V-220651 is not a finding")
              ckl_editor.write_vkey_data(**V_220651_NotAFinding)
         else:
              print("V-220651 is an open finding. Please configure Qos")
              ckl_editor.write_vkey_data(**V_220651_Open)

    #V-220655
         if "spanning-tree guard root" in spanningtree:
              print("V-220655 is not a finding")
              ckl_editor.write_vkey_data(**V_220655_NotAFinding)
         else:
              print("V-220655 is an open finding. Please configure root guard")
              ckl_editor.write_vkey_data(**V_220655_Open)

    #V-220656
         if "spanning-tree bpduguard enable" in spanningtree:
              print("V-220656 is not a finding")
              ckl_editor.write_vkey_data(**V_220656_NotAFinding)
         else:
              print("V-220656 is an open finding. Please configure BPDU guard")
              ckl_editor.write_vkey_data(**V_220656_Open)

    #V-220657
         if "spanning-tree loopguard default" in spanningtree:
              print("V-220657 is not a finding")
              ckl_editor.write_vkey_data(**V_220657_NotAFinding)
         else:
              print("V-220657 is an open finding. Please configure loopguard")
              ckl_editor.write_vkey_data(**V_220657_Open)
 
    #V-220658
         if "switchport block unicast" in showrun:
              print("V-220658 is not a finding")
              ckl_editor.write_vkey_data(**V_220658_NotAFinding)
         else:
              print("V-220658 is an open finding. Please configure Unknown Unicast Flood Blocking (UUFB)")
              ckl_editor.write_vkey_data(**V_220658_Open)
 
    #V-220659  
         if "ip dhcp snooping" and "ip dhcp snooping vlan 556,565" in dhcp:
              print("V-220659 is not a finding")
              ckl_editor.write_vkey_data(**V_220659_NotAFinding)
         else:
              print("V-220659 is an open finding. Please configure DHCP snooping for all user VLANs")
              ckl_editor.write_vkey_data(**V_220659_Open)

    #V-220660
         if " ip verify source" in sourceguard:
              print("V-220660 is not a finding")
              ckl_editor.write_vkey_data(**V_220660_NotAFinding)
         else:
              print("V-220660 is an open finding. Please configure source guard on all user-facing ports")
              ckl_editor.write_vkey_data(**V_220660_Open)
              
    #V-220661
         if "ip arp inspection vlan 556,565" in arp:
              print("V-220661 is not a finding")
              ckl_editor.write_vkey_data(**V_220661_NotAFinding)
         else:
              print("V-220661 is an open finding. Please configure ARP inspection for all user vlans")
              ckl_editor.write_vkey_data(**V_220661_Open)

    #V-220662
         if all(string in stormcontrol for string in stormstrings):
            print("V-220662 is not a finding.")
            ckl_editor.write_vkey_data(**V_220662_NotAFinding)
         else:
            print("V-220662 is an open finding. Please configure storm control")
            ckl_editor.write_vkey_data(**V_220662_Open)
            print(stormstrings)

    #V-220663
         if "no ip igmp snooping" in showrun:
              print("V-220663 is an open finding. Please reeanble ip igmp snooping.")
              ckl_editor.write_vkey_data(**V_220663_Open)
         else:
              print("V-220663 is not a finding")
              ckl_editor.write_vkey_data(**V_220663_NotAFinding)

    #V-220664
         if "spanning-tree mode rapid-pvst" in spanningtree:
              print("V-220664 is not a finding")
              ckl_editor.write_vkey_data(**V_220664_NotAFinding)
         else:
              print("V-220664 is an open finding. Please ensure you are running spanning-tree mode rapid-pvst")
              ckl_editor.write_vkey_data(**V_220664_Open)

    #V-220665
         if "udld enable" in udld:
              print("V-220665 is not a finding")
              ckl_editor.write_vkey_data(**V_220665_NotAFinding)
         else:
              print("V-220665 is an open finding. Please configure UDLD")
              ckl_editor.write_vkey_data(**V_220665_Open)

    #V-220666
         if 'Negotiation of Trunking: On' in negotiation:
            print ('V-220666 is an open finding. Please disable all trunk negotiations.')
            ckl_editor.write_vkey_data(**V_220666_Open)
         else:
            print ('V-220666 is not a finding')
            ckl_editor.write_vkey_data(**V_220666_NotAFinding)
    
    #V-220667
         print(interfacestatus)
         while True:
            status = input("Are all unused ports assigned to VLAN 999? yes/no")

            if status == "yes":
               print("V-220667 is not a finding")
               ckl_editor.write_vkey_data(**V_220667_NotAFinding)
               break  # Exit the loop after a valid response
            elif status == "no":
               print("V-220667 is an open finding. Please ensure all unused ports are assigned to VLAN 999.")
               ckl_editor.write_vkey_data(**V_220667_Open)
               break  # Exit the loop after a valid response
            else:
               print("Invalid input. Please answer with 'yes' or 'no'.") 

    #V-220668
         
         while True:
            status2 = input("Are there any ports assigned to VLAN 1? yes/no")

            if status2 == "no":
               print("V-220667 is not a finding")
               ckl_editor.write_vkey_data(**V_220668_NotAFinding)
               break  # Exit the loop after a valid response
            elif status2 == "yes":
               print("V-220667 is an open finding. Please ensure all unused ports are assigned to VLAN 999.")
               ckl_editor.write_vkey_data(**V_220668_Open)
               break  # Exit the loop after a valid response
            else:
               print("Invalid input. Please answer with 'yes' or 'no'.") 



    #V-220669
         print(trunk_configurations)
         while True:
            Trunk = input("Is VLAN 1 pruned from all trunks? yes/no")

            if Trunk == "yes":
               print("V-220667 is not a finding")
               ckl_editor.write_vkey_data(**V_220669_NotAFinding)
               break  
            elif status2 == "yes":
               print("V-220667 is an open finding. Please ensure VLAN 1 is pruned from all trunks.")
               ckl_editor.write_vkey_data(**V_220669_Open)
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
            ckl_editor.write_vkey_data(**V_220670_NotAFinding)
         else:
            print("V-220670 is an open finding")
            ckl_editor.write_vkey_data(**V_220670_Open)

    #V-220671
         print(interfacestatus)
         while True:
            Intstatus = input("Are there any user facing ports set to trunk? yes/no")

            if Intstatus == "no":
               print("V-220671 is not a finding")
               ckl_editor.write_vkey_data(**V_220671_NotAFinding)
               break  
            elif Intstatus == "yes":
               print("V-220671 is an open finding. Please ensure all user facing ports are access ports.")
               ckl_editor.write_vkey_data(**V_220671_Open)
               break  # Exit the loop after a valid response
            else:
               print("Invalid input. Please answer with 'yes' or 'no'.")
    #V-220673
         while True:
            Intstatus2 = input("Are any of the ports assigned to the native vlan, 333? yes/no")

            if Intstatus2 == "no":
               print("V-220671 is not a finding")
               ckl_editor.write_vkey_data(**V_220673_NotAFinding)
               break  
            elif Intstatus2 == "yes":
               print("V-220671 is an open finding. Please ensure all user facing ports are access ports.")
               ckl_editor.write_vkey_data(**V_220673_Open)
               break  # Exit the loop after a valid response
            else:
               print("Invalid input. Please answer with 'yes' or 'no'.")

     #V-220672
         if "switchport trunk native vlan 1" in nativevlan:
             print('Open finding')
             ckl_editor.write_vkey_data(**V_220672_Open)
         else:
             print('Not a finding')
             ckl_editor.write_vkey_data(**V_220672_NotAFinding)










        

         
         


         






#if __name__ == "__main__":
ios_xe_switch_l2_checks()

                            