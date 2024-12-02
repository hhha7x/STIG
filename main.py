import netmiko
from operator import ne
from netmiko import ConnectHandler
from textfsm import TextFSM
from pprint import pprint
from getpass import getpass
#import Check_variables
#from Check_variables import *
from stig_edit import ckl_editor
import IOSXE_S_NDM
import IOSXE_S_L2

User = input("What is your username?")
Pass = getpass()
with open ('IP1.txt') as Devices:
    for IP in Devices:
         Device = {
                'device_type': 'cisco_ios',
                'ip' : IP,
                'username': USER,
                'password': Pass
                    }


net_connect = ConnectHandler(**Device)

with ConnectHandler(**Device) as netconnect:
     output = net_connect.send_command("show version")

     if "IOS XE" in output:
          print("Device is running IOSXE")
          IOSXE_S_NDM.ios_xe_switch_ndm_checks()
     elif "IOS" in output:
          print("Device is running regular IOS")
     elif "NOXS" in output:
          print ("Device is running NXOS")
     else: 
          print ( "This is not a Cisco device")



#print(output)
