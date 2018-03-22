'''
Coursera:
- Software Defined Networking (SDN) course
-- Programming Assignment: Layer-2 Firewall Application

Professor: Nick Feamster
Teaching Assistant: Arpit Gupta
'''

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.addresses import EthAddr
from collections import namedtuple
import os
''' Add your imports here ... '''
import csv


log = core.getLogger()
policyFile = "%s/pox/pox/misc/firewall-policies.csv" % os.environ[ 'HOME' ]  

''' Add your global variables here ... '''


firewallRules = []

class Firewall (EventMixin):

    def __init__ (self):
        self.listenTo(core.openflow)
	Firewall.readCSVFile(self)	
        log.debug("Enabling Firewall Module")

    def _handle_ConnectionUp (self, event):    
        ''' Add your logic here ... '''
	global firewallRules
	for(source,destination)in firewallRules:
		message = of.ofp_flow_mod()
		match = of.ofp_match()
		match.dl_src = source
		match.dl_dst = destination
		message.priority = 65535 
		message.match = match
		message.actions.append(of.ofp_action_output(port=of.OFPP_NONE))
		event.connection.send(message)
        log.debug("Firewall rules installed on %s", dpidToStr(event.dpid))
   
    def readCSVFile(self):
	with open(policyFile, 'rb') as csvfile:
		linereader = csv.DictReader(csvfile)
		for line in linereader:
			mac_0 = EthAddr(line['mac_0'])
			mac_1 = EthAddr(line['mac_1'])
			global firewallRules
			firewallRules.append((mac_0,mac_1))
		#	print ', '.join((mac_0,mac_1))

		
    

def launch ():
    '''
    Starting the Firewall module
    '''
    core.registerNew(Firewall)
   
