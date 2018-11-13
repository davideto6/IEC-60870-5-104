#protocol 104 single command

import signal
import sys
import time
import math
import threading
#import ConfigParser 
import collections
import logging
import sys
import csv
#from StringIO import StringIO
from scapy.all import * # Scapy dependences
from iec104lib import *	# Library iec 60870-5-104

class bcolors: 			# Terminal's color
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class typesid:
	def __init__(self, typesasdu, ipaddr, count):
         self.tipos = typesasdu
         self.ip = ipaddr
         self.cont = count

class control:
	def __init__(self,ipaddr):
		 self.ip = ipaddr


lista = [255]

def divide(x1,x2):
    x1=float(x1)   
    result=x1/x2
    return result


def sniffer():
	sniff(offline="iec104.pcap", prn = pkt_action, store=0)



def pkt_action(pkt):
	

	global pkt_counter
	global IEC104_counter
	global numero
	global number
	global num
	global IEC104_counter_i
	global IEC104_counter_s
	global IEC104_counter_u
	global inicio
	global final
	global TCP_counter
	global attack
	global STARTDTact	
	global STARTDTcon
	global STOPDTact
	global STOPDTcon
	global TESTFRact
	global TESTFRcon
	global START_ApduLen
	global Header_Eth
	global Tx
	global Rx
	global u
	global att

	pkt_counter+=1

	'''IP checks'''	
	if pkt.haslayer(IP) == 1:

		ipsrc = pkt[IP].src
		ipdst = pkt[IP].dst

		lenght=Header_Eth+pkt[IP].ihl*4+4 # le sumamos 4 por pertenecer a una vlan

		'''TCP checks'''
		if pkt.haslayer(TCP) == 1:

			TCP_counter+=1	
			lenght+=pkt[TCP].dataofs*4

		else:
			print ('ATTACK NO TCP'	)
			pkt.show() 				# SHOW ATTACK PACKET

		'''IEC 60870-5-104 Type I checks'''

		if pkt.haslayer(IEC104_i) == 1:
			encontrado=0
			
			IEC104_counter+=1
			start_value=pkt.START
			lenght+=START_ApduLen+pkt.ApduLen # Ethernet + IP + TCP + 2 bytes(START y ApduLen) + ApduLen
			
			if start_value == 104:
				
				if pkt.ApduLen == 4:
					tipo =	pkt.Tx
					masc = 3
					types=tipo&masc

					if types==1: # Type S
						IEC104_counter_s+=1

					elif types==3: # Type U
						IEC104_counter_u+=1
						concatenar=pkt.Tx+pkt.Rx
						masc=252
						UType=concatenar&masc

						if UType==4:
							STARTDTact+=1

						if UType==8:
							STARTDTcon+=1

						if UType==16:
							STOPDTact+=1
						if UType==32:
							STOPDTcon+=1 

						if UType==64:
							TESTFRact+=1 

						if UType==128:
							TESTFRcon+=1

					else:
						attack+=1
				else:
					tipo =	pkt.Tx
					masc = 1
					types=tipo&masc
					masc_Tx = 254
					comprobacion_Tx = tipo&masc_Tx


				if types==0 and pkt.ApduLen>4: # Type I
					IEC104_counter_i+=1

					if pkt.haslayer(asdu):
						CoT=pkt.Cause&63

						if pkt.TypeID>127:
							print ('ATTACK wrong Type ID ', pkt.TypeID, ', is not defined. Packet number', pkt_counter)
							attack+=1

						if (pkt.TypeID<45 and pkt.TypeID>51) or (pkt.TypeID<58 and pkt.TypeID>64) or (pkt.TypeID<100 and pkt.TypeID>103) or pkt.TypeID==105 or pkt.TypeID==107 or (pkt.TypeID<110 and pkt.TypeID>113) and pkt[TCP].dport==2404:							
							if pkt.TypeID==103 or pkt.TypeID==105 or pkt.TypeID==107:
								1+1
							else:
								print ('ATTACK SLAVE wrong Type ID ', pkt.TypeID, 'in packet number', pkt_counter)
								attack+=1  

						if (pkt.TypeID<30 and pkt.TypeID>40) or (pkt.TypeID<45 and pkt.TypeID>51) or (pkt.TypeID<58 and pkt.TypeID>64) or (pkt.TypeID<16 and pkt.TypeID%2!=1) or pkt.TypeID==104 or pkt.TypeID==100 or pkt.TypeID==20 or pkt.TypeID==21 or (pkt.TypeID<110 and pkt.TypeID>113) or (pkt.TypeID<108 and pkt.TypeID>100 and pkt.TypeID%2!=1) and pkt[TCP].sport==2404:
							
							if pkt.TypeID==100 or pkt.TypeID==20 or pkt.TypeID==21 or pkt.TypeID==104:
								1+1
							else:
								print ('ATTACK MASTER wrong Type ID ', pkt.TypeID, 'in packet number', pkt_counter)
								attack+=1

						if pkt.TypeID == 45 or pkt.TypeID == 46:
							if pkt.ApduLen != 14:
								print ('ATTACK wrong ApduLen, it must be 14 instead of ', pkt.ApduLen, 'in packet number', pkt_counter)
								attack+=1

						if (pkt.TypeID >= 45 and pkt.TypeID <= 48) or pkt.TypeID == 100 or pkt.TypeID == 101:
							if CoT != 7 and CoT!=10 and pkt[TCP].sport == 2404:
								print ('ATTACK wrong CoT, it must be 7 or 10 instead of ', CoT, 'in packet number', pkt_counter)
								attack+=1

							if CoT!=6 and pkt[TCP].dport == 2404:
								print ('ATTACK wrong CoT, it must be 6 instead of ', CoT, 'in packet number', pkt_counter)
								attack+=1

							if (CoT<1 and CoT>13) or (CoT<20 and CoT>41):
								print ('ATTACK wrong CoT range value', CoT, 'in packet number', pkt_counter)
								attack+=1

						if (pkt.TypeID>0):	
							if numero==0:
								lista[numero]=typesid(pkt.TypeID,pkt[IP].src,0)
								numero+=1
								encontrado=0
							
							for i in range(numero):
								if (pkt.TypeID==lista[i].tipos) and (pkt[IP].src==lista[i].ip):
									lista[i].cont+=1
									encontrado=1

							if encontrado==0:
								lista.append(typesid(pkt.TypeID,pkt[IP].src,1))
								numero+=1
				
				while lenght<len(pkt):
					if pkt.haslayer(IEC104_i) == 1:
						encontrado=0
						IEC104_counter+=1
						start_value=pkt.START
						lenght+=START_ApduLen+pkt.ApduLen # Ethernet + IP + TCP + 2 bytes(START y ApduLen) + ApduLen

						if start_value == 104:
							
							if pkt.ApduLen == 4:
								tipo =	pkt.Tx
								masc = 3
								types=tipo&masc

								if types==1: # Type S
									IEC104_counter_s+=1

								elif types==3: # Type U
									IEC104_counter_u+=1
									concatenar=pkt.Tx+pkt.Rx
									masc=252
									UType=concatenar&masc

									if UType==4:
										STARTDTact+=1

									if UType==8:
										STARTDTcon+=1

									if UType==16:
										STOPDTact+=1

									if UType==32:
										STOPDTcon+=1

									if UType==64:
										TESTFRact+=1 

									if UType==128:
										TESTFRcon+=1

								else:
									attack+=1

							else:
								tipo =	pkt.Tx
								masc = 1
								types=tipo&masc
								masc_Tx = 254
								comprobacion_Tx = tipo&masc_Tx


							if types==0 and pkt.ApduLen>4: # Type I
								IEC104_counter_i+=1

							if pkt.haslayer(asdu):

								if pkt.TypeID>127:
									print ('ATTACK wrong Type ID ', pkt.TypeID, ', is not defined. Packet number', pkt_counter)
									attack+=1

								if (pkt.TypeID<45 and pkt.TypeID>51) or (pkt.TypeID<58 and pkt.TypeID>64) or (pkt.TypeID<100 and pkt.TypeID>103) or pkt.TypeID==105 or pkt.TypeID==107 or (pkt.TypeID<110 and pkt.TypeID>113) and pkt[TCP].dport==2404:									
									if pkt.TypeID==103 or pkt.TypeID==105 or pkt.TypeID==107:
										1+1
									else:
										print ('ATTACK SLAVE wrong Type ID ', pkt.TypeID, 'in packet number', pkt_counter)
										attack+=1  

								if (pkt.TypeID<30 and pkt.TypeID>40) or (pkt.TypeID<45 and pkt.TypeID>51) or (pkt.TypeID<58 and pkt.TypeID>64) or (pkt.TypeID<16 and pkt.TypeID%2!=1) or pkt.TypeID==104 or pkt.TypeID==100 or pkt.TypeID==20 or pkt.TypeID==21 or (pkt.TypeID<110 and pkt.TypeID>113) or (pkt.TypeID<108 and pkt.TypeID>100 and pkt.TypeID%2!=1) and pkt[TCP].sport==2404:
									if pkt.TypeID==100 or pkt.TypeID==20 or pkt.TypeID==21 or pkt.TypeID==104:
										1+1
									else:
										print ('ATTACK MASTER wrong Type ID ', pkt.TypeID, 'in packet number', pkt_counter)
										attack+=1 

								if pkt.TypeID == 45 or pkt.TypeID == 46:
									if pkt.ApduLen != 14:
										print ('ATTACK wrong ApduLen, it must be 14 instead of ', pkt.ApduLen, 'in packet number', pkt_counter)
										attack+=1

								if (pkt.TypeID >= 45 and pkt.TypeID <= 48) or pkt.TypeID == 100 or pkt.TypeID == 101:

									if CoT != 7 and CoT!=10 and pkt[TCP].sport == 2404:
										print ('ATTACK wrong CoT, it must be 7 or 10 instead of ', CoT, 'in packet number', pkt_counter)
										attack+=1

									if CoT!=6 and pkt[TCP].dport == 2404:
										print ('ATTACK wrong CoT, it must be 6 instead of ', CoT, 'in packet number', pkt_counter)
										attack+=1

								if (pkt.TypeID>0):	
									if numero==0:
										lista[numero]=typesid(pkt.TypeID,pkt[IP].src,0)
										numero+=1
										encontrado=0
									
									for i in range(numero):
										if (pkt.TypeID==lista[i].tipos) and (pkt[IP].src==lista[i].ip):
											lista[i].cont+=1
											encontrado=1

									if encontrado==0:										
										lista.append(typesid(pkt.TypeID,pkt[IP].src,1))
										numero+=1

						else:
							print('WARNING NO 104')

			else:
				print('WARNING NO 104')

if __name__ == "__main__":
	''' Initializations '''

	pkt_counter = 0
	IEC104_counter = 0
	IEC104_counter_i = 0
	IEC104_counter_s = 0
	IEC104_counter_u = 0
	inicio = 0
	TCP_counter = 0
	attack = 0
	STARTDTact = 0
	STARTDTcon = 0
	STOPDTact = 0
	STOPDTcon = 0
	TESTFRact = 0
	TESTFRcon = 0

	START_ApduLen = 2
	Header_Eth = 14

	Tx = 0
	Rx = 0

	tipoasdu=0
	numero=0
	number=0
	num=0
	
	IEC104_i=i_frame
	IEC104_s=s_frame
	IEC104_u=u_frame

	asdu=asdu_head

	bind_layers(TCP, IEC104_i)

	bind_layers(IEC104_i,asdu)

	init_time = time.time()

	''' Sniffing and call to pkt_action function '''

	print 'Sniffing process started. To stop it, press Ctrl+C'

	sniffer() #Calls to sniffer

	''' Final results display after sniffing'''

	stop_time = time.time()

	print '\nSniffer stopped by keystroke.'
	print '\n#### Final results ####'

	if pkt_counter == 0:
		print ('No packets sniffed in', round((stop_time-init_time),4), 'seconds.')

	else:
		TCP_percent = ((divide(TCP_counter,pkt_counter))*100)
		IEC104_percent = ((divide(IEC104_counter,pkt_counter))*100)
		print ('Time elapsed:'+bcolors.OKBLUE+'', round((stop_time-init_time),4), 'seconds.'+bcolors.ENDC)
		print ('Packets sniffed:', pkt_counter)
		print ('---- IEC 60870-5-104 packets:'+bcolors.OKGREEN+'',IEC104_counter, bcolors.ENDC,'Percent:'+bcolors.OKGREEN+'',IEC104_percent,'%'+bcolors.ENDC)

		if IEC104_counter_i > 0: # print different types iec104-TypeI
			IEC104_percent_i = ((divide(IEC104_counter_i,IEC104_counter))*100)
			print ('---- IEC 60870-5-104 packets Type I:'+bcolors.OKGREEN+'',IEC104_counter_i, bcolors.ENDC,'Percent:'+bcolors.OKGREEN+'',IEC104_percent_i,'%'+bcolors.ENDC)
			print ('\t\tIP\t\tTipos\tContador\tPorcentaje')
			lista.sort(key=lambda typesid: typesid.tipos)
			for i in range(numero):
				porcentaje = ((divide(lista[i].cont,IEC104_counter_i))*100)
				print ('\t\t',lista[i].ip,'\t',lista[i].tipos,'\t',lista[i].cont,'\t\t',porcentaje,'%'			   )
				
		if IEC104_counter_s > 0: # print different types iec104-TypeS
			IEC104_percent_s = ((divide(IEC104_counter_s,IEC104_counter))*100)
			print ('---- IEC 60870-5-104 packets Type S:'+bcolors.OKGREEN+'',IEC104_counter_s, bcolors.ENDC,'Percent:'+bcolors.OKGREEN+'',IEC104_percent_s,'%'+bcolors.ENDC)

		if IEC104_counter_u > 0: # print different types iec104-TypeU
			IEC104_percent_u = ((divide(IEC104_counter_u,IEC104_counter))*100)
			print ('---- IEC 60870-5-104 packets Type U:'+bcolors.OKGREEN+'',IEC104_counter_u, bcolors.ENDC,'Percent:'+bcolors.OKGREEN+'',IEC104_percent_u,'%'+bcolors.ENDC)
			print ('\t\tSTARTDT act =' +bcolors.OKBLUE+'',STARTDTact, bcolors.ENDC)
			print ('\t\tSTARTDT con =' +bcolors.OKBLUE+'',STARTDTcon, bcolors.ENDC)
			print ('\t\tSTOPDT act =' +bcolors.OKBLUE+'',STOPDTact, bcolors.ENDC)
			print ('\t\tSTOPDT con =' +bcolors.OKBLUE+'',STOPDTcon, bcolors.ENDC)
			print ('\t\tTESTFR act =' +bcolors.OKBLUE+'',TESTFRact, bcolors.ENDC)
			print ('\t\tTESTFR con =' +bcolors.OKBLUE+'',TESTFRcon, bcolors.ENDC)
		
		print ('---- TCP packets:'+bcolors.OKGREEN+'',TCP_counter, bcolors.ENDC,'Percent:'+bcolors.OKGREEN+'',TCP_percent,'%'+bcolors.ENDC)
		print ('Possible attacks = '+bcolors.FAIL+'',attack, bcolors.ENDC)

		
