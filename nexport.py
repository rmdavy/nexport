from collections import OrderedDict
from lxml import etree
import os, signal, sys
import argparse
import xlsxwriter
from pathlib import Path

#Parsing function taken from
#https://avleonov.com/2020/03/09/parsing-nessus-v2-xml-reports-with-python/
def get_vulners_from_xml(xml_content):
    vulnerabilities = dict()
    single_params = ["agent", "cvss3_base_score", "cvss3_temporal_score", "cvss3_temporal_vector", "cvss3_vector",
                     "cvss_base_score", "cvss_temporal_score", "cvss_temporal_vector", "cvss_vector", "description",
                     "exploit_available", "exploitability_ease", "exploited_by_nessus", "fname", "metasploit_name","in_the_news",
                     "patch_publication_date", "plugin_modification_date", "plugin_name", "plugin_publication_date",
                     "plugin_type", "script_version", "see_also", "solution", "synopsis", "vuln_publication_date",
                     "compliance",
                     "{http://www.nessus.org/cm}compliance-check-id",
                     "{http://www.nessus.org/cm}compliance-check-name",
                     "{http://www.nessus.org/cm}audit-file",
                     "{http://www.nessus.org/cm}compliance-info",
                     "{http://www.nessus.org/cm}compliance-solution",
                     "{http://www.nessus.org/cm}compliance-result",
                     "{http://www.nessus.org/cm}compliance-see-also"]
    p = etree.XMLParser(huge_tree=True)
    root = etree.fromstring(text=xml_content, parser=p)
    for block in root:
        if block.tag == "Report":
            for report_host in block:
                host_properties_dict = dict()
                for report_item in report_host:
                    if report_item.tag == "HostProperties":
                        for host_properties in report_item:
                            host_properties_dict[host_properties.attrib['name']] = host_properties.text
                for report_item in report_host:
                    if 'pluginName' in report_item.attrib:
                        vulner_struct = dict()
                        vulner_struct['port'] = report_item.attrib['port']
                        vulner_struct['pluginName'] = report_item.attrib['pluginName']
                        vulner_struct['pluginFamily'] = report_item.attrib['pluginFamily']
                        vulner_struct['pluginID'] = report_item.attrib['pluginID']
                        vulner_struct['svc_name'] = report_item.attrib['svc_name']
                        vulner_struct['protocol'] = report_item.attrib['protocol']
                        vulner_struct['severity'] = report_item.attrib['severity']
                        for param in report_item:
                            if param.tag == "risk_factor":
                                risk_factor = param.text
                                vulner_struct['host'] = report_host.attrib['name']
                                vulner_struct['riskFactor'] = risk_factor
                            elif param.tag == "plugin_output":
                                if not "plugin_output" in vulner_struct:
                                    vulner_struct["plugin_output"] = list()
                                if not param.text in vulner_struct["plugin_output"]:
                                    vulner_struct["plugin_output"].append(param.text)
                            else:
                                if not param.tag in single_params:
                                    if not param.tag in vulner_struct:
                                        vulner_struct[param.tag] = list()
                                    if not isinstance(vulner_struct[param.tag], list):
                                        vulner_struct[param.tag] = [vulner_struct[param.tag]]
                                    if not param.text in vulner_struct[param.tag]:
                                        vulner_struct[param.tag].append(param.text)
                                else:
                                    vulner_struct[param.tag] = param.text
                        for param in host_properties_dict:
                            vulner_struct[param] = host_properties_dict[param]
                        compliance_check_id = ""
                        if 'compliance' in vulner_struct:
                            if vulner_struct['compliance'] == 'true':
                                compliance_check_id = vulner_struct['{http://www.nessus.org/cm}compliance-check-id']
                        if compliance_check_id == "":
                            vulner_id = vulner_struct['host'] + "|" + vulner_struct['port'] + "|" + \
                                        vulner_struct['protocol'] + "|" + vulner_struct['pluginID']
                        else:
                            vulner_id = vulner_struct['host'] + "|" + vulner_struct['port'] + "|" + \
                                        vulner_struct['protocol'] + "|" + vulner_struct['pluginID'] + "|" + \
                                        compliance_check_id
                        if not vulner_id in vulnerabilities:
                            vulnerabilities[vulner_id] = vulner_struct
    return(vulnerabilities)


def banner():
	print("""                               
               
   _  __ ____                       __ 
  / |/ // __/__ __ ___  ___   ____ / /_
 /    // _/  \\ \\ // _ \\/ _ \\ / __// __/
/_/|_//___/ /_\\_\\/ .__/\\___//_/   \\__/ 
                /_/        

Because Exporting from Nessus is painful 
Version 0.1ad
@rd_pentest

""")


def main():

	#Show Banner
	banner()

	#Get command line args
	p = argparse.ArgumentParser("./nexport -f nessus.nessus ", formatter_class=lambda prog: argparse.HelpFormatter(prog,max_help_position=20,width=150),description = "Parses Nessus file for some common tasks")

	p.add_argument("-f", "--filename", dest="filename", help="Enter name of nessus file to parse")
	p.add_argument("-id", "--plugin_id", dest="plugin_id", default="",help="Enter plugin id for specific id, or all for all plugins")
	p.add_argument("-out", "--output", dest="output", default="",help="Enter filename to write to ")
	p.add_argument("-nv", "--nessusvulns", dest="nessusvulns", default="",help="Show Nessus Vulnerabilities and PluginID")
	p.add_argument("-ms", "--metasploit", dest="metasploit", default="",help="Show items exploitable with Metasploit")
	p.add_argument("-cp", "--compliance", dest="compliance", default="",help="Pull out failed compliance checks")
	p.add_argument("-pocs", "--pocs", dest="pocs", default="",help="Commands to verify findings and gather additional screenshots")
	p.add_argument("-cat", "--cat", dest="cat", default="",help="Extract CA Issuer from SSL Certificate Cannot Be Trusted (PluginID 51192) useful for validatation when client has own CA")

	args = p.parse_args()

	#Parse plugins for IP, Ports, Services, Hostnames
	if args.nessusvulns!="":
		#Open Nessus file to parse
		file_path = args.filename
		f = open(file_path, 'r')
		xml_content = f.read()
		f.close()

		#Call Nessus vulnerability parse function
		vulners = get_vulners_from_xml(xml_content)

		#print(vulners)

		#Setup devices list variable
		devices=[]

		#Cycle through all vulnerabilities
		for vulner_id in vulners:
			#try:
				#print (vulners[vulner_id]["pluginID"])
				#print(vulners[vulner_id]["host-ip"],",",vulners[vulner_id]["protocol"], vulners[vulner_id]["port"], vulners[vulner_id]["svc_name"],vulners[vulner_id]["host-fqdn"])
			devices.append(vulners[vulner_id]["pluginName"]+","+vulners[vulner_id]["pluginID"])
			#except:
				#print(vulners[vulner_id]["host-ip"],",",vulners[vulner_id]["protocol"], vulners[vulner_id]["port"], vulners[vulner_id]["svc_name"])
			#	devices.append(vulners[vulner_id]["pluginName"]+","+vulners[vulner_id]["pluginID"].upper())

		devices=list(OrderedDict.fromkeys(devices))
		
		#Output to file if required
		if args.output!="":

			#Clean up device list to that all items are unique
			devices=list(OrderedDict.fromkeys(devices))

			#If output variable is not empty write to file
			if args.output!="":
				if args.output.endswith(('.csv'))==False:
					args.output = args.output+ ".csv"

				# open the file in the write mode
				with open(args.output, 'w') as f:
					for device in devices:
						f.write(device)
						f.write('\n')

			print("[*] Written File "+args.output)

		if args.output=="":
			#Print output to screen
			for device in devices:
				print(device)
	
		sys.exit()


	#Parse plugins for IP, Ports, Services, Hostnames
	if args.plugin_id!="":
		#Open Nessus file to parse
		file_path = args.filename
		f = open(file_path, 'r')
		xml_content = f.read()
		f.close()

		#Call Nessus vulnerability parse function
		vulners = get_vulners_from_xml(xml_content)

		#print(vulners)

		#Setup devices list variable
		devices=[]

		#Cycle through all vulnerabilities
		for vulner_id in vulners:
			if args.plugin_id!="all":
				if(vulners[vulner_id]["pluginID"])==args.plugin_id:
					try:
						#print(vulners[vulner_id]["host-ip"],",",vulners[vulner_id]["protocol"], vulners[vulner_id]["port"], vulners[vulner_id]["svc_name"],vulners[vulner_id]["host-fqdn"])
						devices.append(vulners[vulner_id]["host-ip"]+","+"("+vulners[vulner_id]["protocol"].upper()+" "+vulners[vulner_id]["port"]+")"+ " "+"("+vulners[vulner_id]["svc_name"].upper()+")"+" "+"("+vulners[vulner_id]["host-fqdn"]+")")
					except:
						#print(vulners[vulner_id]["host-ip"],",",vulners[vulner_id]["protocol"], vulners[vulner_id]["port"], vulners[vulner_id]["svc_name"])
						devices.append(vulners[vulner_id]["host-ip"]+","+"("+vulners[vulner_id]["protocol"].upper()+" "+vulners[vulner_id]["port"]+")"+" "+"("+vulners[vulner_id]["svc_name"].upper()+")")
			else:
				try:
					#print (vulners[vulner_id]["pluginID"])
					#print(vulners[vulner_id]["host-ip"],",",vulners[vulner_id]["protocol"], vulners[vulner_id]["port"], vulners[vulner_id]["svc_name"],vulners[vulner_id]["host-fqdn"])
					devices.append(vulners[vulner_id]["host-ip"]+","+"("+vulners[vulner_id]["protocol"].upper()+" "+vulners[vulner_id]["port"]+")"+ " "+"("+vulners[vulner_id]["svc_name"].upper()+")"+" "+"("+vulners[vulner_id]["host-fqdn"]+")")
				except:
					#print(vulners[vulner_id]["host-ip"],",",vulners[vulner_id]["protocol"], vulners[vulner_id]["port"], vulners[vulner_id]["svc_name"])
					devices.append(vulners[vulner_id]["host-ip"]+","+"("+vulners[vulner_id]["protocol"].upper()+" "+vulners[vulner_id]["port"]+")"+" "+"("+vulners[vulner_id]["svc_name"].upper()+")")

		
		#Output to file if required
		if args.output!="":

			#Clean up device list to that all items are unique
			devices=list(OrderedDict.fromkeys(devices))

			#If output variable is not empty write to file
			if args.output!="":
				if args.output.endswith(('.csv'))==False:
					args.output = args.output+ ".csv"

				# open the file in the write mode
				with open(args.output, 'w') as f:
					for device in devices:
						f.write(device)
						f.write('\n')

			print("[*] Written File "+args.output)

		if args.output=="":
			#Print output to screen
			for device in devices:
				print(device)
	
		sys.exit()

	#Parse CA for issuer name
	if args.cat!="":
		#Open Nessus file to parse
		file_path = args.filename
		f = open(file_path, 'r')
		xml_content = f.read()
		f.close()

		#Call Nessus vulnerability parse function
		vulners = get_vulners_from_xml(xml_content)

		#print(vulners)

		#Setup devices list variable
		devices=[]
		devices.append("IP"+","+"Port"+","+"CA Issuer")
		#Cycle through all vulnerabilities
		for vulner_id in vulners:

			#Parse for Metasploitable issues
			if(vulners[vulner_id]["pluginID"])=="51192":
				try:

					output=str((vulners[vulner_id]["plugin_output"]))
					#print(output)
					issuer=output[output.find("Issuer"):-4]
					#print(issuer)
					issuer=issuer.replace(", ", " ")
					devices.append((vulners[vulner_id]["host-ip"]+","+vulners[vulner_id]["port"]+","+issuer))
				except:
					pass


		#Clean up device list to that all items are unique
		devices=list(OrderedDict.fromkeys(devices))

		#If output variable is not empty write to file
		if args.output!="":
			if args.output.endswith(('.csv'))==False:
				args.output = args.output+ ".csv"
			
			# open the file in the write mode
			with open(args.output, 'w') as f:
				for device in devices:
					f.write(device)
					f.write('\n')

			print("[*] Written File "+args.output)

		if args.output=="":
			#Print output to screen
			for device in devices:
				print(device)

		sys.exit()

	#Parse for metasploit modules
	if args.metasploit!="":
		#Open Nessus file to parse
		file_path = args.filename
		f = open(file_path, 'r')
		xml_content = f.read()
		f.close()

		#Call Nessus vulnerability parse function
		vulners = get_vulners_from_xml(xml_content)

		#print(vulners)

		#Setup devices list variable
		devices=[]

		#Cycle through all vulnerabilities
		for vulner_id in vulners:

			#Parse for Metasploitable issues

			try:
				if (vulners[vulner_id]["metasploit_name"])!="":
					devices.append((vulners[vulner_id]["host-ip"]+","+vulners[vulner_id]["metasploit_name"]))
			except:
				pass


		#Clean up device list to that all items are unique
		devices=list(OrderedDict.fromkeys(devices))

		#If output variable is not empty write to file
		if args.output!="":
			if args.output.endswith(('.csv'))==False:
				args.output = args.output+ ".csv"
			
			# open the file in the write mode
			with open(args.output, 'w') as f:
				for device in devices:
					f.write(device)
					f.write('\n')

			print("[*] Written File "+args.output)

		if args.output=="":
			#Print output to screen
			for device in devices:
				print(device)

		sys.exit()

	#Pull out failed compliance issues from nessus file
	if args.compliance!="":
		vulner_id=""
		#Open Nessus file to parse
		file_path = args.filename
		f = open(file_path, 'r')
		xml_content = f.read()
		f.close()

		#Call Nessus vulnerability parse function
		vulners = get_vulners_from_xml(xml_content)

		#Setup devices list variable
		devices=[]

		cpvulnerabilities = dict()
		#Cycle through all vulnerabilities
		
		for vulner_id in vulners:
			cvulner_struct = dict()

			if args.compliance!="":
				try:
					#"{http://www.nessus.org/cm}compliance-check-name"
					#"{http://www.nessus.org/cm}compliance-check-id",
		            # "{http://www.nessus.org/cm}compliance-check-name",
		            # "{http://www.nessus.org/cm}audit-file",
		            # "{http://www.nessus.org/cm}compliance-info",
		            # "{http://www.nessus.org/cm}compliance-result",
		            # "{http://www.nessus.org/cm}compliance-see-also"]

					if (vulners[vulner_id]["{http://www.nessus.org/cm}compliance-result"])=="FAILED":
						if args.output=="":
							print("\nCompliance Check",vulners[vulner_id]["{http://www.nessus.org/cm}compliance-result"])
							print(vulners[vulner_id]["{http://www.nessus.org/cm}compliance-check-name"])
							print("\nAudit File")
							print(vulners[vulner_id]["{http://www.nessus.org/cm}compliance-audit-file"])
							print("\nCompliance Info")
							print(vulners[vulner_id]["{http://www.nessus.org/cm}compliance-info"])
							print("\nCompliance Solution")
							print(vulners[vulner_id]["{http://www.nessus.org/cm}compliance-solution"])

						cCheck=str(vulners[vulner_id]["{http://www.nessus.org/cm}compliance-check-name"])
						#print(cCheck)
						cResult=str(vulners[vulner_id]["{http://www.nessus.org/cm}compliance-result"])
						cAudit=str(vulners[vulner_id]["{http://www.nessus.org/cm}compliance-audit-file"])
						cInfo=str(vulners[vulner_id]["{http://www.nessus.org/cm}compliance-info"])
						cSolution=str(vulners[vulner_id]["{http://www.nessus.org/cm}compliance-solution"])

						cvulner_struct["cCheck"] = vulners[vulner_id]["{http://www.nessus.org/cm}compliance-check-name"]
						cvulner_struct['cResult'] = cResult
						cvulner_struct['cAudit'] = cAudit
						cvulner_struct['cInfo'] = cInfo
						cvulner_struct['cSolution'] = cSolution
						
						if not vulner_id in cpvulnerabilities:
							cpvulnerabilities[vulner_id] = cvulner_struct

				except:
					pass

		#Output to file if required
		if args.output!="":

			#Change last chars from .csv to .xlsx to ensure correct filetype
			if args.output.endswith(('.csv')):
				args.output = args.output.replace(".csv", ".xlsx")
			#If fileextension missing add .xlsx
			if args.output.endswith(('.xlsx'))==False:
				args.output = args.output+ ".xlsx"

			workbook = xlsxwriter.Workbook(args.output)
			worksheet = workbook.add_worksheet("CIS Compliance Failures")

			row = 0
			col = 0
			bold = workbook.add_format({'bold': True})

			#Finding*	Description*	Recommendation*	CVSS	CVE Ref*	Thread Level Category
			worksheet.write(row, col,"Compliance Check Name",bold)
			worksheet.write(row, col+1,"Compliance Result",bold)
			worksheet.write(row, col+2,"Audit Type",bold)
			worksheet.write(row, col+3,"Compliance Info",bold)
			worksheet.write(row, col+4,"Compliance Solution",bold)

			row=1

			for vulner_id in cpvulnerabilities:
				worksheet.write(row, col,(cpvulnerabilities[vulner_id]["cCheck"]))
				worksheet.write(row, col+1,(cpvulnerabilities[vulner_id]["cResult"]))
				worksheet.write(row, col+2,(cpvulnerabilities[vulner_id]["cAudit"]))
				worksheet.write(row, col+3,(cpvulnerabilities[vulner_id]["cInfo"]))
				worksheet.write(row, col+4,(cpvulnerabilities[vulner_id]["cSolution"]))

				row += 1

			workbook.close()
			print("[*] Written File "+args.output)

		sys.exit()

	#Parse for poc
	if args.pocs!="":
		#Open Nessus file to parse
		file_path = args.filename
		f = open(file_path, 'r')
		xml_content = f.read()
		f.close()

		#Call Nessus vulnerability parse function
		vulners = get_vulners_from_xml(xml_content)

		#Setup devices list variable
		devices=[]

		devices.append("Vulnerability,IP,Port,POC")

		#Cycle through all vulnerabilities
		for vulner_id in vulners:

			#Parse for poc
			#ToDo
			#msfconsole -n -q -x “use gather/search_email_collector;set domain target.com;run;exit”

			try:
				if (vulners[vulner_id]["pluginID"])=="10043":
					devices.append((vulners[vulner_id]["pluginName"]+","+vulners[vulner_id]["host-ip"]+","+vulners[vulner_id]["port"]+","+"Metasploit: use auxiliary/scanner/chargen/chargen_probe")) 
				if (vulners[vulner_id]["pluginID"])=="10079":
					devices.append((vulners[vulner_id]["pluginName"]+","+vulners[vulner_id]["host-ip"]+","+vulners[vulner_id]["port"]+","+"nmap --script ftp-brute -p 21 "+vulners[vulner_id]["host-ip"]))	
				if (vulners[vulner_id]["pluginID"])=="10081":
					devices.append((vulners[vulner_id]["pluginName"]+","+vulners[vulner_id]["host-ip"]+","+vulners[vulner_id]["port"]+","+"Metasploit: use use auxiliary/scanner/portscan/ftpbounce")) 
				if (vulners[vulner_id]["pluginID"])=="10092":
					devices.append((vulners[vulner_id]["pluginName"]+","+vulners[vulner_id]["host-ip"]+","+vulners[vulner_id]["port"]+","+"nmap -A -p 21 "+vulners[vulner_id]["host-ip"]))	
				if (vulners[vulner_id]["pluginID"])=="10437":
					devices.append((vulners[vulner_id]["pluginName"]+","+vulners[vulner_id]["host-ip"]+","+vulners[vulner_id]["port"]+","+"Metasploit: use auxiliary/scanner/nfs/nfsmount"))	
				if (vulners[vulner_id]["pluginID"])=="10539":
					devices.append((vulners[vulner_id]["pluginName"]+","+vulners[vulner_id]["host-ip"]+","+vulners[vulner_id]["port"]+","+"nmap -sU -p 53 --script=dns-recursion "+vulners[vulner_id]["host-ip"]))	
				if (vulners[vulner_id]["pluginID"])=="10595":
					devices.append((vulners[vulner_id]["pluginName"]+","+vulners[vulner_id]["host-ip"]+","+vulners[vulner_id]["port"]+","+"Metasploit: use auxiliary/gather/enum_dns or dig e.g. dig axfr zonetransfer.me @nsztm1.digi.ninja"))	
				if (vulners[vulner_id]["pluginID"])=="10882":
					devices.append((vulners[vulner_id]["pluginName"]+","+vulners[vulner_id]["host-ip"]+","+vulners[vulner_id]["port"]+","+"sudo nmap --script=sshv1.nse -sV -sC "+vulners[vulner_id]["host-ip"]))
				if (vulners[vulner_id]["pluginID"])=="11213":
					devices.append((vulners[vulner_id]["pluginName"]+","+vulners[vulner_id]["host-ip"]+","+vulners[vulner_id]["port"]+","+"sudo nmap --script http-methods "+vulners[vulner_id]["host-ip"]))
				if (vulners[vulner_id]["pluginID"])=="11356":
					devices.append((vulners[vulner_id]["pluginName"]+","+vulners[vulner_id]["host-ip"]+","+vulners[vulner_id]["port"]+","+"Metasploit: use auxiliary/scanner/nfs/nfsmount"))	
				if (vulners[vulner_id]["pluginID"])=="11819":
					devices.append((vulners[vulner_id]["pluginName"]+","+vulners[vulner_id]["host-ip"]+","+vulners[vulner_id]["port"]+","+"sudo nmap -sU -p 69 --script tftp-enum.nse --script-args tftp-enum.filelist=customlist.txt "+vulners[vulner_id]["host-ip"]))	
				if (vulners[vulner_id]["pluginID"])=="12217":
					devices.append((vulners[vulner_id]["pluginName"]+","+vulners[vulner_id]["host-ip"]+","+vulners[vulner_id]["port"]+","+"sudo nmap -sU -p 53 --script dns-cache-snoop.nse --script-args 'dns-cache-snoop.mode=nonrecursive' 1.2.3.4 "+vulners[vulner_id]["host-ip"]))		
				if (vulners[vulner_id]["pluginID"])=="15984":
					devices.append((vulners[vulner_id]["pluginName"]+","+vulners[vulner_id]["host-ip"]+","+vulners[vulner_id]["port"]+","+"Metasploit: use auxiliary/scanner/nfs/nfsmount"))		
				if (vulners[vulner_id]["pluginID"])=="18405":
					devices.append((vulners[vulner_id]["pluginName"]+","+vulners[vulner_id]["host-ip"]+","+vulners[vulner_id]["port"]+","+"nmap -p 3389 --script rdp-enum-encryption "+vulners[vulner_id]["host-ip"]))	
				if (vulners[vulner_id]["pluginID"])=="20007":
					devices.append((vulners[vulner_id]["pluginName"]+","+vulners[vulner_id]["host-ip"]+","+vulners[vulner_id]["port"]+","+"sudo sslscan "+vulners[vulner_id]["host-ip"]+":"+vulners[vulner_id]["port"]))
				if (vulners[vulner_id]["pluginID"])=="26920":
					devices.append((vulners[vulner_id]["pluginName"]+","+vulners[vulner_id]["host-ip"]+","+vulners[vulner_id]["port"]+","+"nmap --script smb-enum-users.nse -p445 "+vulners[vulner_id]["host-ip"]))					
				if (vulners[vulner_id]["pluginID"])=="30218":
					devices.append((vulners[vulner_id]["pluginName"]+","+vulners[vulner_id]["host-ip"]+","+vulners[vulner_id]["port"]+","+"nmap -p 3389 --script rdp-enum-encryption "+vulners[vulner_id]["host-ip"]))	
				if (vulners[vulner_id]["pluginID"])=="34477":
					devices.append((vulners[vulner_id]["pluginName"]+","+vulners[vulner_id]["host-ip"]+","+vulners[vulner_id]["port"]+","+"nmap --script smb-vuln-ms08-067.nse -p445 "+vulners[vulner_id]["host-ip"]))	
				if (vulners[vulner_id]["pluginID"])=="40887":
					devices.append((vulners[vulner_id]["pluginName"]+","+vulners[vulner_id]["host-ip"]+","+vulners[vulner_id]["port"]+","+"Metasploit: use exploit/windows/smb/ms09_050_smb2_negotiate_func_index")) 	
				if (vulners[vulner_id]["pluginID"])=="41028":
					devices.append((vulners[vulner_id]["pluginName"]+","+vulners[vulner_id]["host-ip"]+","+vulners[vulner_id]["port"]+","+"Metasploit: auxiliary/scanner/snmp/snmp_login or auxiliary/scanner/snmp/snmp_enum")) 					
				if (vulners[vulner_id]["pluginID"])=="42256":
					devices.append((vulners[vulner_id]["pluginName"]+","+vulners[vulner_id]["host-ip"]+","+vulners[vulner_id]["port"]+","+"Metasploit: use auxiliary/scanner/nfs/nfsmount")) 
				if (vulners[vulner_id]["pluginID"])=="42263":
					devices.append((vulners[vulner_id]["pluginName"]+","+vulners[vulner_id]["host-ip"]+","+vulners[vulner_id]["port"]+","+"sudo nmap --script telnet-encryption "+vulners[vulner_id]["host-ip"]+" -p"+vulners[vulner_id]["port"])) 
				if (vulners[vulner_id]["pluginID"])=="42411":
					devices.append((vulners[vulner_id]["pluginName"]+","+vulners[vulner_id]["host-ip"]+","+vulners[vulner_id]["port"]+","+"nmap --script smb-enum-shares.nse -p445 "+vulners[vulner_id]["host-ip"]))
				if (vulners[vulner_id]["pluginID"])=="42873":
					devices.append((vulners[vulner_id]["pluginName"]+","+vulners[vulner_id]["host-ip"]+","+vulners[vulner_id]["port"]+","+"sudo sslscan "+vulners[vulner_id]["host-ip"]+":"+vulners[vulner_id]["port"]))	
				if (vulners[vulner_id]["pluginID"])=="51192":
					devices.append((vulners[vulner_id]["pluginName"]+","+vulners[vulner_id]["host-ip"]+","+vulners[vulner_id]["port"]+","+"sudo sslscan "+vulners[vulner_id]["host-ip"]+":"+vulners[vulner_id]["port"]))
				if (vulners[vulner_id]["pluginID"])=="57582":
					devices.append((vulners[vulner_id]["pluginName"]+","+vulners[vulner_id]["host-ip"]+","+vulners[vulner_id]["port"]+","+"sudo sslscan "+vulners[vulner_id]["host-ip"]+":"+vulners[vulner_id]["port"]))
				if (vulners[vulner_id]["pluginID"])=="57608":
					devices.append((vulners[vulner_id]["pluginName"]+","+vulners[vulner_id]["host-ip"]+","+vulners[vulner_id]["port"]+","+"nmap --script smb-security-mode.nse -p445 "+vulners[vulner_id]["host-ip"]))
				if (vulners[vulner_id]["pluginID"])=="57690":
					devices.append((vulners[vulner_id]["pluginName"]+","+vulners[vulner_id]["host-ip"]+","+vulners[vulner_id]["port"]+","+"nmap -p 3389 --script rdp-enum-encryption "+vulners[vulner_id]["host-ip"]))				
				if (vulners[vulner_id]["pluginID"])=="58453":
					devices.append((vulners[vulner_id]["pluginName"]+","+vulners[vulner_id]["host-ip"]+","+vulners[vulner_id]["port"]+","+"nmap -p 3389 --script rdp-enum-encryption "+vulners[vulner_id]["host-ip"]))	
				if (vulners[vulner_id]["pluginID"])=="58987":
					devices.append((vulners[vulner_id]["pluginName"]+","+vulners[vulner_id]["host-ip"]+","+vulners[vulner_id]["port"]+","+"nmap -sV --script=http-php-version "+vulners[vulner_id]["host-ip"]))
				if (vulners[vulner_id]["pluginID"])=="62694":
					devices.append((vulners[vulner_id]["pluginName"]+","+vulners[vulner_id]["host-ip"]+","+vulners[vulner_id]["port"]+","+"ike-scan "+vulners[vulner_id]["host-ip"]+" -M -A --id=vpn"))	
				if (vulners[vulner_id]["pluginID"])=="68931":
					devices.append((vulners[vulner_id]["pluginName"]+","+vulners[vulner_id]["host-ip"]+","+vulners[vulner_id]["port"]+","+"Metasploit: auxiliary/scanner/ipmi/ipmi_cipher_zero "))
				if (vulners[vulner_id]["pluginID"])=="69551":
					devices.append((vulners[vulner_id]["pluginName"]+","+vulners[vulner_id]["host-ip"]+","+vulners[vulner_id]["port"]+","+"sudo sslscan "+vulners[vulner_id]["host-ip"]+":"+vulners[vulner_id]["port"]))	
				if (vulners[vulner_id]["pluginID"])=="70658":
					devices.append((vulners[vulner_id]["pluginName"]+","+vulners[vulner_id]["host-ip"]+","+vulners[vulner_id]["port"]+","+"sudo nmap --script ssh2-enum-algos "+vulners[vulner_id]["host-ip"]))	
				if (vulners[vulner_id]["pluginID"])=="71049":
					devices.append((vulners[vulner_id]["pluginName"]+","+vulners[vulner_id]["host-ip"]+","+vulners[vulner_id]["port"]+","+"sudo nmap --script ssh2-enum-algos "+vulners[vulner_id]["host-ip"]))	
				if (vulners[vulner_id]["pluginID"])=="77026":
					devices.append((vulners[vulner_id]["pluginName"]+","+vulners[vulner_id]["host-ip"]+","+vulners[vulner_id]["port"]+","+"Metasploit: auxiliary/scanner/http/owa_iis_internal_ip"))	
				if (vulners[vulner_id]["pluginID"])=="80101":
					devices.append((vulners[vulner_id]["pluginName"]+","+vulners[vulner_id]["host-ip"]+","+vulners[vulner_id]["port"]+","+"Metasploit: auxiliary/scanner/ipmi/ipmi_dumphashes or auxiliary/scanner/ipmi/ipmi_version"))	
				if (vulners[vulner_id]["pluginID"])=="83875":
					devices.append((vulners[vulner_id]["pluginName"]+","+vulners[vulner_id]["host-ip"]+","+vulners[vulner_id]["port"]+","+"sudo sslscan "+vulners[vulner_id]["host-ip"]+":"+vulners[vulner_id]["port"]))	
				if (vulners[vulner_id]["pluginID"])=="97833":
					devices.append((vulners[vulner_id]["pluginName"]+","+vulners[vulner_id]["host-ip"]+","+vulners[vulner_id]["port"]+","+"nmap -p445 --script smb-vuln-ms17-010 "+vulners[vulner_id]["host-ip"]))	
				if (vulners[vulner_id]["pluginID"])=="97861":
					devices.append((vulners[vulner_id]["pluginName"]+","+vulners[vulner_id]["host-ip"]+","+vulners[vulner_id]["port"]+","+"nmap -sU -pU:123 -Pn -n --script=ntp-monlist "+vulners[vulner_id]["host-ip"]))
				if (vulners[vulner_id]["pluginID"])=="97994":
					devices.append((vulners[vulner_id]["pluginName"]+","+vulners[vulner_id]["host-ip"]+","+vulners[vulner_id]["port"]+","+"nmap -sV --script=http-headers "+vulners[vulner_id]["host-ip"]))
				if (vulners[vulner_id]["pluginID"])=="100464":
					devices.append((vulners[vulner_id]["pluginName"]+","+vulners[vulner_id]["host-ip"]+","+vulners[vulner_id]["port"]+","+"Metasploit: use auxiliary/scanner/smb/smb1"))	
				if (vulners[vulner_id]["pluginID"])=="104743":
					devices.append((vulners[vulner_id]["pluginName"]+","+vulners[vulner_id]["host-ip"]+","+vulners[vulner_id]["port"]+","+"sudo sslscan "+vulners[vulner_id]["host-ip"]+":"+vulners[vulner_id]["port"]))
				if (vulners[vulner_id]["pluginID"])=="105486":
					devices.append((vulners[vulner_id]["pluginName"]+","+vulners[vulner_id]["host-ip"]+","+vulners[vulner_id]["port"]+","+"Metasploit: use auxiliary/scanner/vmware/esx_fingerprint"))	
				if (vulners[vulner_id]["pluginID"])=="149902":
					devices.append((vulners[vulner_id]["pluginName"]+","+vulners[vulner_id]["host-ip"]+","+vulners[vulner_id]["port"]+","+"Metasploit: exploit/linux/http/vmware_vcenter_vsan_health_rce"))
				if (vulners[vulner_id]["pluginID"])=="146825":
					devices.append((vulners[vulner_id]["pluginName"]+","+vulners[vulner_id]["host-ip"]+","+vulners[vulner_id]["port"]+","+"Metasploit: exploit/multi/http/vmware_vcenter_uploadova_rce"))				
				if (vulners[vulner_id]["pluginID"])=="146826":
					devices.append((vulners[vulner_id]["pluginName"]+","+vulners[vulner_id]["host-ip"]+","+vulners[vulner_id]["port"]+","+"Metasploit: exploit/multi/http/vmware_vcenter_uploadova_rce"))
				if (vulners[vulner_id]["pluginID"])=="150163":
					devices.append((vulners[vulner_id]["pluginName"]+","+vulners[vulner_id]["host-ip"]+","+vulners[vulner_id]["port"]+","+"Metasploit: exploit/linux/http/vmware_vcenter_vsan_health_rce"))
				if (vulners[vulner_id]["pluginID"])=="153953":
					devices.append((vulners[vulner_id]["pluginName"]+","+vulners[vulner_id]["host-ip"]+","+vulners[vulner_id]["port"]+","+"sudo nmap --script ssh2-enum-algos "+vulners[vulner_id]["host-ip"]))	
			except:
				pass

		#Output to file if required
		if args.output!="":
			if args.output.endswith(('.csv'))==False:
				args.output = args.output+ ".csv"

			# open the file in the write mode
			with open(args.output, 'w') as f:
				for device in devices:
					f.write(device)
					f.write('\n')

			print("[*] Written File " +args.output)

		if args.output=="":
			#Print output to screen
			for device in devices:
				print(device)

		sys.exit()

#Routine handles Crtl+C gracefully
def signal_handler(signal, frame):
	print ("\nCtrl+C pressed.. exiting...")
	sys.exit()

#Loads up main
if __name__ == '__main__':
	#Setup Signal handler in case of Ctrl+C
	signal.signal(signal.SIGINT, signal_handler)
	#Call main routine.
	main()