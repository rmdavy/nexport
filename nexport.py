from collections import OrderedDict
from lxml import etree
import os, signal, sys
import argparse

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
Version 0.1a
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
	p.add_argument("-ms", "--metasploit", dest="metasploit", default="",help="Show items exploitable with Metasploit")
	p.add_argument("-cp", "--compliance", dest="compliance", default="",help="Pull out failed compliance checks")

	args = p.parse_args()

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
				# open the file in the write mode
				with open(args.output, 'w') as f:
					for device in devices:
						f.write(device)
						f.write('\n')

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
			if args.metasploit!="" and args.compliance=="":
				try:
					if (vulners[vulner_id]["metasploit_name"])!="":
						devices.append((vulners[vulner_id]["host-ip"]+","+vulners[vulner_id]["metasploit_name"]))
				except:
					pass


		#Clean up device list to that all items are unique
		devices=list(OrderedDict.fromkeys(devices))

		#If output variable is not empty write to file
		if args.output!="":
			# open the file in the write mode
			with open(args.output, 'w') as f:
				for device in devices:
					f.write(device)
					f.write('\n')

		#Print output to screen
		for device in devices:
			print(device)

		sys.exit()

	#Pull out failed compliance issues from nessus file
	if args.compliance!="":
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

		devices.append("Compliance Check Name\tCompliance Result\tAudit Type\tCompliance Info\tCompliance Solution")

		#Cycle through all vulnerabilities
		for vulner_id in vulners:

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
						cResult=str(vulners[vulner_id]["{http://www.nessus.org/cm}compliance-result"])
						cAudit=str(vulners[vulner_id]["{http://www.nessus.org/cm}compliance-audit-file"])
						cInfo=str(vulners[vulner_id]["{http://www.nessus.org/cm}compliance-info"])
						cSolution=str(vulners[vulner_id]["{http://www.nessus.org/cm}compliance-solution"])

						
						cAudit=cAudit.replace("'",'')
						cAudit=cAudit.replace('[','')
						cAudit=cAudit.replace(']','')

					
						devices.append(cCheck+"\t"+cResult+"\t"+cAudit+"\t"+cInfo+"\t"+cSolution)

				except:
					pass


		#Output to file if required
		if args.output!="":
			# open the file in the write mode
			with open(args.output, 'w') as f:
				for device in devices:
					f.write(device)
					f.write('\n')

			print("[*] Writing File")
			print("[!] Important - file "+args.output+" is TAB delimited not comma delimited")

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