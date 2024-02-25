#!/usr/bin/env python3

"""
	This script collects any vulnerabilities associated with the five C/C++ projects by scraping the CVE Details website.
	
	This information includes the CVE identifier, publish date, CVSS score, various impacts, vulnerability types, the CWE ID, and
	the URLs to other relevant websites like a project's Bugzilla or Security Advisory platforms.

	For each project, this information is saved to a CSV file.
"""

import csv
import sys

from modules.common import log
from modules.project import Project
from emails.send_email import Email

####################################################################################################
def send_notification(proj: str) -> None:
    '''
		Sends a notification to email.
	
		Params:
			proj(str): name of the project 
    '''
    email = Email()
    email.start()
    email.send("[AUTO] COLLECT_VULNERABILITIES", f"The collection has just started for project {proj}.")


def main(project_to_analizys: str) -> None:
	'''
		Function thats starts the process.
		The collection will start for the project of the params.
  
		Params:
			project_to_analizys(str): name of the project or an empty string that represents everthing except kernel and mozilla
  	'''
   
	# Get the information of the projects
	project_list = Project.get_project_list_from_config()
	Project.debug_ensure_all_project_repositories_were_loaded(project_list)

	# Iterate for each one and continue only if the the params correspond
	for project in project_list:
		
		if project.short_name == project_to_analizys:
			pass
		elif project_to_analizys == "":
			if project.short_name != 'mozilla' and project.short_name != 'kernel':
				pass	
			else:
				log.info(f'The project {project.short_name} will be skiped.')
				continue
		else:
			log.info(f'The project {project.short_name} will be skiped.')
			continue
		
		CSV_HEADER = [
			'CVE', 'CVE URL',
			
			'Publish Date', 'Last Update Date',

			'CVSS Score', 'Base Severity', 'Exploitable Score', 'Impact Score', 'Source',

			'Vector Type',
			'Confidentiality Impact', 'Integrity Impact', 'Availability Impact', 
			'Access Complexity', 'Authentication', 'Access Vector',
			'Attack Vector', 'Attack Complexity', 'Privileges Required', 'User Interaction', 'Scope',
			'Gained Access', 'Vulnerability Types', 'CWE',
			
			'Affected Product Versions',

			'Bugzilla URLs', 'Bugzilla IDs',
			'Advisory URLs', 'Advisory IDs', 'Advisory Info',
			'Git URLs', 'Git Commit Hashes',
			'SVN URLs', 'SVN Revision Numbers'
		]
  
		# Create the output paths
		project.create_output_subdirectory()
		output_csv_path = project.get_base_output_csv_path('cve')
		
		# Start collecting and writting the vulnerabilities
		with open(output_csv_path, 'w', newline='') as csv_file:
			
			csv_writer = csv.DictWriter(csv_file, fieldnames=CSV_HEADER)
			csv_writer.writeheader()
			
			# For each vulnerability scraped from the website
			for cve in project.scrape_vulnerabilities_from_cve_details():
				
				cve.serialize_containers()
				
				csv_row = {
					'CVE': cve.id, 'CVE URL': cve.url,

					'Publish Date': cve.publish_date, 'Last Update Date': cve.last_update_date,

					'CVSS Score': cve.cvss_score, 'Base Severity': cve.base_severity, 'Exploitable Score': cve.exploitable_score, 'Impact Score': cve.impact_soure, 'Source': cve.source,
					
					'Vector Type': cve.vector_type,
					'Confidentiality Impact': cve.confidentiality_impact, 'Integrity Impact': cve.integrity_impact,
					'Availability Impact': cve.availability_impact, 'Access Complexity': cve.access_complexity, 'Authentication': cve.authentication,
					'Access Vector': cve.access_vector,
					'Attack Vector': cve.attack_vector, 'Attack Complexity': cve.attack_complexity, 'Privileges Required': cve.privileges_required, 'User Interaction': cve.user_interaction, 'Scope': cve.scope,
					'Gained Access': cve.gained_access, 'Vulnerability Types': cve.vulnerability_types, 'CWE': cve.cwe,

					'Affected Product Versions': cve.affected_products,

					'Bugzilla URLs': cve.bugzilla_urls, 'Bugzilla IDs': cve.bugzilla_ids,
					'Advisory URLs': cve.advisory_urls, 'Advisory IDs': cve.advisory_ids, 'Advisory Info': cve.advisory_info,
					'Git URLs': cve.git_urls, 'Git Commit Hashes': cve.git_commit_hashes,
					'SVN URLs': cve.svn_urls, 'SVN Revision Numbers': cve.svn_revision_numbers
				}
				
				csv_writer.writerow(csv_row)
				
		log.info(f'Finished running for the project "{project}".')

	log.info('Finished running.')
	print('Finished running.')


if __name__ == '__main__':
    
    # We send a notification to email before the process starts
    if len(sys.argv) == 1:
        send_notification("all")
        main("")
    else:
        send_notification(sys.argv[1])
        main(sys.argv[1])