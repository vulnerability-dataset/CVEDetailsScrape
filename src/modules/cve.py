#!/usr/bin/env python3

"""
	This module defines a class that represents a software vulnerability and that contains methods for scraping its data from the CVE Details website.
"""

import time
import re
from typing import TYPE_CHECKING, Callable, Optional
from urllib.parse import urlsplit, parse_qsl

if TYPE_CHECKING:
	from .project import Project

import bs4 # type: ignore

from .common import log, remove_list_duplicates, serialize_json_container
from .scraping import ScrapingManager, ScrapingRegex

####################################################################################################

class Cve:
	""" Represents a vulnerability (CVE) scraped from the CVE Details website. """

	CVE_DETAILS_SCRAPING_MANAGER: ScrapingManager = ScrapingManager('https://www.cvedetails.com')

	id: str
	url: str
	project: 'Project'

	publish_date: Optional[str]
	last_update_date: Optional[str]

	cvss_score: 				Optional[list]
	base_severity: 				Optional[list]
	exploitable_score:			Optional[list]
	impact_score: 				Optional[list]
	impact_soure: 				Optional[list]
	source: 					Optional[list]
	
	vector_type:				Optional[list]
	confidentiality_impact: 	Optional[list]
	integrity_impact: 			Optional[list]
	availability_impact: 		Optional[list]
 
	access_complexity: 			Optional[list]
	attack_complexity: 			Optional[list]
	authentication: 			Optional[list]
	access_vector: 				Optional[list]
	attack_vector: 				Optional[list]
	privileges_required:		Optional[list]
	user_interaction:			Optional[list]
	scope:						Optional[list]
	gained_access: 				Optional[list]
 
	vulnerability_types: 		Optional[list]
	cwe: 						Optional[list]

	affected_products: dict

	bugzilla_urls: list
	bugzilla_ids: list
	advisory_urls: list
	advisory_ids: list

	advisory_info: dict

	git_urls: list
	git_commit_hashes: list
	svn_urls: list
	svn_revision_numbers: list

	def __init__(self, id: str, project: 'Project'):
		self.id = id
		self.url = f'https://www.cvedetails.com/cve/{self.id}'
		self.project = project

		self.cve_details_soup = None

		self.publish_date = None
		self.last_update_date = None

		self.cvss_score = []
		self.base_severity = []
		self.exploitable_score = []
		self.impact_soure = []
		self.source = []
		self.vector_type = []
		self.access_vector = []
		self.attack_vector = []
		self.attack_complexity = []
		self.privileges_required = []
		self.user_interaction = []
		self.scope = []
		self.confidentiality_impact = []
		self.integrity_impact = []
		self.availability_impact = []
		self.access_complexity = []
		self.authentication = []
		self.gained_access = []
		self.vulnerability_types = None
		self.cwe = None

		self.affected_products = {}

		self.bugzilla_urls = []
		self.bugzilla_ids = []
		self.advisory_urls = []
		self.advisory_ids = []

		self.advisory_info = {}

		self.git_urls = []
		self.git_commit_hashes = []
		self.svn_urls = []
		self.svn_revision_numbers = []

	def __str__(self):
		return self.id

	def download_cve_details_page(self, link:str = None):
		""" Downloads the CVE's page from the CVE Details website. """

		if link is not None:
			response = Cve.CVE_DETAILS_SCRAPING_MANAGER.download_page(self.url)
			texto = bs4.BeautifulSoup(response.text, 'html.parser')
			return texto

		response = Cve.CVE_DETAILS_SCRAPING_MANAGER.download_page(self.url)
		if response is not None:
			self.cve_details_soup = bs4.BeautifulSoup(response.text, 'html.parser')
		
		return response is not None

	def scrape_dates_from_page(self):
		""" Scrapes any date values from the CVE's page. """

		"""
		<div class="col-auto flex-fill">			
			<div class="d-inline-block  py-1">
				<span class="ssc-text-secondary p-1">Published</span>
				2023-02-03 06:15:10			
    		</div>
			<div class="d-inline-block  py-1">
				<span class="ssc-text-secondary  p-1">Updated</span> 
				2023-03-02 16:15:14			
    		</div>
			<div class="d-inline-block  py-1">
				<span class="ssc-text-secondary  p-1">Source</span> 
				<a href="/vulnerability-list/assigner-1/cve-mitre.org.html" title="CVEs created by MITRE cve@mitre.org">MITRE</a>			
    		</div>
		</div>
		"""
  
		for i in range(1, 4):
			dates = self.cve_details_soup.find('div', class_='col-auto flex-fill').get_text(strip=True)

			if dates is None:
				log.warning(f'--> {i}º error. No dates found for {self}.')
				time.sleep(10)
			else:
				break
		
		if dates is None:
			return

		cve_dates = {}
		lista = dates.split(' ')
		cve_dates['Published'] = lista[0][len('Published'):]
		cve_dates['Updated'] = lista[1][len('21:29:00Updated'):]
  
		self.publish_date = cve_dates.get('Published')
		self.last_update_date = cve_dates.get('Updated')

	def scrape_basic_attributes_from_page(self):
		""" Scrapes any basic attributes from the CVE's page. """

		"""
		<div class="bg-white  ps-2 border-top table-responsive">
			<table class="table table-borderless">
				<thead>
					<tr class="align-top">
						<th class="fw-medium">Base Score</th>
						<th class="fw-medium">Base Severity</th>
						<th class="fw-medium">CVSS Vector</th>
						<th class="fw-medium">Exploitability Score</th>
						<th class="fw-medium">Impact Score</th>
						<th class="fw-medium">Score Source</th>
					</tr>
				</thead>
				<tbody>
					<tr>
						<td class="ps-2">
							<div class="cvssbox score_7">7.5</div>								
						</td>
						<td class="ps-2">
							HIGH								
						</td>
						<td class="ps-2">
							<a title="Show CVSS vector details" href="javascript:showhide('cvss_details_row_1')" role="button">
								AV:N/AC:L/Au:N/C:P/I:P/A:P								
							</a>
						</td>
						<td class="ps-2">
							<div class="cvssbox score_10">10.0</div>								
						</td>
						<td class="ps-2">
							<div class="cvssbox score_6">6.4</div>								
						</td>
						<td>
							NIST
       					</td>
					</tr>
					<tr id="cvss_details_row_1" style="display:none">
						<td colspan="6">
							<div class="d-flex flex-row justify-content-evenly text-secondary d-grid gap-3">
								<div>Access Vector: Network</div>
								<div>Access Complexity: Low</div>
								<div>Authentication: None</div>
								<div>Confidentiality Impact: Partial</div>
								<div>Integrity Impact: Partial</div>
								<div>Availability Impact: Partial</div>								
       						</div>
						</td>
					</tr>
				</tbody>
			</table>
		</div>
		<h2>CWE ids for CVE-2023-25139</h2>
		<ul class="list-group border-0 rounded-0">			
			<li class="list-group-item list-group-item-action border-0 border-top">
				<div>
					<a href="/cwe-details/787/Out-of-bounds-Write.html" title="CWE-787 - CWE definition">CWE-787 Out-of-bounds Write</a>					
				</div>
				<div class="ms-1">
					The product writes data past the end, or before the beginning, of the intended buffer.	
				</div>
				<div class="ssc-text-secondary ms-1">
					Assigned by: nvd@nist.gov (Primary)
				</div>
			</li>
		</ul>
		"""

		# Find the table of scores
		scores_atributes = self.cve_details_soup.find('table', class_='table table-borderless')
		cve_attributes = {}

		if scores_atributes is not None:

			# We search for all "tr", that means all table entries 
			attributes_lines = scores_atributes.find_all('tr')
   
			# We jump the first and iterate 2-2 because in the fisrt we have th information of everything and in the second the detailed vector
			for i in range(1, len(attributes_lines), 2):
				help_attributes = attributes_lines[i]
				help_attributes_open_vector = attributes_lines[i+1]
				scores_atributes_td = help_attributes.find_all('td')
				scores_atributes_td = [td.get_text(strip=True) for td in scores_atributes_td]
				scores_atributes_th = scores_atributes.find_all('th')
				scores_atributes_th = [th.get_text(strip=True) for th in scores_atributes_th]

				for th, td in zip(scores_atributes_th, scores_atributes_td):
					
					if th == 'CVSS Vector':

						if 'CVSS' in td:
							cve_attributes['CVSS SCORE'] = td.split('/')[0][5:]
			
						scores_vector = help_attributes_open_vector.find('div', class_='d-flex flex-row justify-content-evenly text-secondary d-grid gap-3')
						scores_vector_ids = [div.get_text(strip=True) for div in scores_vector]
			
						for id in scores_vector_ids[1:-1]:
							lista = id.split(': ')
							cve_attributes[lista[0]] = lista[1]
							
					else:
						cve_attributes[th] = td

				self.vector_type.append(cve_attributes.get('CVSS SCORE') if cve_attributes.get('CVSS SCORE') is not None else 'Antigo')
				self.cvss_score.append(cve_attributes.get('Base Score'))
				self.base_severity.append(cve_attributes.get('Base Severity'))
				self.impact_soure.append(cve_attributes.get('Impact Score'))
				self.exploitable_score.append(cve_attributes.get('Exploitability Score'))
				self.source.append(cve_attributes.get('Source'))
				self.confidentiality_impact.append(cve_attributes.get('Confidentiality') if cve_attributes.get('Confidentiality') is not None else cve_attributes.get('Confidentiality Impact'))  
				self.integrity_impact.append(cve_attributes.get('Integrity') if cve_attributes.get('Integrity') is not None else cve_attributes.get('Integrity Impact')) 		 
				self.availability_impact.append(cve_attributes.get('Availability') if cve_attributes.get('Availability') is not None else cve_attributes.get('Availability Impact')) 	
				self.access_complexity.append(cve_attributes.get('Access Complexity')) 		
				self.authentication.append(cve_attributes.get('Authentication')) 		
				self.access_vector.append(cve_attributes.get('Access Vector'))
				self.attack_vector.append(cve_attributes.get('Attack Vector'))
				self.attack_complexity.append(cve_attributes.get('Attack Complexity'))
				self.privileges_required.append(cve_attributes.get('Privileges Required'))
				self.user_interaction.append(cve_attributes.get('User Interaction'))
				self.scope.append(cve_attributes.get('Scope'))
				self.gained_access.append(cve_attributes.get('Gained Access'))

		# CVE types are on top of the page, a different place from the table of attributes
		# <span class="ssc-vuln-cat">Overflow</span>
		types = self.cve_details_soup.find_all('span', class_='ssc-vuln-cat')
		cve_attributes["Vulnerability Type(s)"] = []
		
		if len(types) > 0:
			for i in types:
				cve_attributes["Vulnerability Type(s)"].append(i.get_text(strip=True))
			self.vulnerability_types 	= cve_attributes.get('Vulnerability Type(s)')

		cwes = []
		cwe_numbers = self.cve_details_soup.find(string=f'CWE ids for {self.id}')
		if cwe_numbers is not None:
			cwe_numbers_li = cwe_numbers.find_next('ul', class_='list-group')
			cwe_number = cwe_numbers_li.find_all('a')
			for cwe in cwe_number:
				if cwe is not None:
					cwe = cwe.get_text(strip=True).split()[0][4:]
					if cwe is not None and cwe.isnumeric():
						cwes.append(int(cwe))
      
		self.cwe = cwes

	def scrape_affected_product_versions_from_page(self):
		""" Scrapes any affected products and their versions from the CVE's page. """

		"""
		<h2>Products affected by CVE-2023-25139</h2>
		<div style="overflow-x: scroll">
  			<ul class="list-group border-0 rounded-0">
     			<li class="list-group-item list-group-item-action border-0 border-top">
        			<div>
           				<a href="/vendor/72/GNU.html" title="Details for GNU">GNU</a>
               				» 
               			<a href="/version-list/72/767/1/GNU-Glibc.html" title="GNU Glibc versions list">Glibc</a> 
                  			» 
                  		<span class="text-secondary">Version:</span> 
                    		2.37        
                    	<div class="d-inline-block ms-2"></div>
                    </div>
                    <div class="row">
                     	<div class="col-md-8 text-secondary">
                      		cpe:2.3:a:gnu:glibc:2.37:*:*:*:*:*:*:*
                        </div>
                    	<div class="col-md-4 text-end"> 
                    		<a href="/version-search.php?cpeMatchCriteriaId=ac1acc29-6d0b-4599-9591-6de176404d6f" title="Matching product versions">Matching versions</a>
                    	</div>
                	</div>
            	</li>
            </ul>
        </div>
		"""
  
		products_table = self.cve_details_soup.find(string=f'Products affected by {self.id}')
  
		if products_table is None:
			log.warning(f'--> No products table found for {self}.')
			return

		products_table = products_table.find_all_next('li', class_="list-group-item list-group-item-action border-0 border-top")

		for product_index in products_table:

			def get_column_value_and_url(name, num):
				""" Gets a specific cell value and any URL it references from the current row given its column name.. """

				if num != None:
					try:
						info = product_index.find_all('a')[num]
						value = info.get_text(strip=True)
						url = product_index.find_all('a', href=True)[num]
					except:
						return None, None
				else:
					try:	
						info = product_index.find('div').get_text(strip=True).split(':')[1]
						value = info
					except:
						info = product_index.find_all('span')
						value = ""
						for i in info:
							value += i.get_text(strip=True) + ' '
					url = None
    
				if value in ['', '-']:
					value = None

				if url is not None:
					url = url['href']

				return value, url

			_, vendor_url  = get_column_value_and_url('vendor', 0)
			product, product_url = get_column_value_and_url('product', 1)
			version, _ = get_column_value_and_url('version', None)

			vendor_pattern = f'/{self.project.vendor_id[self.project.index_list_vendor_product]}/'
			product_pattern = f'/{self.project.product_id[self.project.index_list_vendor_product]}/' if self.project.product_id[self.project.index_list_vendor_product] is not None else ''
			
			# Check if the vendor and product belong to the current project.
			if vendor_pattern in vendor_url and product_pattern in product_url:

				if product not in self.affected_products:
					self.affected_products[product] = []
				
				if version is not None and version not in self.affected_products[product]:
					self.affected_products[product].append(version)

	def scrape_references_from_page(self):
		""" Scrapes any references and links from the CVE's page. """

		"""
		<h2>References for CVE-2023-25139</h2>
		<div style="overflow-x: scroll">
			<ul class="list-group rounded-0">
				<li class="list-group-item border-0 border-top list-group-item-action">
							<div class="ssc-text-secondary d-inline-block pe-4"></div>
						</div>
						<div class="col-lg-4 text-end py-1 ssc-small"></div>
					</div>
				</li>
			</ul>
		</div>
		"""

		def list_all_urls(url_regex: str, url_handler: Callable = None):
			""" Creates a list of URL that match a regex (or a list of regexes). If a handler method is passed as the second argument, then it
			will be called for each URL in order to create and return a secondary list. This may be used to extract specific parts of the URL."""

			references_table = self.cve_details_soup.find(string=f'References for {self.id}')
			if references_table is None:
				log.warning(f'--> No references table found for {self}.')
				return [], []

			references_table = references_table.find_next('ul', class_='list-group rounded-0')
			a_list = references_table.find_all('a', href=url_regex)	

			url_list = []
			for a in a_list:
				url = a['href']
				if re.search(self.project.url_pattern, url, re.IGNORECASE):
					url_list.append(url)

			secondary_list = []
			if url_handler is not None:
				for url in url_list:
					secondary_value = url_handler(url)
					if secondary_value is not None:
						secondary_list.append(secondary_value)

			return url_list, secondary_list

		def get_query_param(url: str, query_key_list: list) -> Optional[str]:
			""" Gets the value of the first parameter in a URL's query segment given a list of keys to check. """
			
			split_url = urlsplit(url)
			params = dict(parse_qsl(split_url.query))
			result = None
			
			for query_key in query_key_list:
				result = params.get(query_key)
				if result is not None:
					break

			return result

		"""
			Various helper methods to handle specific URLs from different sources.
		"""
  
		def handle_django_urls(url: str) -> Optional[str]:
			if url is not None:
				response = Cve.CVE_DETAILS_SCRAPING_MANAGER.download_page(url)
				texto = bs4.BeautifulSoup(response.text, 'html.parser')
				text_block = texto.find_all(class_="simple")
				if len(text_block) > 1:
					text_block = text_block[1]
				else:
					return
				git_url = text_block.find_all('a', href=True)
				if len(git_url) > 0:
					git_url = git_url[0]['href']
				else:
					print(url)
					return
				split_url = urlsplit(git_url)
				path_components = split_url.path.rsplit('/')
				commit_hash = path_components[-1]
     
				if commit_hash is not None and not ScrapingRegex.GIT_COMMIT_HASH.match(commit_hash):
					commit_hash = None
			
				if commit_hash is None:
					log.error(f'--> Could not find a valid commit hash in "{url}".')
				
				return commit_hash

		def handle_bugzilla_urls(url: str) -> Optional[str]:
			id = get_query_param(url, ['id', 'bug_id'])
			
			if id is None:
				log.error(f'--> Could not find a valid Bugzilla ID in "{url}".')

			return id

		def handle_advisory_urls(url: str) -> Optional[str]:
			split_url = urlsplit(url)
			id = None

			for regex in [ScrapingRegex.MFSA_ID, ScrapingRegex.XSA_ID, ScrapingRegex.APACHE_SECURITY_ID]:
				match = regex.search(split_url.path)
				if match is not None:
					id = match.group(1)

					if regex is ScrapingRegex.MFSA_ID:
						id = id.upper()
						id = id.replace('MFSA', 'MFSA-')
					elif regex is ScrapingRegex.XSA_ID:
						id = 'XSA-' + id
					elif regex is ScrapingRegex.APACHE_SECURITY_ID:
						id = 'APACHE-' + id[0] + '.' + id[1:]

					break

			if id is None:
				log.error(f'--> Could not find a valid advisory ID in "{url}".')

			return id

		def handle_git_urls(url: str) -> Optional[str]:
			commit_hash = get_query_param(url, ['id', 'h'])

			if commit_hash is None:
				split_url = urlsplit(url)
				path_components = split_url.path.rsplit('/')
				commit_hash = path_components[-1]

			# If the hash length is less than 40, we need to refer to the repository
			# to get the full hash.
			if commit_hash is not None and len(commit_hash) < ScrapingRegex.GIT_COMMIT_HASH_LENGTH:
				commit_hash = self.project.find_full_git_commit_hash(commit_hash)

			if commit_hash is not None and not ScrapingRegex.GIT_COMMIT_HASH.match(commit_hash):
				commit_hash = None
			
			if commit_hash is None:
				log.error(f'--> Could not find a valid commit hash in "{url}".')
			
			return commit_hash

		def handle_svn_urls(url: str) -> Optional[str]:
			revision_number = get_query_param(url, ['rev', 'revision', 'pathrev'])

			if revision_number is not None:

				# In some rare cases, the revision number can be prefixed with 'r'.
				# As such, we'll only extract the numeric part of this value.
				match = ScrapingRegex.SVN_REVISION_NUMBER.search(revision_number)
				if match is not None:
					# For most cases, this is the same value.
					revision_number = match.group(1)
				else:
					# For cases where the query parameter was not a valid number.
					revision_number = None

			if revision_number is None:
				log.error(f'--> Could not find a valid revision number in "{url}".')

			return revision_number

		self.bugzilla_urls, self.bugzilla_ids 		= list_all_urls(ScrapingRegex.BUGZILLA_URL, handle_bugzilla_urls)
		self.advisory_urls, self.advisory_ids 		= list_all_urls([ScrapingRegex.MFSA_URL, ScrapingRegex.XSA_URL, ScrapingRegex.APACHE_SECURITY_URL], handle_advisory_urls)

		self.git_urls, self.git_commit_hashes 		= list_all_urls([ScrapingRegex.GIT_URL, ScrapingRegex.GITHUB_URL], handle_git_urls)
		help_git_urls, help_git_commit_hashes 		= list_all_urls(ScrapingRegex.DJANGO_GIT, handle_django_urls)
		self.git_urls += help_git_urls
		self.git_commit_hashes += help_git_commit_hashes
		self.svn_urls, self.svn_revision_numbers 	= list_all_urls(ScrapingRegex.SVN_URL, handle_svn_urls)

	def remove_duplicated_values(self):
		""" Removes any duplicated values from specific CVE attributes that contain lists. """

		self.vulnerability_types 	= remove_list_duplicates(self.vulnerability_types)

		self.bugzilla_urls 			= remove_list_duplicates(self.bugzilla_urls)
		self.bugzilla_ids 			= remove_list_duplicates(self.bugzilla_ids)
		self.advisory_urls 			= remove_list_duplicates(self.advisory_urls)
		self.advisory_ids 			= remove_list_duplicates(self.advisory_ids)

		self.git_urls 				= remove_list_duplicates(self.git_urls)
		self.git_commit_hashes 		= remove_list_duplicates(self.git_commit_hashes)
		self.svn_urls 				= remove_list_duplicates(self.svn_urls)
		self.svn_revision_numbers 	= remove_list_duplicates(self.svn_revision_numbers)

	def serialize_containers(self):
		""" Serializes specific CVE attributes that contain lists or dictionaries using JSON. """

		self.vulnerability_types 	= serialize_json_container(self.vulnerability_types)

		self.affected_products 		= serialize_json_container(self.affected_products)

		self.bugzilla_urls 			= serialize_json_container(self.bugzilla_urls)
		self.bugzilla_ids 			= serialize_json_container(self.bugzilla_ids)
		self.advisory_urls 			= serialize_json_container(self.advisory_urls)
		self.advisory_ids 			= serialize_json_container(self.advisory_ids)

		self.advisory_info 			= serialize_json_container(self.advisory_info)

		self.git_urls 				= serialize_json_container(self.git_urls)
		self.git_commit_hashes 		= serialize_json_container(self.git_commit_hashes)
		self.svn_urls 				= serialize_json_container(self.svn_urls)
		self.svn_revision_numbers 	= serialize_json_container(self.svn_revision_numbers)

if __name__ == '__main__':
	pass
#!/usr/bin/env python3

"""
#!/usr/bin/env python3

"""
