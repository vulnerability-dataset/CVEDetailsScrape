""" 
    This script pick the two most recent csv files from collect_vulnerabilities.py for each project and divide the data in four files:
        equal, new, updated and deleted data. 
    This process find the columns that suffer some update in the updated data.

    This script uses the CSV files generated after running "collect_vulnerabilities.py" to creates its own CSVs.
"""

from datetime import datetime
import os
import csv
import sys
import pandas as pd
from typing import Tuple

from modules.common import log
from modules.project import Project
from modules.database import Database

def verify_content(path: str, path_old: str) -> bool:
    '''
        If check is the file is empty.
        In this cases we have to check if the previous one is not empty too.
        We delete the empty file is the oldest have information.
        
        Params:
            path (str): path to the file
            path_old (str): path to the old file
        Returns:
            bool: true if the file is not empty
    '''
    content = pd.read_csv(path)
    if content.empty:
        content = pd.read_csv(path_old)
        if content.empty:
            os.remove(path)
            return False
    return True

def find_paths(proj_path: str) -> Tuple[str, str]:
    ''' 
        This funtcion receives a path to the cve files and return the two older consecutive days that
        have never been compared.
    
        Params:
                proj_path (str): path to the directory that contains the csv files with the data about cves 
                
        Returns:
                (str): path to the most recent file
                (str): path to the oldest file
    '''
    
    paths_to_return = list()
    files_proj_path = os.listdir(proj_path)
    
    # Iterate for all files of the directory
    for file in files_proj_path:
        
        # We only want the files with "cve.....__.csv" as their name because those are the files that haven't been compared yet
        if "cve" in file and '__' in file:
            file_path = os.path.join(proj_path, file)
            time = os.stat(file_path).st_mtime
            
            # We search to the most old ones
            # This can prevent errors if, for some reason there are more than 2 days without comparation
            if len(paths_to_return) == 0:
                paths_to_return.append([file_path, os.stat(file_path).st_mtime])
            elif len(paths_to_return) == 1:
                if time > paths_to_return[0][1]:
                    paths_to_return.insert(0, [file_path, os.stat(file_path).st_mtime])
                else:
                    paths_to_return.append([file_path, os.stat(file_path).st_mtime])
            elif time < paths_to_return[1][1]:
                paths_to_return.append([file_path, os.stat(file_path).st_mtime])
                paths_to_return.remove(paths_to_return[0])
            elif time < paths_to_return[0][1]:
                paths_to_return.remove(paths_to_return[0])
                paths_to_return.insert(0, [file_path, os.stat(file_path).st_mtime])
    
    if len(paths_to_return) == 0:
        return None, None
    elif len(paths_to_return) == 1:
        return paths_to_return[0][0], ""
    else:
        # We see if the recent are not empty, if is empty we return 2 equal file to complete an equal diff file
        if not verify_content(paths_to_return[0][0], paths_to_return[1][0]):
            return paths_to_return[1][0], paths_to_return[1][0]
              
        # We update the name of the file to remove "__" if both files are valid
        renamed_path = paths_to_return[1][0][:-6] + '.csv'
        os.rename(paths_to_return[1][0], renamed_path)
            
        return paths_to_return[0][0], renamed_path

def read_file(path: str) -> pd.DataFrame:
    '''
        Read a csv file and return the content.
        
        Params:
            path (str): path to the file
            
        Returns:
            (DataFrame): all the lines of the csv file or None if the path are a empty string
    '''
    
    if path != "":
        return pd.read_csv(path, dtype=str)
    return None

def write_file(lines: list, file_name: str, output_directory: str, headers: list) -> None:
    '''
        Write the a csv file in the directory and with the name of the params.
        Use the header to write the received lines.
        
        Params:
            linhas_file (list): list of all cve, each one in dictionary format
            file_name (str): name of the file inside the directory
            output_directory (str): name of the directory where the file will be saved
            headers (list): list of the headers of the file
    '''
    
    if headers is None or lines is None:
        return
    
    # Testing if the directory exists
    if not os.path.isdir(output_directory): 
        os.mkdir(output_directory)
    
    # Build the path to the file
    path_file = os.path.join(output_directory, file_name)
    
    # Write the headers and lines
    with open(path_file, 'w', newline='') as csv_file:
        csv_writer = csv.DictWriter(csv_file, fieldnames=headers)
        csv_writer.writeheader()
        for line in lines:
            csv_writer.writerow(line)
                         
def find_differences_between_two_cve_files(file_recent: pd.DataFrame, file_oldest: pd.DataFrame) -> Tuple[list, list, list, list]:  
    '''
        Receive two DataFrames and gives 4 separate lists with the differences and the similarities between both.
        
        Params:
            file_recent (DataFrame): CVEs from the most recent file
            file_oldest (DataFrame): CVEs from the oldest recent file
        
        Returns:
            (list): new CVEs
            (list): equal CVEs
            (list): missing CVEs
            (list): updated CVEs
    '''

    # Lists to agroup all the CVEs
    cves_updated = list()
    cves_news = list()
    cves_equals = list()
    cves_missing = list()
    
    # Iterate for the recent file
    for index in range(file_recent.shape[0]):
        
        # We use a line from the file and search the same CVE in the other file
        cve = file_recent.iloc[index]
        cve_oldest = file_oldest[file_oldest['CVE'] == cve['CVE']]
        
        # Sometimes, a project can have mulitple products and the same vulnerability belong to both
        # Obtain the line in Series form
        if len(cve_oldest) > 1:
            cve_oldest = file_oldest[file_oldest['CVE'] == cve['CVE']].iloc[0].squeeze()
        else:
            cve_oldest = file_oldest[file_oldest['CVE'] == cve['CVE']].squeeze()
            
        # If the line does not exist in the oldest file it is a new CVE
        if len(cve_oldest) == 0:
            cves_news.append(cve.to_dict())
            
        # If both lines are equal, it is an equal CVE
        # If the "Publication Date" is nan, an error occurs in the download, we assume that it is a similar CVE as well
        elif cve.equals(cve_oldest) or (pd.isna(cve['Publish Date']) or pd.isna(cve_oldest['Publish Date'])):
            cves_equals.append(cve.to_dict())
            
        # Else it is an updated CVE
        else:
            
            # We search for the columns where the differences occur
            columns_with_differences = list()
            
            for column in file_recent.columns:
                
                # If one is nan and the other not, there is a difference
                if pd.isna(cve[column]) or pd.isna(cve_oldest[column]):
                    if not (pd.isna(cve[column]) or pd.isna(cve_oldest[column])):
                        columns_with_differences.append(column)
                        
                # If the columns are different 
                elif cve[column] != cve_oldest[column]:
                    columns_with_differences.append(column)
                    
            # We add the extra column to the dictionary
            dict_aux = cve.to_dict()
            dict_aux['WhatChanged'] = columns_with_differences
            cves_updated.append(dict_aux)
            
    # We iterate now for the oldest file
    for index in range(file_oldest.shape[0]):
        
        # We use a line from the file and search the same CVE in the other file
        cve = file_oldest.iloc[index]
        cve_recent = file_recent[file_recent['CVE'] == cve['CVE']].squeeze()
        
        # If the line does not exist in the most recent file it is a missing CVE
        if len(cve_recent) == 0:
            cves_missing.append(cve.to_dict())
                   
    return cves_news, cves_equals, cves_missing, cves_updated

def main(project_to_analizys: str) -> None:
    '''
        Function thats starts the process.
		The diff will start for the project of the params.
  
		Params:
			project_to_analizys(str): name of the project or an empty string that represents everthing except kernel and mozilla
    '''
    
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

    CSV_HEADER_UPDATED_VULNERABILITIES = [
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
		'SVN URLs', 'SVN Revision Numbers',
        'WhatChanged'
	]
    
    project_list = Project.get_project_list_from_config()
    
    date: str = datetime.now().strftime('%Y-%m-%d')
    
    with Database(buffered=True) as db:
    
        # We iterate for all projects and test if we want to work with each one
        for proj in project_list:
            
            if proj.short_name == project_to_analizys:
                pass
            elif project_to_analizys == "":
                if proj.short_name != 'mozilla' and proj.short_name != 'kernel':
                    pass
                else:
                    log.info(f'The project {proj.short_name} will be skiped.')
                    continue
            else:
                log.info(f'The project {proj.short_name} will be skiped.')
                continue 
            
            log.info(f'Initialize the diff to the project {proj.short_name}')
            
            # Directories needed
            input_directory = proj.output_directory_path
            output_diretory = proj.create_diff_subdirectory()       
            
            # Finding the paths to the files
            path_recent_file, path_old_file = find_paths(input_directory)

            # We need to have at least the recent file 
            if path_recent_file == None:
                log.info(f"No files to compare")
                continue
                
            log.info(f'Files to compare: old - {path_old_file} new - {path_recent_file}')
            
            # Read the files
            lines_recent_file = read_file(path_recent_file)
            # If there is no oldest file we simulate an empty one
            if lines_old_file is None:
                lines_old_file = pd.DataFrame(columns = CSV_HEADER)
            else:
                lines_old_file = read_file(path_old_file)
            
            # Find the differences
            cves_news, cves_equals, cves_missing, cves_updated = find_differences_between_two_cve_files(lines_recent_file, lines_old_file)
            
            # Write the files
            write_file(cves_news, f"{proj.short_name}_novas.csv", output_diretory, CSV_HEADER)
            write_file(cves_equals, f"{proj.short_name}_iguais.csv", output_diretory, CSV_HEADER)
            write_file(cves_missing, f"{proj.short_name}_desaparecidas.csv", output_diretory, CSV_HEADER)
            write_file(cves_updated, f"{proj.short_name}_atualizadas.csv", output_diretory, CSV_HEADER_UPDATED_VULNERABILITIES)
            
            success, _ = db.execute_query(f"INSERT INTO DAILY VALUES ({proj.database_id}, '{date}', {len(cves_news)}, {len(cves_missing)}, {len(cves_updated)}, {len(cves_equals)});");
            if success:
                db.commit()
                
            log.info(f"Stats from {proj}: {len(cves_updated)} updated vulnerabilities, {len(cves_news)} new vulnerabilities, {len(cves_missing)} deleted vulnerabilities and {len(cves_equals)} equal vulnerabilities.")
            log.info(f"{proj.short_name} done!")

if __name__ == '__main__':    
    if len(sys.argv) == 1:
        main("")
    else:
        main(sys.argv[1])