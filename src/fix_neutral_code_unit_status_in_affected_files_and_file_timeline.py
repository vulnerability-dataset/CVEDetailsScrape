#!/usr/bin/env python3

"""
	This script updates the CSV files generated after running "find_affected_files.py" and "create_file_timeline.py" by changing the vulnerability
	status of any neutral code unit from 'Yes' to 'No'.
"""

import pandas as pd # type: ignore

from modules.common import log, deserialize_json_container, serialize_json_container
from modules.project import Project

import sys

####################################################################################################

INPUT_1 = "affected-files.csv"
INPUT_2 = "file-timeline.csv"

####################################################################################################

def main(project_to_analizys: str):
	'''
		Function thats fixes a bug on the previous scripts.
		The process will start for the project of the params.
  
		Params:
			project_to_analizys(str): name of the project or an empty string that represents everthing except kernel and mozilla
  	'''

	total_rows = 0
	total_functions = 0
	total_classes = 0

	def set_status_to_neutral(code_unit_list: list, is_function: bool) -> None:
		""" Sets the vulnerability status of a function or class to neutral if it was vulenrable. """

		global total_functions, total_classes
	
		for unit in code_unit_list:
			
			if unit['Vulnerable'] == 'Yes':
				unit.update({'Vulnerable': 'No'})

				if is_function:
					total_functions += 1
				else:
					total_classes += 1

	# Get the information of the projects
	project_list = Project.get_project_list_from_config()

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
		
		# Create the input path
		input_csv_path, _ = project.find_last_diff_cves(project.output_directory_diff_path, project, INPUT_1, "")
		
		if input_csv_path != None:
			
			log.info(f'Fixing the neutral code unit status for the project "{project}" using the information in "{input_csv_path}".')

			affected_files = pd.read_csv(input_csv_path, dtype=str)

			for index, row in affected_files.iterrows():

				neutral_function_list = deserialize_json_container(row['Neutral File Functions'], [])
				neutral_class_list = deserialize_json_container(row['Neutral File Classes'], [])
				
				set_status_to_neutral(neutral_function_list, True) # type: ignore[arg-type]
				set_status_to_neutral(neutral_class_list, False) # type: ignore[arg-type]

				affected_files.at[index, 'Neutral File Functions'] = serialize_json_container(neutral_function_list) # type: ignore[arg-type]
				affected_files.at[index, 'Neutral File Classes'] = serialize_json_container(neutral_class_list) # type: ignore[arg-type]

				total_rows += 1

			affected_files.to_csv(input_csv_path, index=False)

		# The same process to the second input
		input_csv_path, _ = project.find_last_diff_cves(project.output_directory_diff_path, project, INPUT_2, "")
		
		if input_csv_path == None:
			continue
	
		log.info(f'Fixing the neutral code unit status for the project "{project}" using the information in "{input_csv_path}".')

		timeline = pd.read_csv(input_csv_path, dtype=str)

		is_neutral = (timeline['Affected'] == 'Yes') & (timeline['Vulnerable'] == 'No')
		log.info(f'Number of is_neutral: {len(is_neutral)}.')


		for index, row in timeline[is_neutral].iterrows():

			neutral_function_list = deserialize_json_container(row['Affected Functions'], [])
			neutral_class_list = deserialize_json_container(row['Affected Classes'], [])			

			set_status_to_neutral(neutral_function_list, True) # type: ignore[arg-type]
			set_status_to_neutral(neutral_class_list, False) # type: ignore[arg-type]

			timeline.at[index, 'Affected Functions'] = serialize_json_container(neutral_function_list) # type: ignore[arg-type]
			timeline.at[index, 'Affected Classes'] = serialize_json_container(neutral_class_list) # type: ignore[arg-type]

			total_rows += 1

		timeline.to_csv(input_csv_path, index=False)

	result = f'Finished running. Updated {total_rows} rows including {total_functions} functions and {total_classes} classes.'
	log.info(result)
	print(result)


if __name__ == '__main__':
    if len(sys.argv) == 1:
        main("")
    else:
        main(sys.argv[1])