# Scraping CVEDetails Repository

This group of scripts follows a pipeline that starts with the scrapping of the website [CveDetails](https://www.cvedetails.com) and finishes with the insertion of the database of all the data.

## Repository Structure

The repository is structured as follows:

- **/src**: All the scripts
  - **/emails**: Module that allows to send notifications to email
  - **/modules**: Module with function that allows to work with the database and with all the vulnerabilities for each project
  - **collect_vulnerabilities**: Download all the CVES information from the website
  - **diff_CVE_automatization.py**: Find two consecutive days of the collection mechanism and find the differences between them
  - **find_affected_files.py**: Find the files of each project that contain the vulnerable code
  - **create_file_timeline.py**: Build a timeline with all the files
  - **fix_neutral_code_unit_status_in_affected_files_and_file_timeline.py**: Fix a bug in the output of the last two scripts
  - **insert_new_vulnerabilities_in_database.py**: Insert new vulnerabilities in the database
  - **update_vulnerabilities_in_database.py**: Insert the updates in the database
  - **insert_deleted_vulnerabilities_info_in_database.py**: Insert information on vulnerabilities that disappear
  - **insert_patches_in_database.py**: Insert the patches from new and updated CVES in the database

## How to Use

To use the scripts it is necessary to configure all the basic information in the following files:
1- */src/emails/config/config.json*
2- */src/modules/config/dynamic_config_template.json*
3- */src/modules/config/static_config.json* 
These files have the paths for each repository, the IDs of each project on the website, the information for connecting to the database, and the information needed for sending the notification, etc.

After every configuration, the next order must be followed:
1- **collect_vulnerabilities**
2- **diff_CVE_automatization.py**
3- **find_affected_files.py**
4- **create_file_timeline.py**
5- **fix_neutral_code_unit_status_in_affected_files_and_file_timeline.py**
6- **insert_new_vulnerabilities_in_database.py**
7- **update_vulnerabilities_in_database.py**
8- **insert_deleted_vulnerabilities_info_in_database.py**
9- **insert_patches_in_database.py**

## Contact

For any questions, suggestions, or issues related to this repository, feel free to contact us through the following means:

- Email: [joao.rafael.henriques@gmail.com](mailto:joao.rafael.henriques@gmail.com)
