# Scraping CVEDetails Repository

This group of scripts, follow a pipeline that starts with the scrapping of the website [CveDetails](https://www.cvedetails.com) and finnish with the insertion on the database of all the data.

## Repository Structure

The repository is structured as follows:

- **/src**: All the scripts
  - **/emails**: Module that allow to send notifications to email
  - **/modules**: Module with function that allow to work with the database and with all the vulnerabilities for wach project
  - **collect_vulnerabilities**: Download all the cves information from the website
  - **diff_CVE_automatization.py**: Find two consecutive days of the collection mechanism and find the differences between them
  - **find_affected_files.py**: Find the files of each project that contains the vulnerable code
  - **create_file_timeline.py**: Build a timeline with all the files
  - **fix_neutral_code_unit_status_in_affected_files_and_file_timeline.py**: Fix a bug in the output of the last two scripts
  - **insert_new_vulnerabilities_in_database.py**: Insert new vulnerabilities in the database
  - **update_vulnerabilities_in_database.py**: Insert the updates in the database
  - **insert_deleted_vulnerabilities_info_in_database.py**: Insert an information on vulnerabilities that disapear
  - **insert_patches_in_database.py**: Insert the patches form new and updated cves in the database

## How to Use

To use the scripts it is necessary to configure all the basic information in the following files:
1. */src/emails/config/config.json*
2. */src/modules/config/dynamic_config_template.json*
3. */src/modules/config/static_config.json*
This files have the pathes for each repository, the ids of each project on the website, the information for conect to the database and the information needed for sending the notification, etc.

After every configuration, the next order must be follow:
1- **collect_vulnerabilities**: Download all the cves information from the website
2- **diff_CVE_automatization.py**: Find two consecutive days of the collection mechanism and find the differences between them
3- **find_affected_files.py**: Find the files of each project that contains the vulnerable code
4- **create_file_timeline.py**: Build a timeline with all the files
5- **fix_neutral_code_unit_status_in_affected_files_and_file_timeline.py**: Fix a bug in the output of the last two scripts
6- **insert_new_vulnerabilities_in_database.py**: Insert new vulnerabilities in the database
7- **update_vulnerabilities_in_database.py**: Insert the updates in the database
8- **insert_deleted_vulnerabilities_info_in_database.py**: Insert an information on vulnerabilities that disapear
9- **insert_patches_in_database.py**: Insert the patches form new and updated cves in the database

## Contact

For any questions, suggestions, or issues related to this repository, feel free to contact us through the following means:

- Email: [joao.rafael.henriques@gmail.com](mailto:joao.rafael.henriques@gmail.com)
