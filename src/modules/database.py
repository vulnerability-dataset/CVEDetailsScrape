#!/usr/bin/env python3

"""
	This module defines a class that represents a MySQL database connection and that contains methods for querying its information.
"""

import os
import subprocess
import sys
from typing import Iterator, Optional, Tuple, Union

from mysql.connector import MySQLConnection, Error as MySQLError # type: ignore
from mysql.connector.cursor import MySQLCursor # type: ignore

from .common import log, GLOBAL_CONFIG, DATABASE_CONFIG

class Database:
	""" Represents a connection to the software vulnerability MySQL database. """

	host: str
	port: str
	user: str
	password: str
	database: str

	connection: MySQLConnection
	cursor: MySQLCursor

	input_directory_path: str

	def __init__(self, config: dict = DATABASE_CONFIG, **kwargs):

		try:
			log.info(f'Connecting to the database with the following configurations: {config}')
			
			for key, value in config.items():
				setattr(self, key, value)
			
			self.connection = MySQLConnection(**config)
			self.cursor = self.connection.cursor(dictionary=True, **kwargs)

			log.info(f'Autocommit is {self.connection.autocommit}.')

			self.input_directory_path = os.path.abspath(GLOBAL_CONFIG['output_directory_path'])

		except MySQLError as error:
			log.error(f'Failed to connect to the database with the error: {repr(error)}')
			sys.exit(1)

	def __enter__(self):
		return self

	def __exit__(self, exception_type, exception_value, traceback):

		try:
			self.cursor.close()
			self.connection.close()
		except MySQLError as error:
			log.error(f'Failed to close the connection to the database with the error: {repr(error)}')

	def execute_query(self, query: str, commit: bool = False, **kwargs) -> Tuple[bool, Optional[int]]:
		""" Executes a given SQL query and optionally commits the results. """

		try:
			self.cursor.execute(query, **kwargs)
			if commit:
				self.connection.commit()
			
			success = True
			error_code = None
		
		except MySQLError as error:
			success = False
			error_code = error.errno
			log.warning(f'Failed to execute the query "{query}" with the error: {repr(error)}')

		return (success, error_code)

	def commit(self) -> bool:
		""" Commits the current transaction. """

		try:
			self.connection.commit()
			success = True
		except MySQLError as error:
			success = False
			log.error(f'Failed to perform the commit with the error: {repr(error)}')

		return success

	def rollback(self) -> bool:
		""" Rolls back the current transaction. """

		try:
			self.connection.rollback()
			success = True
		except MySQLError as error:
			success = False
			log.error(f'Failed to perform the rollback with the error: {repr(error)}')

		return success

	def execute_script(self, script_path: str) -> Tuple[bool, str]:
		""" Executes one or more SQL queries inside a file and returns the output of the MySQL command. """

		arguments = ['mysql',
					f'--host={self.host}', f'--port={self.port}', f'--user={self.user}', f'--password={self.password}',
					'--default-character-set=utf8', '--comments', self.database]
		
		try:
			script_file = open(script_path)
			result = subprocess.run(arguments, stdin=script_file, capture_output=True, text=True)
			success = result.returncode == 0
			output = result.stdout

			if not success:
				command_line_arguments = ' '.join(arguments)
				error_message = result.stderr or result.stdout
				log.error(f'Failed to run the command "{command_line_arguments}" with the error code {result.returncode} and the error message "{error_message}".')

		except Exception as error:
			success = False
			output = ''
			log.error(f'Failed to execute the script "{script_path}" with the error: {repr(error)}')

		return (success, output)

	def call_procedure(self, name: str, *args) -> Tuple[bool, tuple]:
		""" Calls a previously created stored procedure. """

		try:
			output = self.cursor.callproc(name, args)
			success = True
		except Exception as error:
			success = False
			output = ()
			log.error(f'Failed to call the procedure "{name}" with the error: {repr(error)}')

		return (success, output)

	def verify_vector(self, row, index: int, id: int):
		"""Verify if a vector are in the database.

		Args:
			row (pd.Serie): row with all the data
			index (_type_): index of the vector in row 
			id (_type_): V_ID of the CVE

		Returns:
			bool: true if the vector is in the datatbase or false if not or if an error append
		"""
		sucess, error = self.execute_query(
										f'''SELECT * FROM VETORES WHERE 
											TIPO LIKE "{row['Vector Type'].strip('"[]').split(",")[index].strip(" ").strip("'")}" 
											AND ATTACK_VECTOR LIKE "{row['Attack Vector'].strip('"[]').split(",")[index].strip(" ").strip("'")}" 
											AND ACCESS_VECTOR LIKE "{row['Access Vector'].strip('"[]').split(",")[index].strip(" ").strip("'")}" 
											AND ATTACK_COMPLEXITY LIKE "{row['Attack Complexity'].strip('"[]').split(",")[index].strip(" ").strip("'")}"
											AND PRIVILEGES_REQUIRED LIKE "{row['Privileges Required'].strip('"[]').split(",")[index].strip(" ").strip("'")}" 
											AND USER_INTERACTION LIKE "{row['User Interaction'].strip('"[]').split(",")[index].strip(" ").strip("'")}" 
											AND SCOPE LIKE "{row['Scope'].strip('"[]').split(",")[index].strip(" ").strip("'")}"
											AND AUTHENTICATION LIKE "{row['Authentication'].strip('"[]').split(",")[index].strip(" ").strip("'")}" 
											AND GAINED_ACCESS LIKE "{row['Gained Access'].strip('"[]').split(",")[index].strip(" ").strip("'")}" 
											AND CONFIDENTIALITY LIKE "{row['Confidentiality Impact'].strip('"[]').split(",")[index].strip(" ").strip("'")}" 
											AND INTEGRITY LIKE "{row['Integrity Impact'].strip('"[]').split(",")[index].strip(" ").strip("'")}" 
											AND AVALABILITY LIKE "{row['Availability Impact'].strip('"[]').split(",")[index].strip(" ").strip("'")}" 
											AND V_ID = {id} AND BASE_SEVERITY LIKE "{row['Base Severity'].strip('"[]').split(",")[index].strip(" ").strip("'")}" 
											AND EXPLOITABILITY_SCORE LIKE "{row['Exploitable Score'].strip('"[]').split(",")[index].strip(" ").strip("'")}" 
											AND IMPACT_SCORE LIKE "{row['Impact Score'].strip('"[]').split(",")[index].strip(" ").strip("'")}" 
											AND SOURCE LIKE "{row['Source'].strip('"[]').split(",")[index].strip(" ").strip("'")}";
                                           '''
										)
		if sucess and self.cursor.rowcount == 0:
			return False
		return True

	def insert_vector(self, row, index: int, id: int, cvss_rating: float) -> None:
		"""Insert a vector in the database.

		Args:
			row (pd.Serie): row with all the data
			index (_type_): index of the vector in row 
			id (_type_): V_ID of the CVE
		"""
		if not self.verify_vector(row, index, id): 
			success, error_code = self.execute_query(	'''
														INSERT INTO VETORES
														(
															TIPO, ATTACK_VECTOR,
															ACCESS_VECTOR, ACCESS_COMPLEXITY, ATTACK_COMPLEXITY,
															PRIVILEGES_REQUIRED, USER_INTERACTION, SCOPE,
															AUTHENTICATION, GAINED_ACCESS, CONFIDENTIALITY,
															INTEGRITY, AVALABILITY, V_ID, CVSS_SCORE, BASE_SEVERITY, EXPLOITABILITY_SCORE, IMPACT_SCORE, SOURCE
														)
														VALUES
														(
															%(TIPO)s, %(ATTACK_VECTOR)s,
															%(ACCESS_VECTOR)s, %(ACCESS_COMPLEXITY)s, %(ATTACK_COMPLEXITY)s,
															%(PRIVILEGES_REQUIRED)s, %(USER_INTERACTION)s, %(SCOPE)s,
															%(AUTHENTICATION)s, %(GAINED_ACCESS)s, %(CONFIDENTIALITY)s,
															%(INTEGRITY)s, %(AVALABILITY)s, %(V_ID)s,
															%(CVSS_SCORE)s, %(BASE_SEVERITY)s, %(EXPLOITABILITY_SCORE)s, %(IMPACT_SCORE)s, %(SOURCE)s
														);
														''',
														
														params={
															'TIPO': row['Vector Type'].strip("\"[]").split(",")[index].strip(" ").strip("'"),
															'ATTACK_VECTOR': row['Attack Vector'].strip("\"[]").split(",")[index].strip(" ").strip("'"),
															'ACCESS_VECTOR': row['Access Vector'].strip("\"[]").split(",")[index].strip(" ").strip("'"),
															'ACCESS_COMPLEXITY': row['Access Complexity'].strip("\"[]").split(",")[index].strip(" ").strip("'"),
															'ATTACK_COMPLEXITY': row['Attack Complexity'].strip("\"[]").split(",")[index].strip(" ").strip("'"),
															'PRIVILEGES_REQUIRED': row['Privileges Required'].strip("\"[]").split(",")[index].strip(" ").strip("'"),
															'USER_INTERACTION': row['User Interaction'].strip("\"[]").split(",")[index].strip(" ").strip("'"),
															'SCOPE': row['Scope'].strip("\"[]").split(",")[index].strip(" ").strip("'"),
															'AUTHENTICATION': row['Authentication'].strip("\"[]").split(",")[index].strip(" ").strip("'"),
															'GAINED_ACCESS': row['Gained Access'].strip("\"[]").split(",")[index].strip(" ").strip("'"),
															'CONFIDENTIALITY': row['Confidentiality Impact'].strip("\"[]").split(",")[index].strip(" ").strip("'"),
															'INTEGRITY': row['Integrity Impact'].strip("\"[]").split(",")[index].strip(" ").strip("'"),
															'AVALABILITY': row['Availability Impact'].strip("\"[]").split(",")[index].strip(" ").strip("'"),
															'V_ID': id,
															'CVSS_SCORE': cvss_rating,
															'BASE_SEVERITY': row['Base Severity'].strip("\"[]").split(",")[index].strip(" ").strip("'"),
															'EXPLOITABILITY_SCORE': row['Exploitable Score'].strip("\"[]").split(",")[index].strip(" ").strip("'"),
															'IMPACT_SCORE': row['Impact Score'].strip("\"[]").split(",")[index].strip(" ").strip("'"),
															'SOURCE': row['Source'].strip("\"[]").split(",")[index].strip(" ").strip("'")
														}
													)
			if success:
				self.commit()
				log.info(f'Vector inserted for {id}.')
			else:
				log.error(f'Vector not insert with error {error_code}.')
    
	def teste():
		return True