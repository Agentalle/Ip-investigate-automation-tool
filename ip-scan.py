# Updated ip-scan.py

import csv
import os

class FileHandler:
    @staticmethod
    def read_file(file_path):
        try:
            with open(file_path, 'r') as file:
                return file.read()
        except FileNotFoundError:
            print(f"Error: The file {file_path} was not found.")
        except IOError:
            print(f"Error: Could not read the file {file_path}.")

class CSVHandler:
    @staticmethod
    def read_csv(file_path):
        data = []
        try:
            with open(file_path, mode='r') as file:
                csv_reader = csv.reader(file)
                for row in csv_reader:
                    data.append(row)
        except FileNotFoundError:
            print(f"Error: The CSV file {file_path} was not found.")
        except IOError:
            print(f"Error: Could not read the CSV file {file_path}.")
        return data

# Example usage
file_content = FileHandler.read_file('example.txt')

if file_content:
    print(file_content)