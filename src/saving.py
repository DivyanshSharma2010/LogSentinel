import csv
import json

def save_as_csv(data, filename):
    """ Saves a list of dictionary or a list of list to a CSV file"""

    if not data:
        print("No data to save")
        return

    if not filename.endswith('.csv'):
        filename += '.csv'

    try:
        with open(filename, 'w', newline='', encoding="utf-8") as f:

            # CASE 1: Data is a List of Dictionaries (Grok Output)
            if isinstance(data[0], dict):
                headers = data[0].keys()
                writer = csv.DictWriter(f, fieldnames=headers)
                writer.writeheader()
                writer.writerows(data)
                
            # CASE 2: Data is a List of Lists (Simple Rows)
            elif isinstance(data[0], list):
                writer = csv.writer(f)
                writer.writerows(data)
                
            # CASE 3: Data is a single list (A single row)
            else:
                writer = csv.writer(f)
                writer.writerow(data)

        print(f"Success! Saved {len(data)} rows to '{filename}'")
    except IOError as e:
        print(f"Error saving file: {e}")

def save_as_json(data, filename):
    """Saves data in a JSON file"""

    if not data:
        print("No data to save")
        return

    if not filename.endswith('.json'):
        filename += '.json'

    try:
        with open(filename, 'w', encoding="utf-8") as f:

            json.dump(data, f, indent=3, default=str)

    except IOError as e:
        print(f"Error saving JSON file: {e}")
    except TypeError as e:
        print(f"Error serializing data (is it valid JSON?): {e}")