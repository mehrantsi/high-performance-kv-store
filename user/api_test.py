import requests
import json
from config import API_URL, API_KEY

headers = {
    "Content-Type": "application/json",
    "x-api-key": API_KEY
}

def insert_record(key, value):
    response = requests.post(f"{API_URL}/record", 
                             headers=headers, 
                             json={"key": key, "value": value})
    print(f"Inserted record - Key: {key}, Value: {value}")
    print(f"Response: {response.status_code} - {response.json()}")

def retrieve_record(key):
    response = requests.get(f"{API_URL}/record/{key}", headers=headers)
    if response.status_code == 200:
        print(f"Retrieved record - Key: {key}, Value: {response.json()['value']}")
    else:
        print(f"Failed to retrieve record for key: {key}")
    print(f"Response: {response.status_code} - {response.json()}")

def delete_record(key):
    response = requests.delete(f"{API_URL}/record/{key}", headers=headers)
    print(f"Deleted record with key: {key}")
    print(f"Response: {response.status_code} - {response.json()}")

def partial_update(key, partial_value):
    response = requests.post(f"{API_URL}/record", 
                             headers=headers, 
                             json={"key": key, "value": partial_value, "partialUpdate": True})
    print(f"Partially updated record - Key: {key}, Appended: {partial_value}")
    print(f"Response: {response.status_code} - {response.json()}")

def get_stats():
    response = requests.get(f"{API_URL}/stats", headers=headers)
    print("Statistics:")
    print(f"Response: {response.status_code} - {response.json()}")

def main():
    print("HPKV API Feature Showcase")
    print("=========================\n")

    # 1. Insert records
    print("1. Inserting records")
    insert_record("key1", "value1")
    insert_record("key2", "value2")
    insert_record("key3", "value3")
    print()

    # 2. Retrieve records
    print("2. Retrieving records")
    retrieve_record("key1")
    retrieve_record("key2")
    retrieve_record("nonexistent_key")
    print()

    # 3. Update a record
    print("3. Updating a record")
    insert_record("key2", "updated_value2")
    retrieve_record("key2")
    print()

    # 4. Performing partial update
    print("4. Performing partial update")
    partial_update("key1", "_appended")
    retrieve_record("key1")
    print()

    # 5. Delete a record
    print("5. Deleting a record")
    delete_record("key3")
    retrieve_record("key3")
    print()

    # 6. Read individual records
    print("6. Reading individual records")
    retrieve_record("key1")
    retrieve_record("key2")
    print()

    # 7. Get statistics
    print("7. Getting statistics")
    get_stats()
    print()

if __name__ == "__main__":
    main()
