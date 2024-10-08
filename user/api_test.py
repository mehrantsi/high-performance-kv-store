import time
import requests
import json
import random
import string
from config import API_URL, API_KEY

headers = {
    "Content-Type": "application/json",
    "x-api-key": API_KEY
}

def insert_record(key, value):
    response = requests.post(f"{API_URL}/record", 
                             headers=headers, 
                             json={"key": key, "value": value})
    print(f"Inserted record - Key: {key[:20]}... (length: {len(key)}), Value: {value[:20]}... (length: {len(value)})")
    print(f"Response status code: {response.status_code}")
    return response.status_code == 200

def retrieve_record(key, expected_value=None):
    response = requests.get(f"{API_URL}/record/{key}", headers=headers)
    if response.status_code == 200:
        retrieved_value = response.json()['value']
        print(f"Retrieved record - Key: {key[:20]}... (length: {len(key)}), Value: {retrieved_value[:20]}... (length: {len(retrieved_value)})")
        if expected_value is not None:
            if retrieved_value == expected_value:
                print("Retrieved value matches the expected value.")
            else:
                print("WARNING: Retrieved value does not match the expected value!")
                print(f"Expected: {expected_value[:50]}...")
                print(f"Retrieved: {retrieved_value[:50]}...")
        return retrieved_value
    else:
        print(f"Failed to retrieve record for key: {key[:20]}...")
        print(f"Response status code: {response.status_code}")
        return None

def delete_record(key):
    response = requests.delete(f"{API_URL}/record/{key}", headers=headers)
    print(f"Deleted record with key: {key[:20]}... (length: {len(key)})")
    print(f"Response status code: {response.status_code}")

def partial_update(key, partial_value):
    response = requests.post(f"{API_URL}/record", 
                             headers=headers, 
                             json={"key": key, "value": partial_value, "partialUpdate": True})
    print(f"Partially updated record - Key: {key[:20]}... (length: {len(key)}), Appended: {partial_value[:20]}... (length: {len(partial_value)})")
    print(f"Response status code: {response.status_code}")

def get_stats():
    response = requests.get(f"{API_URL}/stats", headers=headers)
    print("Statistics:")
    print(f"Response status code: {response.status_code}")
    if response.status_code == 200:
        print(json.dumps(response.json(), indent=2))

def generate_random_string(length):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

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
    retrieve_record("key1", "value1")
    retrieve_record("key2", "value2")
    retrieve_record("nonexistent_key")
    print()

    # 3. Update a record
    print("3. Updating a record")
    insert_record("key2", "updated_value2")
    retrieve_record("key2", "updated_value2")
    print()

    # 4. Performing partial update
    print("4. Performing partial update")
    partial_update("key1", "_appended")
    retrieve_record("key1", "value1_appended")
    print()

    # 5. Delete a record
    print("5. Deleting a record")
    delete_record("key3")
    retrieve_record("key3")
    print()

    # 6. Read individual records
    print("6. Reading individual records")
    retrieve_record("key1", "value1_appended")
    retrieve_record("key2", "updated_value2")
    print()

    # 7. Get statistics
    print("7. Getting statistics")
    get_stats()
    print()

    # 8. Test large key and value
    print("8. Testing large key and value")
    large_key = generate_random_string(508) # 512 - 4 for tenant id
    large_value = generate_random_string(100 * 1024)  # 100 KB
    
    print("Inserting large key-value pair")
    if insert_record(large_key, large_value):
        print()

        print("Retrieving large key-value pair")
        retrieved_value = retrieve_record(large_key, large_value)
        if retrieved_value != large_value:
            print("ERROR: Retrieved large value does not match the inserted value!")
        print()
        
        print("Deleting large key-value pair")
        delete_record(large_key)
        print()
        
        print("Attempting to retrieve deleted large key-value pair")
        retrieve_record(large_key)
        print()
    else:
        print("Failed to insert large key-value pair. Skipping related tests.")

    # Get final statistics
    print("Final statistics:")
    get_stats()

if __name__ == "__main__":
    main()
