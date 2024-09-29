import requests
import time
import statistics
import random
import string
import json
from config import API_URL, API_KEY

headers = {
    "Content-Type": "application/json",
    "x-api-key": API_KEY
}

def generate_random_string(length):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def insert_record(key, value):
    start_time = time.time()
    response = requests.post(f"{API_URL}/record", 
                             headers=headers,
                             json={"key": key, "value": value})
    end_time = time.time()
    if response.status_code == 200:
        return (end_time - start_time) * 1000  # Convert to milliseconds
    else:
        print(f"Failed to insert record: {response.text}")
        return None

def retrieve_record(key):
    start_time = time.time()
    response = requests.get(f"{API_URL}/record/{key}", headers=headers)
    end_time = time.time()
    if response.status_code == 200:
        return (end_time - start_time) * 1000  # Convert to milliseconds
    else:
        print(f"Failed to retrieve record: {response.text}")
        return None

def delete_record(key):
    start_time = time.time()
    response = requests.delete(f"{API_URL}/record/{key}", headers=headers)
    end_time = time.time()
    if response.status_code == 200:
        return (end_time - start_time) * 1000  # Convert to milliseconds
    else:
        print(f"Failed to delete record: {response.text}")
        return None

def run_test(num_records):
    write_latencies = []
    read_latencies = []
    delete_latencies = []
    
    print(f"Running test with {num_records} records...")
    
    # Insert records
    for i in range(num_records):
        key = f"key_{num_records}_{i}"
        value = generate_random_string(50)  # Generate a random 50-character string
        latency = insert_record(key, value)
        if latency is not None:
            write_latencies.append(latency)
    
    # Read records
    for i in range(num_records):
        key = f"key_{num_records}_{i}"
        latency = retrieve_record(key)
        if latency is not None:
            read_latencies.append(latency)
    
    # Delete records
    for i in range(num_records):
        key = f"key_{num_records}_{i}"
        latency = delete_record(key)
        if latency is not None:
            delete_latencies.append(latency)
    
    # Calculate statistics
    write_median = statistics.median(write_latencies)
    read_median = statistics.median(read_latencies)
    delete_median = statistics.median(delete_latencies)
    write_std_dev = statistics.stdev(write_latencies)
    read_std_dev = statistics.stdev(read_latencies)
    delete_std_dev = statistics.stdev(delete_latencies)
    
    print(f"Results for {num_records} records:")
    print(f"Write         - Median Latency: {write_median:.3f} ms, Std Dev: {write_std_dev:.3f} ms")
    print(f"Read          - Median Latency: {read_median:.3f} ms, Std Dev: {read_std_dev:.3f} ms")
    print(f"Delete        - Median Latency: {delete_median:.3f} ms, Std Dev: {delete_std_dev:.3f} ms")

def main():
    sample_sizes = [100, 1000, 10000]
    
    for size in sample_sizes:
        run_test(size)
        print()

if __name__ == "__main__":
    main()
