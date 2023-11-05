import subprocess
import os

test_number = 1

def fill_tests(command):
    global test_number
    print(f"Filling test {test_number}")
    
    # Create the test directory
    test_directory = f"./tests/test{test_number}"
    os.makedirs(test_directory, exist_ok=True)
    
    # Run the command and capture the output and return code
    with open(f"{test_directory}/stdout.out", "w") as stdout_file, open(f"{test_directory}/stderr.out", "w") as stderr_file:
        process = subprocess.Popen(command, shell=True, stdout=stdout_file, stderr=stderr_file)
        process.wait()
        return_code = process.returncode
    
    # Write the return code to the file
    with open(f"{test_directory}/return_code.out", "w") as return_code_file:
        return_code_file.write(str(return_code))
    
    test_number += 1

test_cases = [
    "./dns -h", # Arguments
    "./dns -r",
    "./dns -s",
    "./dns -s 8.8.8.8",
    "./dns -s 8.8.8.8 -p www.fit.vutbr.cz www.fit.vutbr.cz",
    "./dns -t -s 8.8.8.8 www.fit.vutbr.cz",
    "./dns -s 8.8.8.8 www.fit.vutbr.cz www.fit.vut.cz",
    "./dns -s kazi.fit.vutbr.cz www.fit.vut.cz", # IPv4 addresses
    "./dns -s 8.8.8.8 www.seznam.cz",
    "./dns -s 8.8.8.8 kazi.fit.vutbr.cz",
    "./dns -6 -s 8.8.8.8 www.fit.vutbr.cz", # IPv6 addresses
    "./dns -r -6 -s kazi.fit.vutbr.cz www.seznam.cz",
    "./dns -6 -s 2001:67c:1220:808::93e5:80c www.fit.vut.cz", # IPv6 DNS server
    "./dns -s 8.8.8.8 -r halabalala.cz", # SOA record
    "./dns -x -s 8.8.8.8 2001:67c:1220:808::93e5:80c", # Reverse lookup
    "./dns -x -r -s kazi.fit.vutbr.cz 2001:67c:1220:808::93e5:80c",
    "./dns -x -s dns.google 2a02:598:2::1222",
    "./dns -s 8.8.8.8 -6 www.seznam.cz -r", # Mixed arguments
    "./dns -6 -s 8.8.8.8 -r facebook.com",
        
]

if __name__ == "__main__":
    for test_case in test_cases:
        fill_tests(test_case)