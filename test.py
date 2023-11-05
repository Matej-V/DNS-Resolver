import subprocess
import os
import difflib

# Global variables
successful_tests = 0
failed_tests = 0
not_defined = 0
folder_number = 1

# Function to run a command and compare its output with the expected output
def test_command(command):
    global successful_tests, failed_tests, not_defined, folder_number

    # Set the paths to the files
    return_code_file = f"./tests/test{folder_number}/return_code.out"
    stdout_file = f"./tests/test{folder_number}/stdout.out"
    stderr_file = f"./tests/test{folder_number}/stderr.out"

    # Run the command and save its output
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    return_code = process.returncode
    print("Output: " + stdout.decode())

    with open(return_code_file, 'r') as rc_file:
        expected_return_code = int(rc_file.read().strip())

    if return_code != expected_return_code:
        print(f"Test '{folder_number}' FAIL: Wrong return code")
        failed_tests += 1
    elif return_code == 0:
        with open(stdout_file, 'r') as sf:
            expected_output = sf.read()
        
        if stdout.decode().strip() == expected_output.strip():
            print(f"Test '{folder_number}' SUCCESS")
            successful_tests += 1
        else:
            print(f"Test '{folder_number}' ended with correct return code, but the result must be compared with reference in file {stdout_file}")
            print(command)
            print(stdout.decode())
            not_defined += 1
    else:
        with open(stderr_file, 'r') as ef:
            expected_error = ef.read()
        
        actual_error = stderr.decode().strip()
        if actual_error == expected_error.strip():
            print(f"Test '{folder_number}' SUCCESS")
            successful_tests += 1
        else:
            print(f"Test '{folder_number}' FAIL: Wrong output")
            print(command)
            diff = difflib.unified_diff(expected_error.splitlines(), actual_error.splitlines(), lineterm='')
            for line in diff:
                print(line)
            
            failed_tests += 1

    print()
    folder_number += 1

# Run tests
test_cases = [
    "./dns -h", # Arguments
    "./dns -r",
    "./dns -s",
    "./dns -s 8.8.8.8",
    "./dns -s 8.8.8.8 -p www.fit.vutbr.cz www.fit.vutbr.cz",
    "./dns -t -s 8.8.8.8 www.fit.vutbr.cz",
    "./dns -s 8.8.8.8 www.fit.vutbr.cz www.fit.vut.cz",
    "./dns -s 8.8.8.8 www.fit.vut.cz", # IPv4 addresses
    "./dns -s 8.8.8.8 www.seznam.cz",
    "./dns -s 8.8.8.8 kazi.fit.vutbr.cz",
    "./dns -6 -s 8.8.8.8 www.fit.vutbr.cz", # IPv6 addresses
    "./dns -r -6 -s 8.8.8.8 www.seznam.cz",
    "./dns -6 -s 2001:67c:1220:808::93e5:80c www.fit.vut.cz", # IPv6 DNS server
    "./dns -s 8.8.8.8 -r halabalala.cz", # SOA record
    "./dns -x -s 8.8.8.8 2001:67c:1220:808::93e5:80c", # Reverse lookup
    "./dns -x -r -s 8.8.8.8 2001:67c:1220:808::93e5:80c",
    "./dns -x -s dns.google 2a02:598:2::1222",
    "./dns -s 8.8.8.8 -6 www.seznam.cz -r", # Mixed arguments
    "./dns -6 -s 8.8.8.8 -r facebook.com",
        
]

if __name__ == "__main__":
    for test_case in test_cases:
        test_command(test_case)
    # Final result output
    print("SUCCESS:", successful_tests)
    print("FAIL:", failed_tests)
    print("UP TO USER TO SAY:", not_defined)
