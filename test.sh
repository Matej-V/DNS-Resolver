##
# File: test.sh
# Brief: Test script for ISA DNS resolver project
# Author: Matej Vadovic, xvadov01
##

# Global variables
successful_tests=0
failed_tests=0
folder_number=1

# Function to run a command and compare its output with the expected output
test_command() {
    local command="$1"

    # Set the paths to the files
    return_code_file="./tests/test$folder_number/return_code.out"
    stdout_file="./tests/test$folder_number/stdout.out"
    stderr_file="./tests/test$folder_number/stderr.out"

    # Run the command and save its output
    local return_code
    local command_output
    command_output=$(eval "$command" 2> >(tee "$stderr_file"))

    return_code=$?

    # Sometimes the order of each answer may vary, but the result is correct because it contains all the expected answers. Therefore, I will sort them first and then compare. The disadvantage is that lines between sections can be shuffled.
    if [ "$return_code" -ne "$(cat "$return_code_file")" ]; then
        echo "Test '$folder_number' neúspešný: Návratový kód sa nezhoduje"
        ((failed_tests++))
    elif [ "$return_code" -eq 0 ]; then
        if diff -q <(sort "$stdout_file") <(echo "$command_output" | sort) > /dev/null; then
            echo "Test '$folder_number' úspešný"
            ((successful_tests++))
        else
            echo "Test '$folder_number' neúspešný: Obsah stdout súboru sa nezhoduje"
            ((failed_tests++))
            diff -Bw <(sort "$stdout_file") <(echo "$command_output" | sort)
        fi
    else
        if diff -q <(sort "$stderr_file") <(echo "$command_output" | sort) > /dev/null; then
            echo "Test '$folder_number' úspešný"
            ((successful_tests++))
        else
            echo "Test '$folder_number' neúspešný: Obsah stderr súboru sa nezhoduje"
            ((failed_tests++))
            diff -Bw <(sort "$stderr_file") <(echo "$command_output" | sort)
        fi
    fi
    
    ((folder_number++))  
}


# Spusti testy
echo "Running tests..."

test_command "./dns -h"
test_command "./dns -r"
test_command "./dns -s"
test_command "./dns -s 8.8.8.8"
test_command "./dns -s 8.8.8.8 -p www.fit.vutbr.cz www.fit.vutbr.cz"
test_command "./dns -t -s 8.8.8.8 www.fit.vutbr.cz"
test_command "./dns -s 8.8.8.8 www.fit.vutbr.cz www.fit.vut.cz"

# IPv4 adress
test_command "./dns -s 8.8.8.8 www.fit.vut.cz"
test_command "./dns -s 8.8.8.8 www.seznam.cz"
test_command "./dns -s 8.8.8.8 kazi.fit.vutbr.cz"

# IPv6 adress
test_command "./dns -6 -s 8.8.8.8 www.fit.vutbr.cz"
test_command "./dns -r -6 -s 8.8.8.8 www.seznam.cz"

# IPv6 DNS server
test_command "./dns -6 -s 2001:67c:1220:808::93e5:80c www.fit.vut.cz"

# SOA record
test_command "./dns -s 8.8.8.8 -r halabalala.cz" # Funny is that halabala.cz really exists, that is why I used halabalala.cz

# Reverse lookup
test_command "./dns -x -s 8.8.8.8 2001:67c:1220:808::93e5:80c"
test_command "./dns -x -r -s 8.8.8.8 2001:67c:1220:808::93e5:80c"
test_command "./dns -x -s dns.google 2a02:598:2::1222"

# Mixed arguments
test_command "./dns -s 8.8.8.8 -6 www.seznam.cz -r"
test_command "./dns -6 -s 8.8.8.8 -r facebook.com"








# Finalny vypis vysledkov
echo "Úspešné testy: $successful_tests"
echo "Neúspešné testy: $failed_tests"