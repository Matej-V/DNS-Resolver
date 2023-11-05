test_number=1

fill_tests() {
    command="$1"
    echo "Filling tests"
    mkdir -p ./tests/test$test_number
    $command > ./tests/test$test_number/stdout.out 2> ./tests/test$test_number/stderr.out
    echo $? > ./tests/test$test_number/return_code.out
    ((test_number++))
}

fill_tests "./dns -h"
fill_tests "./dns -r"
fill_tests "./dns -s"
fill_tests "./dns -s 8.8.8.8"
fill_tests "./dns -s 8.8.8.8 -p www.fit.vutbr.cz www.fit.vutbr.cz"
fill_tests "./dns -t -s 8.8.8.8 www.fit.vutbr.cz"
fill_tests "./dns -s 8.8.8.8 www.fit.vutbr.cz www.fit.vut.cz"

# IPv4 adress
fill_tests "./dns -s 8.8.8.8 www.fit.vut.cz"
fill_tests "./dns -s 8.8.8.8 www.seznam.cz"
fill_tests "./dns -s 8.8.8.8 kazi.fit.vutbr.cz"

# IPv6 adress
fill_tests "./dns -6 -s 8.8.8.8 www.fit.vutbr.cz"
fill_tests "./dns -r -6 -s 8.8.8.8 www.seznam.cz"

# IPv6 DNS server
fill_tests "./dns -6 -s 2001:67c:1220:808::93e5:80c www.fit.vut.cz"

# SOA record
fill_tests "./dns -s 8.8.8.8 -r halabalala.cz" # Funny is that halabala.cz really exists, that is why I used halabalala.cz

# Reverse lookup
fill_tests "./dns -x -s 8.8.8.8 2001:67c:1220:808::93e5:80c"
fill_tests "./dns -x -r -s 8.8.8.8 2001:67c:1220:808::93e5:80c"
fill_tests "./dns -x -s dns.google 2a02:598:2::1222"

# Mixed arguments
fill_tests "./dns -s 8.8.8.8 -6 www.seznam.cz -r"
fill_tests "./dns -6 -s 8.8.8.8 -r facebook.com"
