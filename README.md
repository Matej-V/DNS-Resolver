Projekt ISA - DNS resolver
==========================
Jazyk: C++, Python3 \
Platforma: Linux \
Autor: Matej Vadovič \
Login: xvadov01

Popis projektu
--------------
Program je implementácia DNS resolveru, ktorý slúži na zasielanie dotazov o preklad doménových mien a IP adries, získavanie informácií o doménových menách a ich záznamoch.

Implementácia DNS resolveru je v súbore `dns.cpp`, ku ktorému patrí hlavičkový súbor `dns.hpp`. Testovací skript `test.py` je napísaný v jazyku Python.

Preklad
-------
Preklad programu je možné vykonať pomocou príkazu `make`. \

Spustenie
---------
Program je možné spustiť pomocou príkazu 
```
./dns [-r] [-x] [-6] -s server [-p port] adresa
````
Testy možno spustiť pomocou príkazu:
```
make test
```
Význam prepínačov možno získať pomocou príkazu:
```
./dns -h
```