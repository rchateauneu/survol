cython dockit.pyx
# gcc -I /usr/include/python2.7 -l python2.7 dockit.c -o dockit

# gcc -Isrc -fPIC $(pkg-config --cflags --libs python2) -c src/hw.c hw_wrap.c
# gcc -shared -fPIC -o hw.so hw.o hw_wrap.o

# gcc -I /usr/include/python2.7 -l python2.7 dockit.c -o dockit
gcc -Isrc -fPIC $(pkg-config --cflags --libs python2) -c dockit.c
gcc -shared -fPIC -o dockit.so dockit.o
