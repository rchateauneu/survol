# Generated makefile: 2020-12-19
# Working directory:/home/rchateau/survol/Experimental/MakefileTests
/home/rchateau/survol/Experimental/MakefileTests: /home/rchateau/survol/Experimental/MakefileTests/makefile
	# Directory: /home/rchateau/survol/Experimental/MakefileTests
	make -B

/tmp/ccM07BAx.s: /home/rchateau/survol/Experimental/MakefileTests/hellomake.c /home/rchateau/survol/Experimental/MakefileTests/hellomake.h
	# Directory: /home/rchateau/survol/Experimental/MakefileTests
	/usr/libexec/gcc/x86_64-redhat-linux/7/cc1 -quiet -I . hellomake.c -quiet -dumpbase hellomake.c -mtune=generic -march=x86-64 -auxbase-strip hellomake.o -o /tmp/ccM07BAx.s

/home/rchateau/survol/Experimental/MakefileTests/hellomake.o: /tmp/ccM07BAx.s
	# Directory: /home/rchateau/survol/Experimental/MakefileTests
	as -I . --64 -o hellomake.o /tmp/ccM07BAx.s

/tmp/cc94RQ0B.s: /home/rchateau/survol/Experimental/MakefileTests/hellofunc.c /home/rchateau/survol/Experimental/MakefileTests/hellomake.h
	# Directory: /home/rchateau/survol/Experimental/MakefileTests
	/usr/libexec/gcc/x86_64-redhat-linux/7/cc1 -quiet -I . hellofunc.c -quiet -dumpbase hellofunc.c -mtune=generic -march=x86-64 -auxbase-strip hellofunc.o -o /tmp/cc94RQ0B.s

/home/rchateau/survol/Experimental/MakefileTests/hellofunc.o: /tmp/cc94RQ0B.s
	# Directory: /home/rchateau/survol/Experimental/MakefileTests
	as -I . --64 -o hellofunc.o /tmp/cc94RQ0B.s

/home/rchateau/survol/Experimental/MakefileTests/hellomake: /home/rchateau/survol/Experimental/MakefileTests/hellofunc.o /home/rchateau/survol/Experimental/MakefileTests/hellomake.o
	# Directory: /home/rchateau/survol/Experimental/MakefileTests
	/usr/bin/ld -plugin /usr/libexec/gcc/x86_64-redhat-linux/7/liblto_plugin.so -plugin-opt=/usr/libexec/gcc/x86_64-redhat-linux/7/lto-wrapper -plugin-opt=-fresolution=/tmp/ccf5oFtK.res -plugin-opt=-pass-through=-lgcc -plugin-opt=-pass-through=-lgcc_s -plugin-opt=-pass-through=-lc -plugin-opt=-pass-through=-lgcc -plugin-opt=-pass-through=-lgcc_s --build-id --no-add-needed --eh-frame-hdr --hash-style=gnu -m elf_x86_64 -dynamic-linker /lib64/ld-linux-x86-64.so.2 -o hellomake /usr/lib/gcc/x86_64-redhat-linux/7/../../../../lib64/crt1.o /usr/lib/gcc/x86_64-redhat-linux/7/../../../../lib64/crti.o /usr/lib/gcc/x86_64-redhat-linux/7/crtbegin.o -L/usr/lib/gcc/x86_64-redhat-linux/7 -L/usr/lib/gcc/x86_64-redhat-linux/7/../../../../lib64 -L/lib/../lib64 -L/usr/lib/../lib64 -L/usr/lib/gcc/x86_64-redhat-linux/7/../../.. hellomake.o hellofunc.o -lgcc --as-needed -lgcc_s --no-as-needed -lc -lgcc --as-needed -lgcc_s --no-as-needed /usr/lib/gcc/x86_64-redhat-linux/7/crtend.o /usr/lib/gcc/x86_64-redhat-linux/7/../../../../lib64/crtn.o

/tmp/ccCvNaFe.ld: /home/rchateau/survol/Experimental/MakefileTests/hellofunc.o /home/rchateau/survol/Experimental/MakefileTests/hellomake.o
	# Directory: /home/rchateau/survol/Experimental/MakefileTests
	/usr/bin/ld -plugin /usr/libexec/gcc/x86_64-redhat-linux/7/liblto_plugin.so -plugin-opt=/usr/libexec/gcc/x86_64-redhat-linux/7/lto-wrapper -plugin-opt=-fresolution=/tmp/ccf5oFtK.res -plugin-opt=-pass-through=-lgcc -plugin-opt=-pass-through=-lgcc_s -plugin-opt=-pass-through=-lc -plugin-opt=-pass-through=-lgcc -plugin-opt=-pass-through=-lgcc_s --build-id --no-add-needed --eh-frame-hdr --hash-style=gnu -m elf_x86_64 -dynamic-linker /lib64/ld-linux-x86-64.so.2 -o hellomake /usr/lib/gcc/x86_64-redhat-linux/7/../../../../lib64/crt1.o /usr/lib/gcc/x86_64-redhat-linux/7/../../../../lib64/crti.o /usr/lib/gcc/x86_64-redhat-linux/7/crtbegin.o -L/usr/lib/gcc/x86_64-redhat-linux/7 -L/usr/lib/gcc/x86_64-redhat-linux/7/../../../../lib64 -L/lib/../lib64 -L/usr/lib/../lib64 -L/usr/lib/gcc/x86_64-redhat-linux/7/../../.. hellomake.o hellofunc.o -lgcc --as-needed -lgcc_s --no-as-needed -lc -lgcc --as-needed -lgcc_s --no-as-needed /usr/lib/gcc/x86_64-redhat-linux/7/crtend.o /usr/lib/gcc/x86_64-redhat-linux/7/../../../../lib64/crtn.o

/tmp/ccb8lACZ.le: /home/rchateau/survol/Experimental/MakefileTests/hellofunc.o /home/rchateau/survol/Experimental/MakefileTests/hellomake.o
	# Directory: /home/rchateau/survol/Experimental/MakefileTests
	/usr/bin/ld -plugin /usr/libexec/gcc/x86_64-redhat-linux/7/liblto_plugin.so -plugin-opt=/usr/libexec/gcc/x86_64-redhat-linux/7/lto-wrapper -plugin-opt=-fresolution=/tmp/ccf5oFtK.res -plugin-opt=-pass-through=-lgcc -plugin-opt=-pass-through=-lgcc_s -plugin-opt=-pass-through=-lc -plugin-opt=-pass-through=-lgcc -plugin-opt=-pass-through=-lgcc_s --build-id --no-add-needed --eh-frame-hdr --hash-style=gnu -m elf_x86_64 -dynamic-linker /lib64/ld-linux-x86-64.so.2 -o hellomake /usr/lib/gcc/x86_64-redhat-linux/7/../../../../lib64/crt1.o /usr/lib/gcc/x86_64-redhat-linux/7/../../../../lib64/crti.o /usr/lib/gcc/x86_64-redhat-linux/7/crtbegin.o -L/usr/lib/gcc/x86_64-redhat-linux/7 -L/usr/lib/gcc/x86_64-redhat-linux/7/../../../../lib64 -L/lib/../lib64 -L/usr/lib/../lib64 -L/usr/lib/gcc/x86_64-redhat-linux/7/../../.. hellomake.o hellofunc.o -lgcc --as-needed -lgcc_s --no-as-needed -lc -lgcc --as-needed -lgcc_s --no-as-needed /usr/lib/gcc/x86_64-redhat-linux/7/crtend.o /usr/lib/gcc/x86_64-redhat-linux/7/../../../../lib64/crtn.o

