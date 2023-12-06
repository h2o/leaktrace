# leaktrace
This is a LD_PRELOAD library for detecting memory leaks.


Intended use is to obtain memory dumps multiple times without rebooting a program, then compare the dumps; if we see increase of memory allocated from a particular call site not being freed, that's likely an indication that memory is leaking from that call site.

## Usage

### 1. Build the Preload Library
```
% gcc -Wall -Wno-unused-result -g -O2 -fPIC -shared preload.c -o leaktrace.so
```

### 2. Run Rrograms with the Preload Library being attached
```
% LD_PRELOAD=/path/to/leaktrace.so LEAKTRACE_PATH=/path/to/leaktrace.dump h2o -m worker ...
```

When SIGUSR2 is sent to the program, leaktrace dumps the memory allocation information into the file specified by LEAKTRACE_PATH.
When sending SIGUSR2, the file MUST not exist; if it exists, leaktrace will refuse to overwrite.

The dump can be taken any number of times without rebooting h2o.

### 3. Annotate the Leaktrace Dump

```
% ./annotate.pl -p (pidof h2o) -f /path/to/leaktrace.dump
```

annotate.pl resolves the call sites to lines of source files if possible, and emits an output like following:
```
addr    bytes   alloc   free    coll    location
libcrypto.so.3+1b746e   723472  6998    4281    0       CRYPTO_zalloc at ??:? 
libcrypto.so.3+1acdc6   58200   2636    211     0       OPENSSL_LH_insert at ??:? 
h2o+b7b47       19755   242     0       0       h2o_mem_alloc at /home/kazuho/mydev/h2o/include/h2o/memory.h:442 (inlined by) h2o_mem_alloc_shared at /home/kazuho/mydev/h2o/lib/common/memory.c:230 
h2o+ac952       11072   2       0       0       h2o_file_read at /home/kazuho/mydev/h2o/lib/common/file.c:48 
libcrypto.so.3+1e81c1   10200   1468    1213    0       RAND_keep_random_devices_open at ??:? 
libcrypto.so.3+1b84a3   8574    14343   13674   0       CRYPTO_strndup at ??:? 
(snip)
```

Descriptions of the columns are as follows:
* addr - address of the call site
* bytes - total amount of memory being allocated from the call site and not yet being freed
* alloc - number of times memory has been allocated from the call site
* free - number of times memory allocated from the call site has been freed
* coll - collisions between different call sites, that could have led to inaccurate numbers
