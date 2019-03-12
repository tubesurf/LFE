# Volatility plugin: ld_preload_check

## Background
Most modern code compiled for Linux relies on shared libraries to provide developers with the ability to build on top of existing work, rather than re-writing code such as string copy. The use of shared libraries has many advantages for the operating system also as a library can be loaded once into memory and allow multiple programs to take advantage of its exported functions. This helps reduce the amount of duplicate code in memory and also provides a level of abstraction for developers. 

However there is fundamental flaw in the way that symbols from shared libraries are exported that malware authors are able to take advantage of to develop application level hooks to hide information from a user. If a library is loaded into a process space exporting for example "SymbolA" and then at a later point in time a library with the same symbol name i.e. "SymbolA" then it is possible for the second library to intercept the calls from the application. 

While a system is running it is possible to determine if this has occurred, however currently if a memory dump is taken and then analysed after it is not possible to determine if more than one library is exporting the same symbol. 



A Loadable Kernel Module (LKM) which allows for volatile memory acquisition from Linux and Linux-based devices, such as Android. This makes LiME unique as it is the first tool that allows for full memory captures on Android devices. It also minimizes its interaction between user and kernel space processes during acquisition, which allows it to produce memory captures that are more forensically sound than those of other tools designed for Linux memory acquisition.

## Table of Contents
 * [Concept](#concept)
 * [Getting Started](#started)
 	* [System details](#system)
 	* [Memory dump](#memdump)
 	* [Volatility](#vol)
 * [Plugin walkthrough](#walk)
## Concept <a name="concept"/>
When dealing with a live system a method that can be used to identify LD_PRELOAD rootkits is detailed in a check point blog  (http://www.chokepoint.net/2014/02/detecting -userland-preload-rootkits.html) from  February 2014. The book "The Art Of Memory Forensics" summaries the concept for live analysis into three main points:

1. Using the dlsym function to request the address of a number of commonly hooked functions such as write, open, read, printf, etc

2. Then undertake the same requests again for the same  function using dlsym again but with the RTLD_NEXT flag set. With the RTLD_NEXT flag set it lets the dynamic loader to skip the first library (which could be the hooking library) in which the symbol is found and then look for it in the other loaded libraries. 

3. Using the response from dlsym and dlsym iwth RTLD_NEXT set it is possible to compare the two results and determines whether a mismatch exists i.e. potentially a hooked function.

The detection method described above is interesting as it relies on the dynamic linker to determine inconsistenciedds, and thus a live system to undertake the analysis. However if we take the case where a memory dump has been acquired is it possible to determine if a maliscous library is hooking functions with volatility?

From the book "The Art of Memory Forensics" the authors suggest that Using the Volatility library listing and symbol resolution API it would be possible to develop a plugin that could identify libraries exporting the same symbol. 

The following is path taken to develop such a plugin and also the surprising results found.

## Getting started <a name=started/>
Before getting started it was necessary to have an enviroment to undertake the work which is detailed below: 

### System details <a name=system/>
If you are trying to follow along the following details may assist you:
* Ubuntu 16.04 in a virtual machine with 4G of ram and kernel version "Linux ubuntu 4.15.0-45-generic #48~16.04.1-Ubuntu SMP"
* LiME from https://github.com/504ensicsLabs/LiME commit version 9bd146ae54ef9f04acc09c44544aaf66aa8566d1 
* Volatility from https://github.com/volatilityfoundation/volatility commit version 753bfa87b62ecf4652f1850ebb8dd8d719a953a8

### Memory dump <a name=memdump/>

A memory dump is a extraction of the data currently held in RAM, it is quiet difficult to gather the data in RAM for a specific point in time as the act of extracting the data could cuase changes and also the time it takes the data could be paged out or into RAM. There are a number of tools that can be used for extracting data from RAM to undertake anylsis and in a paper at (https://ro.ecu.edu.au/adf/144/) Andri, Craig, and Peter undertake a compairion of three such tools Live Respose, LiME, and Mem Tool.
For this project a memory dump was undertaken using Lime the following steps where taken to achive the memory dump of the Ubuntu virtual machine:

```
$git clone https://github.com/504ensicsLabs/LiME.git
$cd workspace/LIME/src/
$ make

$ sudo insmod ./lime.ko "path=tcp:4444 format=lime"

$ nc <host> 4444 > ram.lime
```
If you are dumping memory across a socket ensure that either a firewall rule is added to allow the connection or that the firewall is disabled during the capture.

### Volatility <a name=vol/>

Volatility provides an open source framework for the analysis of extracted artefacts from memory for Linux, Windows, and Mac OSX. 

To get volatility working for Ubuntu 16.04 undertake the following

```
git clone https://github.com/volatilityfoundation/volatility.git
pip install pycrypto Distorm3 OpenPyxl ujso
```

Hopefully it is possible to obtain the kernel version for the RAM dump undertaken of the host under investigation as this will be required for volatility to find critical data structures. If you do know the Linux kernel verison but there isn't a profile avaliable then you will need to create one (this is most likley for Linux hosts), to build a profile undertake the following:
```
apt-get install libelf-dev
make -C /lib/modules/$(uname -r)/build CONFIG_DEBUG_INFO=y M=$PWD modules
dwarfdump -di ./module.o > module.dwarf
zip debian0415039.zip module.dwarf /boot/System.map-$(uname -r)
```

Now that you know the profile or have been able to generate a profile you can run a number of plugins against the data and start your anaylsis, voliatity have a helpful command reference at https://github.com/volatilityfoundation/volatility/wiki/Command-Reference. The following just providles a example of running the linux_banner plugin:
```
python ./vol.py --profile=Linuxdebian0415039x64 -f ../dump.mem linux_banner
Volatility Foundation Volatility Framework 2.6.1
Linux version 4.15.0-39-generic (buildd@lcy01-amd64-012) (gcc version 5.4.0 20160609 (Ubuntu 5.4.0-6ubuntu1~16.04.10)) #42~16.04.1-Ubuntu SMP Wed Oct 24 17:09:54 UTC 2018 (Ubuntu 4.15.0-39.42~16.04.1-generic 4.15.18)
```

## Plugin walkthrough<a name=code/>

The following section is a walkthrough of the plugin created to determine if a process had more than one library exporting the same symobol.

As discussed earlier the main parts of plugin are for a process undertake the following:
* determine the libraries mapped into the address space
* for the address space that is marked read and execuatable check if the liabry was paged into memory at the time
* thus check for a valid elf header
* if the elf header is valid then extract out all the valid symbols of the library
* store the symbols associated with that library and repeat for each library
* once all the libraries have been checked then output any symbols that are mapped by more than one library



This section obtains the list of process's on the system and also the virtual memory region for that process.

```
 def calculate(self):
        linux_common.set_plugin_members(self)
        tasks = linux_pslist.linux_pslist.calculate(self)

        for task in tasks:
            print "\n\n\n[-] Libraries found in the process (name:" + str(task.comm) +"pid: " + str(task.pid) +") with valid elf headers\n\n\n"
            # for a test check if there is memory
            if task.mm:
                # Gets the virual memory address for the process
                for vma in task.get_proc_maps():
                        # So for each task go and call the render_text
                        yield task, vma

```

We need a data structure to store the symbols we find and then map the library to that symbol in a fast way so that we can quickly add any other libraries to that symbol. Python provides the default dictionary that allows us to add an array of libraries for each symbol found.

```
        # Create a dictonary to store the symbols and the library they are in
        self.library_data = defaultdict(list)

```

Once we have the address space we can get a listing of objects mapped into the memory i.e. the libraries. Using some check's i.e. looking for a .so in the file name, the address space that was marked read and executable, and checking if the library was in memory at the time of capture i.e. a valid elf header.  

```
	    # First check if we have a library
            if ".so" in fname:
            # Next Check if its marked executable i.e. it was able to run in memory
                if "r-x" in str(vma.vm_flags):
                # vma is the memory address start, end of the elf library

                    # Get the process address space
                    proc_as = task.get_process_address_space()

                    # Based on address range of the library try to create a elf header
                    elf_hdr_obj = obj.Object("elf_hdr", offset=vma.vm_start, vm=proc_as)

 		    # Check if that elf header is valid, as the memory may not have been captured
                    if elf_hdr_obj.is_valid():
                        print( "[+] Valid elf header found for " + fname + " extractinging symbols")

```


Now we can extract the symbols from the library and place them into the dictionary.
```
		    # If we have a valid elf header then most likely we can recover the symbols
                        number_symbols_found=0
                        for symbol in  elf_hdr_obj.symbols():

                            #Get the symbol name
                            output = elf_hdr_obj.symbol_name(symbol)
                            # Some times the symbol name can't be recovered
                            if "N/A" not in output:
                                number_symbols_found=number_symbols_found + 1
                                self.library_data[output].append(fname)
                        print "         [o] Number of symbols in library: " + str(number_symbols_found)
                        print "         [o] Number of symbols in dict: " + str(len(self.library_data.keys()))

```


Now that the symbols are extracted we can undertake a check of which symbols are exported by more than one library.

```
# For each key check if more than one item if so print the items
        conflict_symbols = 0
        print "\n\n\n[-] Symbols exported by muliple libraries\n\n\n"
        for key_symbol, libraries in self.library_data.iteritems():
                if len(libraries) > 1:
                        print "[!] " + str(len(libraries)) + " libraries exporting: "  + key_symbol + "\n\t\t[o]", '\n\t\t[o] '.join(libraries)
                        conflict_symbols = conflict_symbols + 1

        print "[+] Number of conflict symbols: " + str(conflict_symbols)


``` 


## Example run

The following is a cutdown example run against a gnome-terminal process using the ld_prelaod_check plugin:

```
python ./vol.py  --profile=Linuxdebian0415039x64 -f ../dump.mem linux_ld_preload_check -p 1986

Volatility Foundation Volatility Framework 2.6.1



[-] Libraries found in the process (name:gnome-terminal-pid: 1986) with valid elf headers



[+] Valid elf header found for /lib/x86_64-linux-gnu/libdl-2.23.so extractinging symbols
		[o] Number of symbols in library: 0
		[o] Number of symbols in dict: 0
[+] Valid elf header found for /usr/lib/x86_64-linux-gnu/libffi.so.6.0.4 extractinging symbols
		[o] Number of symbols in library: 0
		[o] Number of symbols in dict: 0
[+] Valid elf header found for /usr/lib/x86_64-linux-gnu/libXdamage.so.1.1.0 extractinging symbols
		[o] Number of symbols in library: 0
		[o] Number of symbols in dict: 0
[+] Valid elf header found for /usr/lib/x86_64-linux-gnu/libXcursor.so.1.0.2 extractinging symbols
		[o] Number of symbols in library: 128
		[o] Number of symbols in dict: 127
[+] Valid elf header found for /usr/lib/x86_64-linux-gnu/libfontconfig.so.1.9.0 extractinging symbols
		[o] Number of symbols in library: 0
		[o] Number of symbols in dict: 127
[+] Valid elf header found for /usr/lib/x86_64-linux-gnu/libpangoft2-1.0.so.0.3800.1 extractinging symbols
		[o] Number of symbols in library: 346
		[o] Number of symbols in dict: 463

<...cut...>

[-] Symbols exported by muliple libraries

<...cut...>

[!] 3 libraries exporting: g_param_spec_string
		[o] /usr/lib/x86_64-linux-gnu/libgobject-2.0.so.0.4800.2
		[o] /usr/lib/x86_64-linux-gnu/libatk-1.0.so.0.21809.1
		[o] /usr/lib/x86_64-linux-gnu/libgdk-3.so.0.1800.9
[!] 2 libraries exporting: pango_layout_set_tabs
		[o] /usr/lib/x86_64-linux-gnu/libpango-1.0.so.0.3800.1
		[o] /usr/lib/x86_64-linux-gnu/libgtk-3.so.0.1800.9
[!] 2 libraries exporting: g_ptr_array_set_size
		[o] /lib/x86_64-linux-gnu/libglib-2.0.so.0.4800.2
		[o] /usr/lib/x86_64-linux-gnu/libgtk-3.so.0.1800.9
[+] Number of conflict symbols: 1903

```

As described in the above sections the run from above shows in the first section that it is finding valid elf headers and then how many symbols that have been extracted from the library. Note this may not always be possible due to the way different sections are memory are paged in and out of ram hence some libraries have a valid elf header but symbols can't be extracted.

The next section shows for each symbol the exported libraries if there is more than two, note that in this case there are over 1903 conflicts.

If you have the file on disk then you could use readelf to also check if the libraries are exporting the same symbol, this may not be a maliscious act though. The example below shows how readelf was used to confirm the plugin was working:

```
$ readelf -Ws /usr/lib/x86_64-linux-gnu/libgtk-3.so.0.1800.9 | grep g_ptr_array_set_size
  1116: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND g_ptr_array_set_size
$ readelf -Ws /lib/x86_64-linux-gnu/libglib-2.0.so.0.4800.2 | grep g_ptr_array_set_size
  1322: 000000000001e200   186 FUNC    GLOBAL DEFAULT   12 g_ptr_array_set_size
```

This seems pretty strange but the following section provides some insight into why this could be the case...


## Shared library issues

The paper by Ulrich Drepper "How To Write Shared Libraries" (https://akkadia.org/drepper/dsohowto.pdf) provides great detail on how a ELF shared library is loaded into memory. For a shared libary to be loaded to be used by a program the kernel requires the dynamic linker:
* to determine and load dependencies, 
* relocate the application and all dependencies, and
* initalize the application and dependencies in the correct order.

As part of the relocaiton process the dynamic linker has to perform a relocation for all symbols that are going to be used at run-time that aren't know at link-time. From the paper it states that "Note that there is no problem if the scope contains more than one definition of the same symbol. The symbol lookup algorithm simply picks up the first definition it findes". Thus from what we have seen from the example is expected then in the case of the linker it will jsut take the first library that resolves the symbol. Thus if a attacker is using the LD_PRELOAD method there symbol will load first! If not then its could just be a matter of the name of the library getting loaded first and thus having its symbols used.

A blog by Michael (https://holtstrom.com/michael/blog/post/437/Shared-Library-Symbol-Conflicts-%28on-Linux%29.html) provides a pratical example of where this can happen due to poor programming. So when looking for libraries that are resolving the same symbols we should confirm if the intent is malicious.

## Contribution 

This blog post has been created for completing the requirments of the SecurityTube Linux Forensics Expert certification:http://www.securitytube-training.com/online-courses/linux-forensics/ as student ID SLE-2150. Undertaking the Linux Forensics Course it was possible to gain a stronger understanding of the forensics process involved with Linux systems and also appreciate the diffrence between memory anaylsis and more traditional forms of forensics.





