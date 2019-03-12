#"""
#@description:  Plugin for checking process's address space for libraries resolving multiple symbols.
#@license:      GNU General Public License 2.0
#"""

import volatility.obj as obj
import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.pslist as linux_pslist
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address

from collections import defaultdict
import sys

class linux_ld_preload_check(linux_pslist.linux_pslist):
    """Outputs Libraries for a process"""

    def calculate(self):
        linux_common.set_plugin_members(self)
        tasks = linux_pslist.linux_pslist.calculate(self)

        for task in tasks:
	    print "\n\n\n[-] Libraries found in the process (name:" + str(task.comm) +"pid: " + str(task.pid) +") with valid elf headers\n\n\n" 
	    # for a test check if there is memory
            if task.mm:
		# Gets the virual memory address for the elf object i.e. in our case a library
                for vma in task.get_proc_maps():
			# So for each task go and call the render_text
			yield task, vma            



    def render_text(self, outfd, data):
        # Create a dictonary to store the sybmols and the library they are in
    	self.library_data = defaultdict(list)
	for task, vma in data:
            (fname, major, minor, ino, pgoff) = vma.info(task)
	
            # First check if we have a library
            if ".so" in fname:
            # Next Check if its marked exectuabled i.e. it was able to run in memory
                if "r-x" in str(vma.vm_flags):
		# vma is the memory address start, end of the elf library

                    # Get the process address space
                    proc_as = task.get_process_address_space()

                    # Based on address range of the library try to create a elf header
                    elf_hdr_obj = obj.Object("elf_hdr", offset=vma.vm_start, vm=proc_as)

                    # Check if that elf header is valid, as the memory may not have been captured
                    if elf_hdr_obj.is_valid():
			#sys.stdout.write( "[+] Valid elf header found for " + fname + " extractinging symbols")
			print( "[+] Valid elf header found for " + fname + " extractinging symbols")
                        # If we have a valid elf header then most likley we can recover the symbols
                        number_symbols_found=0
			for symbol in  elf_hdr_obj.symbols():
                            
			    #Get the symbol name
			    output = elf_hdr_obj.symbol_name(symbol)
                            # Some times the symbol name can't be recovered
			    if "N/A" not in output:
				number_symbols_found=number_symbols_found + 1
				self.library_data[output].append(fname)
			print "		[o] Number of symbols in library: " + str(number_symbols_found)
			print "		[o] Number of symbols in dict: " + str(len(self.library_data.keys()))
                    #else:
                    #    print "[-] No valid elf header found for: "+ fname

	# For each key check if more than one item if so print the items
	conflict_symbols = 0
	print "\n\n\n[-] Symbols exported by muliple libraries\n\n\n"	
	for key_symbol, libraries in self.library_data.iteritems():
		if len(libraries) > 1:
			print "[!] " + str(len(libraries)) + " libraries exporting: "  + key_symbol + "\n\t\t[o]", '\n\t\t[o] '.join(libraries)
			conflict_symbols = conflict_symbols + 1

	print "[+] Number of conflict symbols: " + str(conflict_symbols) 
