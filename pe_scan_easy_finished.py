import pefile
import sys
import ctypes
import glob
import argparse
import itertools

def search_tables(thefile, pename, search = []):
    if hasattr(thefile, "DIRECTORY_ENTRY_IMPORT"):
        if args.verbose or args.dump:
            print("Processing Import Table...")
        for dllimport in thefile.DIRECTORY_ENTRY_IMPORT:
            fname = dllimport.dll.decode()
            for eachfunc in dllimport.imports:
                if args.dump:
                    name = eachfunc.name if eachfunc.name else b"BLANK" 
                    print("{0: >} in {1} at offset 0x{2:0>16X}".format(name.decode(),fname,eachfunc.address ))
                    continue
                for eachterm in search:                   
                    if args.inexact:
                        if eachfunc.name and (eachterm in eachfunc.name.decode().lower()) or not search:
                            print("{} uses {} in dll {}".format(pename, eachfunc.name, fname))
                    else:
                        if eachfunc.name and eachterm == eachfunc.name.decode():
                            print("{} uses {} in dll {}".format(pename, eachfunc.name, fname))
                    #else:
                    #    print("{} not in {}".format(eachterm, eachfunc.name)
    if hasattr(thefile, "DIRECTORY_ENTRY_EXPORT"):
        if args.verbose or args.dump:
            print("Processing the Export Table...")
        for symbol in thefile.DIRECTORY_ENTRY_EXPORT.symbols:
            fname = thefile.DIRECTORY_ENTRY_EXPORT.name.decode()
            if args.dump:
                name = symbol.name if symbol.name else b"BLANK"
                print("{0} in {1} at offset 0x{2:0>16X} in {}".format(name.decode(), fname, symbol.address_offset))
                continue
            for eachterm in search:
                if symbol.name:
                    if args.inexact:
                        if symbol.name and (eachterm in symbol.name.decode().lower()) or not search:
                            print("{0} exports {1} at 0x{2:0>16X} ".format(pename, symbol.name, symbol.address_offset))
                    else:
                        if symbol.name and eachterm == symbol.name.decode():
                            print("{0} exports {1} at 0x{2:0>16X}".format(pename, symbol.name, symbol.address_offset))

def bits2flag(flags,byte_value):
    bits_array = map(int, format(byte_value,"016b"))
    return "|".join(itertools.compress(flags[::-1],bits_array))                       
                
search = ["printf", "gets", "lstrcpyW"]

dll_characteristics = ['reserved0', 'reserved1', 'reserved2', 'reserved3', 'undefined1', 'High_Entropy_VA', 'Dynamic_Base', 'Force_Integrity', 'NX_Compat', 'No_isolation', 'No_SEH', 'No_bind', 'App_Container', 'WDM_Driver', 'Guard_CF', 'Terminal_Server_Aware']

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--dump", action= "store_true", help = "Dump all information about the pe. No filters or search applied.")
    parser.add_argument("-a","--add", nargs='*', help = "In addition to defaults also search for these functions being used by the exectuables. The function names are separated by spaces and terminated with two dashes. Example: -a modulea moduleb --")
    parser.add_argument("-o","--only", nargs='*', help = "Only search for these functions being used by the executables. The function names are separated by spaces and terminated with two dashes. Example: -e modulea moduleb --")
    parser.add_argument("-i","--inexact", action="store_true", help = "Ignore case sensitive and allow substring match of function names rather than exact names.")
    parser.add_argument("-f","--flags", action="store_true", help = "Display the DLL Characteristic flags.")
    parser.add_argument("-v","--verbose", action="store_true", help = "MAKE SOME NOISE UP IN HERE!!!")
    parser.add_argument("-t", "--toggle", choices = dll_characteristics, help = "The name of a single PE DLL Characteristics bit to toggle.")
    parser.add_argument("pefiles", help= "The name of an EXE or DLL is a required argument. Wildcards are supported.")
    args = parser.parse_args()

    pefiles = glob.glob(args.pefiles)
    if len(pefiles)==0:
        print("No files found.")
        sys.exit(1)

    if args.add:
        search.extend(args.add)

    if args.only:
        search = args.only

    for pe in pefiles:
        try:
            thefile = pefile.PE(pe)
        except Exception as e:
            print("Unable to open file {}".format(str(e)))
            continue   
        if args.dump or args.flags:
            file_options = thefile.OPTIONAL_HEADER.DllCharacteristics
            print("{} flags : {}".format(pe, bits2flag(dll_characteristics, file_options)))
        if args.toggle:
            current_flags = thefile.OPTIONAL_HEADER.DllCharacteristics
            bitsmask = 2**dll_characteristics.index(args.toggle)
            thefile.OPTIONAL_HEADER.DllCharacteristics = current_flags ^ bitsmask
            thefile.write(filename = "{}.new".format(pe))
            print("Flags Changes written to {}.new".format(pe))
        if args.verbose: 
            print("Searching EXE {} for vulnerable functions {}".format(pe, str(search)))
        search_tables(thefile,pe, search)