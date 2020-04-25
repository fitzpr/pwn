import os, time

program = "/opt/bla/bin/target ARG1 ARG2"
string = "A"
var = "Segmentation fault"

for i in range(4000,10000,<NumberOfArguments>):
        ps.putenv("<VARIABLE>,string*i)
        a,b=os.popen4(program, 'r')
        str1 = b.read()
        if var in str1:
                print "Success! Segmentation Fault hit at",i, string,"'s\n"
                exit()
        else:
                time.sleep(0)
print "\nNo luck... Sorry it didn't work out...\n"
exit()
