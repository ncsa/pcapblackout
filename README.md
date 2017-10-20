pcapblackout
============

Replace the application data in a pcap with an arbitrary string, leaving everything else the same.

Probably want to run the resulting pcap through tcprewrite to fix the checksums after:

    tcprewrite --fixcsum --infile=input.pcap --outfile=output.pcap
