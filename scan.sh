#!/bin/bash


# Model file to store the results of NMAP scan for furhter analysis

output_file="scan_results.txt"

# Running the NMAP scan to identify the open ports and store the results into output file

nmap -A -T4 -p- $1 > $output_file

# The next intent should be to send the output of this file to a secodary shell script that contains the conditional statements for every condition that can be performed during  pentesting

#cat "$output_file"
