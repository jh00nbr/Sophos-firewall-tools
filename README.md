## Sophos-firewall-tools
Scripts developed for process automation and testing in Sophos firewall.

## SF Import hosts - Tool to import objects of hosts in the Firewall XG Sophos


* Enable the API on sophos firewall
![alt text](https://raw.githubusercontent.com/jh00nbr/Sophos-firewall-tools/master/api_sophos_allowed.png)

> **Example File format of the objects to be imported: example_hosts.txt;
The format of each line is separated by ":" (host: ip address)**


./sfimport.py -l <file_hosts.txt> -gw <ip_firewall> -u <user> -p <password> -P <default_port> --importhost 


![alt text](https://raw.githubusercontent.com/jh00nbr/Sophos-firewall-tools/master/output_import_fw.png)

