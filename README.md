# arp spoof
## Enviroment
  * Hypervisor : virtual box
    * Host OS : Window
    * Virtual OS : Linux
   
## Warning
  network settings : virtualbox - setting - network - bridge - Promiscuous Mode ( all accept )  
  <br>
  Since packets from the host OS are also captured by the virtual OS, all incoming packets to the host IP need to be filtered.
  ```C++
  Ip g_hostIp(string("192.168.0.100"));
  Ip g_netMask(string("255.255.255.0"));
  
  int main(int argc, char* argv[]) {
  ...
  string filterExp = "not host " + string(g_hostIp);
  if(!SetPcapFilter(pcap, filterExp)) throw runtime_error("Failed to set filter");
  ...
  ```
