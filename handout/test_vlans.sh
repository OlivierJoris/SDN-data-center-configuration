# Inside Mininet

# Reachability
pingall

# Measures 

# VLAN 0 - ping
h1 ping -c 10 h5
h1 ping -c 10 h9
h1 ping -c 10 h13

# VLAN 0 - iperf
iperf h1 h5
iperf h1 h9
iperf h1 h13

# VLAN 1 - ping
h2 ping -c 10 h6
h2 ping -c 10 h10
h2 ping -c 10 h14

# VLAN 1 - iperf
iperf h2 h6
iperf h2 h10
iperf h2 h14

# VLAN 2 - ping
h3 ping -c 10 h7
h3 ping -c 10 h11
h3 ping -c 10 h15

# VLAN 2 - iperf
iperf h3 h7
iperf h3 h11
iperf h3 h15

# VLAN 3 - ping
h4 ping -c 10 h8
h4 ping -c 10 h12
h4 ping -c 10 h16

# VLAN 3 - iperf
iperf h4 h8
iperf h4 h12
iperf h4 h16
