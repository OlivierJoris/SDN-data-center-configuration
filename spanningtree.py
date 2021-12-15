from logging import BufferingFormatter
from ryu import ofproto
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet.ethernet import ethernet
from ryu.ofproto import ofproto_v1_0
from ryu.topology import event
from ryu.topology.api import get_all_host, get_switch, get_link
from ryu.lib.packet import ether_types, packet, ethernet
from ryu.lib.mac import haddr_to_bin

import copy
import sys

MAC_BROADCAST = 'ff:ff:ff:ff:ff:ff'
SIZE_SWITCH_ID_HEX = 16

class SpanningTreeController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]
    
    def __init__(self, *args, **kwargs):
        """
        Initialize.
        """
        super(SpanningTreeController, self).__init__(*args, **kwargs)
        self.hosts = []             # MAC address of the hosts
        self.switches = []          # ID of the switches
        self.switchesMapping = {}   # Mapping between the switches' ids and mac addresses + ports
        self.links = []             # List of links
        self.linksMap = {}          # Mapping between a switch id and the id of a neighbor switch and the port to reach it.
        self.topology = Topology(0) # Represent the topology
    
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        """
        Add a flow inside a switch.

        Arguments:
        ----------
        - `datapath`: Switch.
        - `priority`: Priority of the flow.
        - `match`: Matching rule.
        - `actiosn`: Actions of the flow.
        - `buffer_id`: ID of the packet inside the buffer of the switch.

        Source: Official book (page 8).
        """

        parser = datapath.ofproto_parser

        if buffer_id:
            mod = parser.OFPFlowMod(
                datapath=datapath, buffer_id=buffer_id,
                priority=priority, match=match,
                actions=actions
            )
        else:
            mod = parser.OFPFlowMod(
                datapath=datapath, priority=priority,
                match=match, actions=actions
            )
        
        datapath.send_msg(mod)

    @set_ev_cls(event.EventSwitchEnter, MAIN_DISPATCHER)
    def switch_in_handler(self, ev):
        """
        Handler when a switch enters the topology.
        Partially based on https://github.com/Ehsan70/RyuApps/blob/master/TopoDiscoveryInRyu.md
            and https://sdn-lab.com/2014/12/31/topology-discovery-with-ryu/
        """

        print("\nTopology:")
        # Fetch data
        switch_list = copy.copy(get_switch(self, None))
        links_list = copy.copy(get_link(self, None))
        hosts_list = copy.copy(get_all_host(self))

        # List format
        switches = [switch.dp.id for switch in switch_list]
        switchesDetails = [switch.to_dict() for switch in switch_list]
        links = [(link.src.dpid,link.dst.dpid) for link in links_list]
        linksDetails = [link.to_dict() for link in links_list]
        hosts = [(host.mac) for host in hosts_list]

        # Print
        print("Nb hosts = {}".format(len(hosts)))
        print("Hosts:")
        print(sorted(hosts))
        print("Nb switches = {}".format(len(switches)))
        #print("Switches:")
        #print(sorted(switches))
        print("Nb links = {}".format(len(links)))
        #print("Links:")
        #print(links)

        # Save
        self._update_hosts_list()
        self.switches = []
        self.switches = copy.copy(switches)
        self.links = []
        self.links = copy.copy(links)

        # Mapping switches' ids and MAC addresses + ports
        self._update_switch_mappings(switchesDetails)

        # Map of links
        self._update_link_map(links, linksDetails)

        # Update topo
        self.topology.fill_graph(len(self.switches), self.links)
        #self.topology.print()
        self.topology.primMST()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
        Handler when the controller receives the response to the features request.

        Source: Official book (page 8)
        """

        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Set the table-miss flow entry inside the switch.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        self.add_flow(datapath, 0, match, actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """
        Handler called when a packet arrives at the controller.
        """

        # Update the list of hosts
        self._update_hosts_list()

        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        # Ignore link discovery packet
        if eth == ether_types.ETH_TYPE_LLDP:
            return
        src = eth.src
        dst = eth.dst

        if (src in self.hosts) or (dst in self.hosts):
            print("Packet from {} to {} received at sw {} port {}".format(src, dst, dp.id, msg.in_port))

        # If the destination is broadcast (e.g. in the case of ARP request) and the src is one of the host,
        # need to add a flow to go back to the host and broadcast on all the ports of the spanning tree.
        if src in self.hosts and dst == MAC_BROADCAST:
            print("New flow for src in hosts and dst = broadcast")
            # Flow to go back to the host.
            match = ofp_parser.OFPMatch(dl_dst = src)
            actions = [ofp_parser.OFPActionOutput(msg.in_port)]
            self.add_flow(dp, 1, match, actions)
            print("Add flow to go back to host: flow_dst={} action_port={}".format(src, msg.in_port))

            # Flow that flood to neigbors of the switch in the spanning tree. 
            switchIdInt = dp.id
            if dp.id == self.topology.s0ID:
                switchIdInt = 0

            switchIdString = dp.id
            if dp.id == self.topology.s0ID:
                switchIdString = '0000000000000000'
            else:
                switchIdString = convert_int_to_switch_id(dp.id)
            
            # Get neighbors of switch in spanning tree.
            neighbors = self.topology.findNeigborSwitches(switchIdInt)
            print("Neighbors = {}".format(neighbors))

            # Find the ports on which to send the packet to reach the neighbors.
            listPorts = []
            for neighbor in neighbors:
                neighborID = convert_int_to_switch_id(neighbor)
                port = self.linksMap[switchIdString][neighborID]
                listPorts.append(port)
            
            # If the switch is a edge switch, send on ports of hosts.
            edge, maxN = self._is_edge_switch(switchIdString)
            if edge:
                portsUsed = []
                keys = self.linksMap[switchIdString].values()
                for key in keys:
                    portsUsed.append(int(key))
                for i in range(maxN):
                    if i not in portsUsed:
                        listPorts.append(str(i))
            
            # Build actions: send on ports to reach neighbors.
            actions = []
            for port in listPorts:
                if int(port) == msg.in_port: # do not send back on the port on which the packet arrive
                    continue
                print("Add flow to send packet on all allowed port: packet_src={} flow_dst={} action_port={}".format(src, dst, port))
                actions.append(ofp_parser.OFPActionOutput(int(port)))
            print("")

            # Add flow
            match = ofp_parser.OFPMatch(dl_src = src, dl_dst = dst)
            self.add_flow(dp, 1, match, actions)

            # Send OFPPacketOut for the current packert.
            data = None
            if msg.buffer_id == ofp.OFP_NO_BUFFER:
                data = msg.data
            
            out = ofp_parser.OFPPacketOut(
                datapath = dp, buffer_id = msg.buffer_id, in_port = msg.in_port,
                actions = actions, data = data
            )

            dp.send_msg(out)

            return


        """
        actions = [ofp_parser.OFPActionOutput(ofp.OFPP_FLOOD)]

        data = None
        if msg.buffer_id == ofp.OFP_NO_BUFFER:
            data = msg.data

        out = ofp_parser.OFPPacketOut(
            datapath=dp, buffer_id=msg.buffer_id, in_port=msg.in_port,
            actions=actions, data = data)
        dp.send_msg(out)
        """

        return

    def _update_hosts_list(self):
        """
        Updates the list of MAC addr of the hosts.
        """

        hosts_list = copy.copy(get_all_host(self))
        hosts = [(host.mac) for host in hosts_list]
        self.hosts = []
        self.hosts = copy.copy(hosts)

        # Temporary
        f = open("hosts.txt", "w")
        f.write("Nb hosts = " + str(len(hosts)) + "\n")
        for host in hosts:
            f.write(str(host) + "\n")
        f.close()
    
    def _update_switch_mappings(self, switchDetails):
        """
        Updates the mappings between the swicthes ids and ports' descriptions.

        Arguments:
        ----------
        - `switchDetails`: Details about the switches.
        """

        self.switchesMapping.clear()
        
        for sw in range(len(switchDetails)):
            ports = _convert_port_description_to_dict(switchDetails[sw]['ports'])
            # Check for id of s0
            if int(switchDetails[sw]['dpid'], 16) == self.topology.s0ID:
                self.switchesMapping.update({'0000000000000000': ports})
            else:
                self.switchesMapping.update({switchDetails[sw]['dpid']: ports})
        
        print("Mapping between swicth id and ports desc. (switch id -> {port id : port mac})")
        for switch in self.switchesMapping:
            print(str(switch) + " -> " + str(self.switchesMapping[switch]))

        # Temporary
        f = open("switchMapping.txt", "w")
        f.write("Switch details (nb entries = {})\n".format(len(self.switchesMapping.keys())))
        for switch in self.switchesMapping:
            f.write(str(switch) + ' -> ' + str(self.switchesMapping[switch]) + '\n')
        f.close()

    def _update_link_map(self, links, linksDetails):
        """
        Updates the mapping between a switch id and the id of a neighbor switch and the port to reach it.

        Arguments:
        ----------
        - `links`: List of links.
        - `linksDetials`: Details about the links.
        """

        # Find max value because switch s0 has an id randomly generated by Ryu which has the maximum value.
        s0ID = 1
        for link in links:
            if len(link) != 2:
                continue
            if link[0] > s0ID:
                s0ID = link[0]
            if link[1] > s0ID:
                s0ID = link[1]
        self.topology.s0ID = s0ID

        self.linksMap.clear()

        nbSwitches = len(self.switches)
        sources = []
        for _ in range(nbSwitches):
            sources.append(0)
        maps = []
        for _ in range(nbSwitches):
            maps.append({})

        for link in linksDetails:
            sourceID = link['src']['dpid']
            destID = link['dst']['dpid']
            sourceOutPort = link['src']['port_no']

            if int(sourceID, 16) == s0ID:
                sourceID = '0000000000000000'
            if int(destID, 16) == s0ID:
                destID = '0000000000000000'

            sources[int(sourceID, 16)] = sourceID
            maps[int(sourceID, 16)].update({destID: sourceOutPort})

        for source in sources:
            self.linksMap.update({source: maps[int(source, 16)]})
        
        print("Link map (switch id -> {neighbor switch id: port of source to reach neigbor})")
        for source in self.linksMap:
            print(str(source) + " -> " + str(self.linksMap[source]))

        # Temporary
        f = open("linksmap.txt", "w")
        f.write("Map of links\n")
        for source in self.linksMap:
            f.write(str(source) + " -> " + str(self.linksMap[source]) + "\n")
        f.close()
    
    def _is_edge_switch(self, switchID: str):
        """
        Return true if the switch is a edge/TOR switch. Else, return false.

        Argument:
        ---------
        - `switchID`: ID of the switch as a string.

        Return:
        -------
        Tuple containing whether the switch is a edge switch or not and the max
        number of neighbors for a switch.
        """

        countPorts = {}
        for switch in self.linksMap:
            countPorts.update({switch: len(self.linksMap[switch].keys())})
        
        maxCount = 0
        for count in countPorts:
            if countPorts[count] > maxCount:
                maxCount = countPorts[count]
        
        return (len(self.linksMap[switchID].keys()) != maxCount, maxCount)


def _convert_port_description_to_dict(portsDesc):
    """
    Converts the description of the ports of a switch to a dict.

    Arguments:
    ----------
    - `portsDesc`: Description of the ports of a switch.

    Return:
    -------
    Description of the ports as a dictionary.
    """
    
    ports = {}
    for i in range(len(portsDesc)):
        ports.update({portsDesc[i]['port_no']: portsDesc[i]['hw_addr']})
    
    return ports

def convert_int_to_switch_id(integer):
    """
    Convert an integer in base 10 to a switch id as a string.

    Arguments:
    ----------
    - `integer`: Integer to convert to string.

    Return:
    -------
    Switch ID as a string.
    """

    hexString = hex(integer)
    hexString = hexString[2:] # Remove 0x at the beginning of string
    for _ in range(SIZE_SWITCH_ID_HEX - len(hexString)):
        hexString = "0" + hexString
    
    return hexString


class Topology:
    """
    Represents the topology of the network by an undirected graph where
    the vertices of the graph are the network elements (hosts and switches)
    and the edges are the links between the elements.
    """

    def __init__(self, nbElements):
        """
        Initialize the object.

        Arguments:
        ----------
        - `nbElements`: Number of elements in the network.
        """
        self.nbElements = nbElements
        self._init_graph(self.nbElements)
        self.s0ID = 0

    def _init_graph(self, size=0):
        """
        Initializes the graph with a given size.

        Arguments:
        ----------
        - `size`: Number of elements in the graph.
        """

        self.nbElements = size
        self.graph = []
        emptyRow = []
        for _ in range(self.nbElements):
            emptyRow.append(0)
        for _ in range(self.nbElements):
            self.graph.append(copy.copy(emptyRow))

    def print(self):
        """
        Print the graph.
        """

        print("Topology: size {}".format(self.nbElements))
        for i in range(len(self.graph)):
            for j in range(len(self.graph[i])):
                if self.graph[i][j] == 1:
                    print("x", end='')
                else:
                    print(" ", end='')
            print("")
        print("")
    
    def fill_graph(self, nbElements, links):
        """
        Fill the graph of `nbElements` network elements with the given
        `links`.

        Arguments:
        ----------
        - `nbElements`: Number of elements in the graph.
        - `links`: List of links represented as an array of tuples
         (each tuple has a size of 2) and the elements of each tuple are the ids
         of the network elements.
        """

        self.nbElements = nbElements
        self._init_graph(self.nbElements)

        # Find max value because switch s0 has an id randomly generated by Ryu which has the maximum value.
        s0ID = 1
        for link in links:
            if len(link) != 2:
                print("Link {} has an unexpected format".format(link))
                continue
            if link[0] > s0ID:
                s0ID = link[0]
            if link[1] > s0ID:
                s0ID = link[1]

        self.s0ID = s0ID

        # Fill graph
        for link in links:
            if len(link) != 2:
                print("Link {} has an unexpected format".format(link))
                continue

            tmp = [0, 0]
            if link[0] == self.s0ID:
                tmp[0] = 0
            else:
                tmp[0] = link[0]

            if link[1] == self.s0ID:
                tmp[1] = 0
            else:
                tmp[1] = link[1]

            # Undirected graph => need to set both directions.
            try:
                self.graph[tmp[0]][tmp[1]] = 1
                self.graph[tmp[1]][tmp[0]] = 1
            except IndexError as _:
                continue
    
    def printMST(self, parent):
        """
        Print the spanning tree.

        Argument:
        ---------
        - `parent`: Represent the minimal spanning tree.
    
        Source: https://www.geeksforgeeks.org/prims-minimum-spanning-tree-mst-greedy-algo-5/?ref=lbp
        """
        print("Spanning tree")
        print("Edge \tWeight")
        for i in range(1, self.nbElements):
            print(parent[i], "-", i, " | ", self.graph[i][ parent[i] ])
        print("")
 
    def minKey(self, key, mstSet):
        """
        Find vertices with minimal cost.
        Source: https://www.geeksforgeeks.org/prims-minimum-spanning-tree-mst-greedy-algo-5/?ref=lbp
        """
 
        # Initialize min value
        min = sys.maxsize
        min_index = 0
 
        for v in range(self.nbElements):
            if key[v] < min and mstSet[v] == False:
                min = key[v]
                min_index = v
 
        return min_index
 
    def primMST(self):
        """
        Compute the minimum spanning tree with Prim's algorithm.
        Source: https://www.geeksforgeeks.org/prims-minimum-spanning-tree-mst-greedy-algo-5/?ref=lbp

        Return:
        -------
        Return the links that form the minimal spanning tree.
        """
 
        # Key values used to pick minimum weight edge in cut
        key = [sys.maxsize] * self.nbElements
        parent = [None] * self.nbElements # Array to store constructed MST
        # Make key 0 so that this vertex is picked as first vertex
        key[0] = 0
        mstSet = [False] * self.nbElements
 
        parent[0] = -1 # First node is always the root of
 
        for cout in range(self.nbElements):
 
            # Pick the minimum distance vertex from
            # the set of vertices not yet processed.
            # u is always equal to src in first iteration
            u = self.minKey(key, mstSet)
 
            # Put the minimum distance vertex in
            # the shortest path tree
            mstSet[u] = True
 
            # Update dist value of the adjacent vertices
            # of the picked vertex only if the current
            # distance is greater than new distance and
            # the vertex in not in the shortest path tree
            for v in range(self.nbElements):
 
                # graph[u][v] is non zero only for adjacent vertices of m
                # mstSet[v] is false for vertices not yet included in MST
                # Update the key only if graph[u][v] is smaller than key[v]
                if self.graph[u][v] > 0 and mstSet[v] == False and key[v] > self.graph[u][v]:
                        key[v] = self.graph[u][v]
                        parent[v] = u
 
        self.printMST(parent)
        
        tree = []
        for i in range(1, self.nbElements):
            tree.append([parent[i], i])

        return tree
    
    def findNeigborSwitches(self, switchID: int):
        """
        Find the neighbor switch(es) of the switch with the given ID.

        Argument:
        ---------
        - `switchID`: ID of the switch we are considering.

        Return:
        -------
        List of IDs of neighbor switches (can be empty).
        """

        neighbors = []

        tree = self.primMST()

        for link in tree:
            if link[0] == switchID:
                neighbors.append(link[1])
            if link[1] == switchID:
                neighbors.append(link[0])

        return neighbors
