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

import copy
import sys

MAC_BROADCAST = 'ff:ff:ff:ff:ff:ff' # MAC addr for broadcast
SIZE_SWITCH_ID_HEX = 16             # Nb of hexadecimal digits in a switch ID

class SpanningTreeController(app_manager.RyuApp):
    """
    Implementation of controller that builds a spanning tree.
    """

    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION] # Set OpenFlow version
    
    def __init__(self, *args, **kwargs):
        """
        Initialize.
        """
        super(SpanningTreeController, self).__init__(*args, **kwargs)
        self.hosts = []             # MAC addresses of the hosts
        self.hostSwitchMapping = {} # Mapping between the id of a host and the id of the switch to which its is connected.
        self.switches = []          # IDs of the switches
        self.switchesMapping = {}   # Mapping between the switches' ids and mac addresses + ports
        self.dataflows = {}         # Mapping between switch ID (int) and associated dataflow object.
        self.links = []             # List of links
        self.linksMap = {}          # Mapping between a switch id and the id of a neighbor switch with the port to reach it.
        self.topology = Topology(0) # Represents the topology
    
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        """
        Add a flow inside a switch.

        Arguments:
        ----------
        - `datapath`: Datapath that represent the switch.
        - `priority`: Priority of the flow.
        - `match`: Matching rule.
        - `actions`: Actions of the flow.
        - `buffer_id`: ID of the packet inside the buffer of the switch.

        Source: Based on official book (page 8). Adapted to OpenFlow 1.0.
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

        # Fetch data
        switch_list = copy.copy(get_switch(self, None))
        links_list = copy.copy(get_link(self, None))

        # List format
        switches = [switch.dp.id for switch in switch_list]
        switchesDetails = [switch.to_dict() for switch in switch_list]
        links = [(link.src.dpid,link.dst.dpid) for link in links_list]
        linksDetails = [link.to_dict() for link in links_list]

        # Save
        self._update_hosts_list()
        self.switches = []
        self.switches = copy.copy(switches)
        self.dataflows.update({ev.switch.dp.id: ev.switch.dp})
        self.links = []
        self.links = copy.copy(links)

        # Mapping switches' ids and MAC addresses + ports
        self._update_switch_mappings(switchesDetails)

        # Map of links
        self._update_link_map(links, linksDetails)

        # Update topo and build minimal spanning tree
        self.topology.fill_graph(len(self.switches), self.links)
        self.topology.primMST()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
        Handler when the controller receives the response to the
        features request for a switch.

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

        if ((src in self.hosts) and (dst in self.hosts)) or ((src in self.hosts) and (dst == MAC_BROADCAST)):
            print("Packet from {} to {} received at sw {} port {}".format(src, dst, dp.id, msg.in_port))

        # If the destination is broadcast (e.g. in the case of ARP request) and the src is one of the host,
        # need to add a flow to go back to the host and broadcast on all the ports of the switch
        # connected to the spanning tree
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
                if int(port) == msg.in_port: # do not send back on the port on which the packet arrived
                    continue
                print("Add flow to send packet on all allowed port: packet_src={} flow_dst={} action_port={}".format(src, dst, port))
                actions.append(ofp_parser.OFPActionOutput(int(port)))
            print("")

            # Add flow
            match = ofp_parser.OFPMatch(dl_src = src, dl_dst = dst)
            self.add_flow(dp, 1, match, actions)

            # Send OFPPacketOut for the current packet.
            data = None
            if msg.buffer_id == ofp.OFP_NO_BUFFER:
                data = msg.data
            
            out = ofp_parser.OFPPacketOut(
                datapath = dp, buffer_id = msg.buffer_id, in_port = msg.in_port,
                actions = actions, data = data
            )

            dp.send_msg(out)

            return

        if (src in self.hosts) and (dst in self.hosts):
            self.compute_paths(src, dst)
            print("")
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
        Updates the list of MAC addresses of the hosts and the mapping
        between the hosts' ids and the id of the switch to which each host
        is connected.
        """

        hosts_list = copy.copy(get_all_host(self))
        hosts = [(host.mac) for host in hosts_list]
        self.hosts = []
        self.hosts = copy.copy(hosts)

        hostDetails = [host.to_dict() for host in hosts_list]
        
        self.hostSwitchMapping.clear()
        for host in range(len(hostDetails)):
            mapping = {
                'dpid': hostDetails[host]['port']['dpid'],
                'port': hostDetails[host]['port']['port_no']
            }
            self.hostSwitchMapping.update({hostDetails[host]['mac']: mapping})
    
    def _update_switch_mappings(self, switchDetails: list):
        """
        Updates the mappings between the switches ids and ports' descriptions.

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
        
        print("Mapping between switch id and ports desc. (switch id -> {port id : port mac})")
        for switch in self.switchesMapping:
            print(str(switch) + " -> " + str(self.switchesMapping[switch]))

    def _update_link_map(self, links: list, linksDetails: list):
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
            sources.append("0")
        maps = []
        for _ in range(nbSwitches):
            maps.append({})

        # For each link, build a dictionary
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

        # Group dictionaries by source switch
        for source in sources:
            self.linksMap.update({source: maps[int(source, 16)]})
        
        print("Link map (switch id -> {neighbor switch id: port of source to reach neigbor})")
        for source in self.linksMap:
            print(str(source) + " -> " + str(self.linksMap[source]))
    
    def _is_edge_switch(self, switchID: str):
        """
        Return true if the switch is a edge/TOR switch. Else, return false.

        Argument:
        ---------
        - `switchID`: ID of the switch.

        Return:
        -------
        Tuple containing whether the switch is a edge switch or not and the max
        number of links for a switch.
        """

        countPorts = {}
        for switch in self.linksMap:
            countPorts.update({switch: len(self.linksMap[switch].keys())})
        
        maxCount = 0
        for count in countPorts:
            if countPorts[count] > maxCount:
                maxCount = countPorts[count]
        
        return (len(self.linksMap[switchID].keys()) != maxCount, maxCount)
    
    def compute_paths(self, src: str, dst: str) -> list:
        """
        Computes paths between source `src` and destination `dst`.
        The returned paths are limited to links in the spanning tree.

        Arguments:
        ----------
        - `src`: MAC address of source host.
        - `dst`: MAC address of destination host.

        Returns:
        --------
        - Paths between 2 hosts where a path is a list of switch ids (list of str).
        """

        print("Computing path btw {} and {}".format(src, dst))

        # Get switch to which src and dst are connected
        switchSRC = self.hostSwitchMapping[src]['dpid']
        switchDST = self.hostSwitchMapping[dst]['dpid']

        # If src and dst are connected to the same switch, return simple path
        if switchSRC == switchDST:
            return [[switchSRC]] # Equivalently switchDST

        # Compute path using DFS
        paths = []
        stack = [(switchSRC, [switchSRC])]
        while stack:
            _, path = stack.pop()
            # Need to fetch the neighbors of last element of path
            last = path[-1]
            neighbors = self.topology.findNeigborSwitches(int(last, 16))

            for neighbor in neighbors:
                n = convert_int_to_switch_id(neighbor)
                if n == switchDST:
                    paths.append(path + [n])
                elif n not in path: # prevent loop by going back to last switch
                    stack.append((n, path + [n]))

        print("Paths between {} and {}".format(src, dst))
        print(paths)

        return paths


def _convert_port_description_to_dict(portsDesc: list) -> dict:
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

def convert_int_to_switch_id(integer: int) -> str:
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
    the vertices of the graph are the network elements (switches)
    and the edges are the links between the elements.
    """

    def __init__(self, nbElements: int):
        """
        Initializes the object.

        Arguments:
        ----------
        - `nbElements`: Number of elements in the network.
        """
        self.nbElements = nbElements
        self._init_graph(self.nbElements)
        self.s0ID = 0

    def _init_graph(self, size: int=0):
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
        Prints the graph.
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
    
    def fill_graph(self, nbElements: int, links: list):
        """
        Fills the graph of `nbElements` network elements with the given
        `links`.

        Arguments:
        ----------
        - `nbElements`: Number of elements in the graph.
        - `links`: List of links represented as a list of tuples
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
    
    def printMST(self, parent: list):
        """
        Prints the spanning tree.

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
 
    def minKey(self, key: list, mstSet: list) -> int:
        """
        Finds vertices with minimal cost.

        Return:
        -------
        Index of vertex with minimal cost.

        Source: https://www.geeksforgeeks.org/prims-minimum-spanning-tree-mst-greedy-algo-5/?ref=lbp
        """
 
        min = sys.maxsize
        min_index = 0
 
        for v in range(self.nbElements):
            if key[v] < min and mstSet[v] == False:
                min = key[v]
                min_index = v
 
        return min_index
 
    def primMST(self) -> list:
        """
        Computes the minimum spanning tree with Prim's algorithm.

        Return:
        -------
        Links that form the minimal spanning tree.

        Source: https://www.geeksforgeeks.org/prims-minimum-spanning-tree-mst-greedy-algo-5/?ref=lbp
        """

        key = [sys.maxsize] * self.nbElements
        parent = [None] * self.nbElements # Minimal spanning tree
        key[0] = 0
        mstSet = [False] * self.nbElements
 
        parent[0] = -1
 
        for cout in range(self.nbElements):
 
            u = self.minKey(key, mstSet)

            mstSet[u] = True
 
            for v in range(self.nbElements):
                if self.graph[u][v] > 0 and mstSet[v] == False and key[v] > self.graph[u][v]:
                        key[v] = self.graph[u][v]
                        parent[v] = u
 
        #self.printMST(parent)
        
        tree = []
        for i in range(1, self.nbElements):
            tree.append([parent[i], i])

        return tree

    def findNeigborSwitches(self, switchID: int) -> list:
        """
        Find the neighbor switch(es) of the switch with the given ID.
        The neighbors are limited to the ones in the minimal spanning tree.

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
