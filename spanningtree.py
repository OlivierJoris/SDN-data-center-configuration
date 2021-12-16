# Authors: Maxime Goffart (180521) and Olivier Joris (182113)

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
        self.datapath = {}          # Mapping between switch ID (int) and associated datapath object
        self.links = []             # List of links
        self.linksMap = {}          # Mapping between a switch id and the id of a neighbor switch with the port to reach it
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

        Argument:
        ---------
        - `ev`: Event generated when the switch contacted the controller.

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

        # Save
        self._update_hosts_list()
        self.switches = []
        self.switches = copy.copy(switches)
        self.links = []
        self.links = copy.copy(links)

        # Mapping switches' ids and MAC addresses + ports
        self._update_switch_mappings(switchesDetails)

        # Map of links
        self._update_link_map()

        # Update topo and build minimal spanning tree
        self.topology.fill_graph(len(self.switches), self.links)
        self.topology.primMST()

        self.datapath.update({ev.switch.dp.id: ev.switch.dp})

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """
        Handler called when a packet arrives at the controller.

        Argument:
        ---------
        - `ev`: Event generated.
        """

        # Update the list of hosts and map of links
        self._update_hosts_list()
        self._update_link_map()

        msg = ev.msg
        dp = msg.datapath

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        # Ignore link discovery packet
        if eth == ether_types.ETH_TYPE_LLDP:
            return

        src = eth.src
        dst = eth.dst

        if ((src in self.hosts) and (dst in self.hosts)) or ((src in self.hosts) and (dst == MAC_BROADCAST)):
            print("Packet from {} to {} received at sw {} port {}".format(src, dst, dp.id, msg.in_port))

        """
        If the destination is broadcast (e.g. in the case of ARP request) and
        the src is one of the host, need to broadcast on all the ports of the
        switch connected to the spanning tree
        """
        if src in self.hosts and dst == MAC_BROADCAST:
            self.flood_neigbors(ev)
            return

        """
        If the source and the destination are hosts, need to compute a path
        between them and set flows along the path.
        """
        if (src in self.hosts) and (dst in self.hosts):
            paths = self.compute_paths(src, dst)
            self.add_flows_path(ev, paths)

            return

        return

    def flood_neigbors(self, ev):
        """
        Flood a packet to the neighbors of the switch.
        Neighbors are limited to the ones connected to the switch
        in the minimal spanning tree.

        Argument:
        ---------
        - `ev`: Event received in the handler.
        """

        """
        If the destination is broadcast (e.g. in the case of ARP request) and
        the src is one of the host, need to broadcast on all the ports of the
        switch connected to the spanning tree
        """

        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        src = eth.src
        dst = eth.dst

        switchIdInt = dp.id
        switchIdString = _convert_int_to_switch_id(dp.id)
        
        # Get neighbors of switch in spanning tree
        neighbors = self.topology.findNeigborSwitches(switchIdInt)

        # Find the ports on which to send the packet to reach the neighbors
        listPorts = []
        for neighbor in neighbors:
            tmpNeighbor = neighbor
            if tmpNeighbor == 0:
                tmpNeighbor = self.topology.s0ID
            neighborID = _convert_int_to_switch_id(tmpNeighbor)
            port = self.linksMap[switchIdString][neighborID]
            listPorts.append(port)
        
        # If the switch is a edge switch, send on ports of hosts
        edge, maxN = self._is_edge_switch(switchIdString)
        if edge:
            portsUsed = []
            keys = self.linksMap[switchIdString].values()
            for key in keys:
                portsUsed.append(int(key))
            for i in range(1, maxN+1):
                if i not in portsUsed:
                    listPorts.append(str(i))
        
        # Build actions: send on ports to reach neighbors
        actions = []
        for port in listPorts:
            if int(port) == msg.in_port: # do not send back on the port on which the packet arrived
                continue
            actions.append(ofp_parser.OFPActionOutput(int(port)))

        # Add flows
        match = ofp_parser.OFPMatch(dl_src = src, dl_dst = dst, in_port = msg.in_port)
        self.add_flow(dp, 1, match, actions)

        # Need to send current packet
        data = None
        if msg.buffer_id == ofp.OFP_NO_BUFFER:
            data = msg.data
        
        out = ofp_parser.OFPPacketOut(
            datapath = dp, buffer_id = msg.buffer_id, in_port = msg.in_port,
            actions = actions, data = data
        )

        dp.send_msg(out)

    def add_flows_path(self, ev, paths: list):
        """
        Add flows along a path. Used when the source and the destination of a packet
        are hosts inside the network.

        Arguments:
        ----------
        - `ev`: Event receives in the handler.
        - `paths`: List of paths on which to set the flows.
        """

        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        src = eth.src
        dst = eth.dst

        # Base case: source and destination are connected to the same switch
        if len(paths) == 1 and len(paths[0]) == 1:

            match = ofp_parser.OFPMatch(dl_src = src, dl_dst = dst, in_port = msg.in_port)
            action = [ofp_parser.OFPActionOutput(int(self.hostSwitchMapping[dst]['port']))]

            # Add flow
            self.add_flow(dp, 2, match, action)

            # Need to send current packet
            data = None
            if msg.buffer_id == ofp.OFP_NO_BUFFER:
                data = msg.data
            
            out = ofp_parser.OFPPacketOut(
                datapath = dp, buffer_id = msg.buffer_id, in_port = msg.in_port,
                actions = action, data = data
            )

            dp.send_msg(out)
        
        # If source and destination are connected to different switches
        elif len(paths) >= 1 and len(paths[0]) > 1:
            # Should have only one path due to minimal spanning tree
            in_port = msg.in_port

            for index in range(len(paths[0])):
                # 1) Config match rule
                match = ofp_parser.OFPMatch(dl_src = src, dl_dst = dst, in_port = in_port)

                # 2) Get port on which to reach next switch (or destination host if end of path)
                currSwitch = paths[0][index]
                port = 0
                if index == len(paths[0]) - 1: # The next hop is the host destination
                    port = int(self.hostSwitchMapping[dst]['port'])
                else: # The next hop is the next switch in the path
                    nextSwitch = paths[0][index+1]
                    port = int(self.linksMap[currSwitch][nextSwitch])

                # 3) Config action list
                action = [ofp_parser.OFPActionOutput(port)]

                # 4) Add flow using datapath of current switch in path
                currDP = self.datapath[int(currSwitch, 16)]
                self.add_flow(currDP, 2, match, action)

                # 5) Update in_port
                if index < len(paths[0]) - 1:
                    nextSwitch = paths[0][index+1]
                    in_port = int(self.linksMap[nextSwitch][currSwitch])

            # Need to send current packet to next hop
            data = None
            if msg.buffer_id == ofp.OFP_NO_BUFFER:
                data = msg.data

            action = [ofp_parser.OFPActionOutput(int(self.linksMap[_convert_int_to_switch_id(dp.id)][paths[0][1]]))]

            out = ofp_parser.OFPPacketOut(
                datapath = dp, buffer_id = msg.buffer_id, in_port = msg.in_port,
                actions = action, data = data
            )

            dp.send_msg(out)

        return

    def _update_hosts_list(self):
        """
        Update the list of MAC addresses of the hosts and the mapping
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
        Update the mappings between the switches ids and ports' descriptions.

        Arguments:
        ----------
        - `switchDetails`: Details about the switches.
        """

        self.switchesMapping.clear()
        
        for sw in range(len(switchDetails)):
            ports = _convert_port_description_to_dict(switchDetails[sw]['ports'])
            self.switchesMapping.update({switchDetails[sw]['dpid']: ports})

    def _update_link_map(self):
        """
        Update the mapping between a switch id and the id of a neighbor switch and the port to reach it.
        """

        # Fetch data
        links_list = copy.copy(get_link(self, None))
        links = [(link.src.dpid,link.dst.dpid) for link in links_list]
        linksDetails = [link.to_dict() for link in links_list]
        # Save
        self.links = []
        self.links = copy.copy(links)

        """
        Find max value because switch s0 has an id randomly generated
        by Ryu which has the maximum value
        """
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

            sourceIDInt = int(sourceID, 16)
            if sourceIDInt > len(self.switches):
                sourceIDInt = 0

            sources[sourceIDInt] = sourceID
            maps[sourceIDInt].update({destID: sourceOutPort})

        # Group dictionaries by source switch
        for source in sources:
            sourceID = int(source, 16)
            if sourceID > len(self.switches):
                sourceID = 0
            self.linksMap.update({source: maps[sourceID]})
    
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
        Compute paths between source `src` and destination `dst`.
        The returned paths  arelimited to links in the spanning tree.

        Arguments:
        ----------
        - `src`: MAC address of source host.
        - `dst`: MAC address of destination host.

        Returns:
        --------
        - Paths between 2 hosts where a path is a list of switch ids (list of str).
        """

        # Get switch to which src and dst are connected
        switchSRC = self.hostSwitchMapping[src]['dpid']
        switchDST = self.hostSwitchMapping[dst]['dpid']

        # If src and dst are connected to the same switch, return simple path
        if switchSRC == switchDST:
            return [[switchSRC]] # Equivalently switchDST

        # Compute paths using DFS
        validPaths = []
        stack = [(switchSRC, [switchSRC])]
        while stack:
            _, path = stack.pop()
            # Need to fetch the neighbors of last element of path
            last = path[-1]
            neighbors = self.topology.findNeigborSwitches(int(last, 16))

            for neighbor in neighbors:
                tmpNeighbor = neighbor
                if tmpNeighbor == 0:
                    tmpNeighbor = self.topology.s0ID
                n = _convert_int_to_switch_id(tmpNeighbor)
                if n == switchDST:
                    validPaths.append(path + [n])
                elif n not in path: # prevent loop
                    stack.append((n, path + [n]))

        return validPaths

def _convert_port_description_to_dict(portsDesc: list) -> dict:
    """
    Convert the description of the ports of a switch to a dict.

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

def _convert_int_to_switch_id(integer: int) -> str:
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
    Represent the topology of the network by an undirected graph where
    the vertices of the graph are the network elements (switches)
    and the edges are the links between the elements.
    """

    def __init__(self, nbElements: int):
        """
        Initialize the object.

        Arguments:
        ----------
        - `nbElements`: Number of elements in the network.
        """
        self.nbElements = nbElements
        self._init_graph(self.nbElements)
        self.s0ID = 0

    def _init_graph(self, size: int=0):
        """
        Initialize the graph with a given size.

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
    
    def fill_graph(self, nbElements: int, links: list):
        """
        Fill the graph of `nbElements` network elements with the given
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

        """
        Find max value because switch s0 has an id randomly generated
        by Ryu which has the maximum value
        """
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
 
    def minKey(self, key: list, mstSet: list) -> int:
        """
        Find vertices with minimal cost.

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
        Compute the minimum spanning tree with Prim's algorithm.

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

        if switchID > self.nbElements:
            switchID = 0

        tree = self.primMST()

        for link in tree:
            if link[0] == switchID:
                neighbors.append(link[1])
            if link[1] == switchID:
                neighbors.append(link[0])

        return neighbors
