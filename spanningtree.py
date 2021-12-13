from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet.ethernet import ethernet
from ryu.ofproto import ofproto_v1_0
from ryu.topology import event
from ryu.topology.api import get_all_host, get_host, get_switch, get_link
from ryu.lib.packet import packet, ethernet, ether_types

import copy
import sys

class SpanningTreeController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]
    
    def __init__(self, *args, **kwargs):
        """
        Initialize.
        """
        super(SpanningTreeController, self).__init__(*args, **kwargs)
        self.hosts = []             # MAC address of the hosts
        self.switches = []          # ID of the switches
        self.switchesMapping = []   # Mapping between the switches' ids and mac addresses + ports
        self.links = []             # List of links
        self.topology = Topology(0) # Represent the topology

    @set_ev_cls(event.EventSwitchEnter, MAIN_DISPATCHER)
    def switch_in_handler(self, ev):
        """
        Handler when a switch enters the topology.
        Based on https://github.com/Ehsan70/RyuApps/blob/master/TopoDiscoveryInRyu.md
            and https://sdn-lab.com/2014/12/31/topology-discovery-with-ryu/
        """

        print("Topology:")
        # Fetch data
        switch_list = copy.copy(get_switch(self, None))
        links_list = copy.copy(get_link(self, None))
        hosts_list = copy.copy(get_all_host(self))

        # List format
        switches = [switch.dp.id for switch in switch_list]
        switchesDetails = [switch.to_dict() for switch in switch_list]
        links = [(link.src.dpid,link.dst.dpid) for link in links_list]
        hosts = [(host.mac) for host in hosts_list]

        # Print
        #print("Nb hosts = {}".format(len(hosts)))
        #print("Hosts:")
        #print(sorted(hosts))
        print("Nb switches = {}".format(len(switches)))
        print("Switches:")
        print(sorted(switches))
        print("Switch details")
        for details in switchesDetails:
            print(details)
        
        # Analyze first entry
        print("Details switch 0")
        print(switchesDetails[0]['ports'])
        for i in range(len(switchesDetails[0]['ports'])):
            print("Port number {}".format(switchesDetails[0]['ports'][i]['port_no']))
            print("Port addr {}".format(switchesDetails[0]['ports'][i]['hw_addr']))
            print("Port name {}".format(switchesDetails[0]['ports'][i]['name']))

        #print("Nb links = {}".format(len(links)))
        #print("Links:")
        #print(links)

        # Mapping switches' ids and MAC addresses + ports
        

        # Save
        self.hosts = []
        self.switches = []
        self.links = []
        self.hosts = copy.copy(hosts)
        self.switches = copy.copy(switches)
        self.links = copy.copy(links)

        # Update topo
        self.topology.fill_graph(len(self.switches), self.links)
        #self.topology.print()
        self.topology.primMST()


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """
        Handler a packet arrives at the controller.
        """

        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser

        pkt = packet.Packet(msg.data)
        pkt_protocol = pkt.get_protocol(ethernet.ethernet)
        src = pkt_protocol.src
        dst = pkt_protocol.dst

        self._update_hosts_list()

        #print("Packet from {} (id = {}) to {}".format(src, dp.id,dst))

        actions = [ofp_parser.OFPActionOutput(ofp.OFPP_FLOOD)]

        data = None
        if msg.buffer_id == ofp.OFP_NO_BUFFER:
             data = msg.data

        out = ofp_parser.OFPPacketOut(
            datapath=dp, buffer_id=msg.buffer_id, in_port=msg.in_port,
            actions=actions, data = data)
        dp.send_msg(out)

    def _update_hosts_list(self):
        """
        Updates the list of the hosts.
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
        print("ID of s0 = {}".format(self.s0ID))

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
        Source: https://www.geeksforgeeks.org/prims-minimum-spanning-tree-mst-greedy-algo-5/?ref=lbp
        """
        print("Tree")
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
 
        #self.printMST(parent)
        
        tree = []
        for i in range(1, self.nbElements):
            tree.append([parent[i], i])
        return tree