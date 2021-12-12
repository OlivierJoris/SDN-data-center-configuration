import networkx as nx

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link

class SpanningTree(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SpanningTree, self).__init__(*args, **kwargs)
        self.network = nx.DiGraph()
        self.tree = nx.DiGraph()

    def update_tree(self, link1, link2):
        self.network.add_edge_from(link1)
        self.network.add_edge_from(link2)
        
        self.tree = nx.minimum_spanning_tree(self.network)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser

        # Received packet
        pkt = packet.Packet(msg.data)
        ptcl_pkt = pkt.get_protocol(ethernet.ethernet)
        destination = ptcl_pkt.dst
        source = ptcl_pkt.src

        # Learn source if not in initial tree and add link 
        if source not in self.tree: 
            self.tree.add_node(source)
            self.tree.add_edge(source, dp.id)
            self.tree.add_edge(dp.id, source, {'port':msg.in_port})  

        if destination in self.tree:
            path = nx.shortest_path(self.tree, source, destination) 
            nxt = path[path.index(dp.id) + 1] 
            output_port = self.tree[dp.id][nxt]['port'] 
        # Learn source if not in initial tree
        else:
            self.tree.add_node(destination)
            self.tree.add_edge(destination, dp.id)
            self.tree.add_edge(dp.id, destination, {'port':msg.in_port})  

        actions = [ofp_parser.OFPActionOutput(output_port)]

        #self.logger.info("Packet received from %s at port %s", dp.id, msg.in_port)

        # Match inside switch 
        if output_port != ofp.OFPP_FLOOD:
            match = ofp_parser.OFPMatch(in_port=msg.in_port, dl_dst=destination)

            flow_mod = ofp_parser.OFPFlowMod(datapath=dp, priority=1,
                                        match=match, actions=actions)
            dp.send_msg(flow_mod)

        data = None
        if msg.buffer_id == ofp.OFP_NO_BUFFER:
            data = msg.data

        out = ofp_parser.OFPPacketOut(
                    datapath=dp, buffer_id=msg.buffer_id,
                    in_port=msg.in_port, actions=actions, data=data)  
                
        dp.send_msg(out)

    @set_ev_cls(event.EventSwitchEnter, MAIN_DISPATCHER)
    def get_topology_data(self, ev):
        links_list = get_link(self, None)
        link1 = [(link.src.dpid,link.dst.dpid,{'port':link.src.port_no}) for link in links_list]

        links_list = get_link(self, None)
        link2 = [(link.dst.dpid,link.src.dpid,{'port':link.dst.port_no}) for link in links_list]
        self.update_tree(link1, link2)
        