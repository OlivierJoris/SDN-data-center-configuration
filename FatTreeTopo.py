import math
import os

from mininet.cli import CLI
from mininet.net import Mininet
from mininet.topo import Topo
from mininet.log import setLogLevel

from mininet.node import OVSSwitch, RemoteController
from mininet.link import TCLink


class FatTreeTopo(Topo):
    coreLayer = []
    aggregationLayer = []
    edgeLayer = []
    hostsLayer = []

    nbSwitches = 0
    nbHosts = 0

    def __init__(self, k, nbPods, linkBandwidth, maxQ, delay, **opts):
        Topo.__init__(self, **opts)
        self.k = k
        self.nbPods = nbPods
        self.maxQ = maxQ
        self.delay = delay
        self.linkBandwidth = linkBandwidth

        if self.k % 2 != 0:
            raise runtime_error(
                "Error: k-Ary Fat Tree can only be created for even parameter k.")

        if self.nbPods > self.k:
            raise runtime_error(
                "Error: k-Ary Fat Tree can handled up to k pods.")

        # Create the Pods
        for i in range(self.nbPods):
            self.addPod()

        # Create the Core Layer
        for i in range(round((self.k/2)**2)):
            self.addcoreLayer()

    def addcoreLayer(self):
        sw = self._addSwitch()

        for pods in self.aggregationLayer:
            self._addLink(
                sw, pods[math.floor(len(self.coreLayer)/(round(self.k/2)))])

        self.coreLayer.append(sw)

    def addPod(self):
        # Aggregation Layer
        self.aggregationLayer.append([])
        for i in range(round(self.k/2)):
            sw = self._addSwitch()

            self.aggregationLayer[-1].append(sw)

        # Access Layer
        self.edgeLayer.append([])
        for i in range(round(self.k/2)):
            sw = self._addSwitch()

            for aggrsw in self.aggregationLayer[-1]:
                self._addLink(sw, aggrsw)

            self.edgeLayer[-1].append(sw)

        # hosts
        self.hostsLayer.append([])
        for i in range(round((self.k/2)**2)):
            h = self._addHost()

            self._addLink(
                h, self.edgeLayer[-1][math.floor(i/(round(self.k/2)))])

            self.hostsLayer[-1].append(h)

    def _addSwitch(self):
        sw = self.addSwitch("s" + str(self.nbSwitches))
        self.nbSwitches = self.nbSwitches + 1

        return sw

    def _addHost(self):
        h = self.addHost("h" + str(self.nbHosts))
        self.nbHosts = self.nbHosts + 1

        return h

    def _addLink(self, node1, node2):
        self.addLink(node1, node2,
                     cls=TCLink,
                     bw=self.linkBandwidth,
                     delay=f'{self.delay}ms',
                     max_queue_size=self.maxQ
                     )


if __name__ == "__main__":
    from argparse import ArgumentParser

    # Parse arguments
    parser = ArgumentParser(description="")
    parser.add_argument('--k',
                        dest="k",
                        type=int,
                        action="store",
                        help="Parameter k of k-Ary FatTree topology (cfr. Al-Fares et al.)",
                        required=True
                        )

    parser.add_argument('--nbPods',
                        dest="nbPods",
                        type=int,
                        action="store",
                        help="Number of pods in the FatTree topology (cfr. Al-Fares et al.)",
                        required=True
                        )

    parser.add_argument('--bw',
                        dest="bw",
                        type=int,
                        action="store",
                        help="Bandwidth of links (Mb/s)",
                        default=100
                        )

    parser.add_argument('--delay',
                        dest="delay",
                        type=int,
                        action="store",
                        help="Delay of links (ms)",
                        default=50
                        )

    parser.add_argument('--maxQ',
                        dest="maxQ",
                        type=int,
                        action="store",
                        help="Max buffer size of network interfaces (packets)",
                        default=20
                        )

    args = parser.parse_args()

    print("Create network and run basic experiments")
    topo = FatTreeTopo(
        k=args.k,
        nbPods=args.nbPods,
        linkBandwidth=args.bw,
        maxQ=args.maxQ,
        delay=args.delay
    )

    controller = RemoteController('c0')

    net = Mininet(topo=topo, link=TCLink, switch=OVSSwitch,
                  controller=RemoteController('c0'), autoSetMacs=True)
    setLogLevel('info')

    net.start()

    CLI(net)
    net.stop()
