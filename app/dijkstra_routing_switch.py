"""
Runs Dijkstra on every packetin to compute the shortest path.

Run:
    ryu-manager ryu/app/shortest_path_13.py --observe-links
"""

import heapq

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types
from ryu.topology import event as topo_event
from ryu.topology import switches as topo_switches


class ShortestPath13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'switches': topo_switches.Switches}

    def __init__(self, *args, **kwargs):
        super(ShortestPath13, self).__init__(*args, **kwargs)
        # dpid -> Datapath object
        self.datapaths = {}
        # adjacency[(src_dpid, dst_dpid)] = out_port on src toward dst
        self.adjacency = {}
        # mac_to_port[dpid][mac] = port number the mac was seen on
        self.mac_to_port = {}


    # Topology event handlers

    @set_ev_cls(topo_event.EventSwitchEnter)
    def switch_enter_handler(self, ev):
        switch = ev.switch
        dpid = switch.dp.id
        self.datapaths[dpid] = switch.dp
        self.mac_to_port.setdefault(dpid, {})
        self.logger.info("Switch connected: dpid=%016x", dpid)
        self._log_topology()

    @set_ev_cls(topo_event.EventSwitchLeave)
    def switch_leave_handler(self, ev):
        dpid = ev.switch.dp.id
        self.datapaths.pop(dpid, None)
        self.mac_to_port.pop(dpid, None)
        # Remove all adjacency entries involving this switch
        self.adjacency = {
            k: v for k, v in self.adjacency.items()
            if k[0] != dpid and k[1] != dpid
        }
        self.logger.info("Switch disconnected: dpid=%016x", dpid)

    @set_ev_cls(topo_event.EventLinkAdd)
    def link_add_handler(self, ev):
        link = ev.link
        src_dpid = link.src.dpid
        dst_dpid = link.dst.dpid
        out_port = link.src.port_no
        self.adjacency[(src_dpid, dst_dpid)] = out_port
        self.logger.info(
            "Link added: %016x port %d --> %016x", src_dpid, out_port, dst_dpid
        )
        self._log_topology()

    @set_ev_cls(topo_event.EventLinkDelete)
    def link_delete_handler(self, ev):
        link = ev.link
        src_dpid = link.src.dpid
        dst_dpid = link.dst.dpid
        self.adjacency.pop((src_dpid, dst_dpid), None)
        self.logger.info("Link removed: %016x --> %016x", src_dpid, dst_dpid)

    #OpenFlow event handling

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # Tablemiss: send all unknown packets to controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(datapath, 0, match, actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth_list = pkt.get_protocols(ethernet.ethernet)
        if not eth_list:
            return
        eth = eth_list[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return  # handled by topology module

        src_mac = eth.src
        dst_mac = eth.dst
        src_dpid = datapath.id

        self.logger.info(
            "PacketIn dpid=%016x port=%d src=%s dst=%s",
            src_dpid, in_port, src_mac, dst_mac,
        )
        
        # Only record the MAC if this port is a hostfacing port, not an
        # interswitch link. Flooding causes intermediate switches to see the
        # source MAC arrive on the uplink port, which would create a phantom
        # entry and break last-hop delivery.
        inter_switch_ports = {
            port for (dpid, _), port in self.adjacency.items()
            if dpid == src_dpid
        }
        if in_port not in inter_switch_ports:
            self.mac_to_port.setdefault(src_dpid, {})[src_mac] = in_port

        # try to forward via shortest path instead of flooding
        dst_dpid = self._find_dpid_for_mac(dst_mac)

        if dst_dpid is None:
            # Destination unknown flood so the host can reply and be learned
            self.logger.info("dst MAC %s unknown, flooding", dst_mac)
            actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        else:
            # We know where the destination is; compute the shortest path and
            # install one flow rule per switch along the path.
            path = self.get_path(src_dpid, dst_dpid)
            self.logger.info(
                "Path %016x -> %016x: %s",
                src_dpid, dst_dpid,
                ' -> '.join('%016x' % d for d in path) if path else 'NONE',
            )

            if not path:
                # No path found, fall back to flood
                actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
            else:
                try:
                    # install a flow on every intermediate switch
                    # For each hop except the last, the outport comes from adjacency.
                    for i in range(len(path) - 1):
                        hop_dpid = path[i]
                        next_dpid = path[i + 1]
                        out_port = self.adjacency[(hop_dpid, next_dpid)]
                        hop_dp = self.datapaths[hop_dpid]
                        hop_parser = hop_dp.ofproto_parser
                        match = hop_parser.OFPMatch(eth_dst=dst_mac)
                        flow_actions = [hop_parser.OFPActionOutput(out_port)]
                        self._add_flow(hop_dp, 1, match, flow_actions)
                        self.logger.info(
                            "Flow installed: dpid=%016x out_port=%d dst=%s",
                            hop_dpid, out_port, dst_mac,
                        )

                    # install a flow on the last switch to the host port
                    last_dpid = path[-1]
                    host_port = self.mac_to_port[last_dpid][dst_mac]
                    last_dp = self.datapaths[last_dpid]
                    last_parser = last_dp.ofproto_parser
                    match = last_parser.OFPMatch(eth_dst=dst_mac)
                    flow_actions = [last_parser.OFPActionOutput(host_port)]
                    self._add_flow(last_dp, 1, match, flow_actions)
                    self.logger.info(
                        "Flow installed (last hop): dpid=%016x out_port=%d dst=%s",
                        last_dpid, host_port, dst_mac,
                    )

                    # Determine the outport for the current packet on this switch
                    if len(path) == 1:
                        out_port = host_port
                    else:
                        out_port = self.adjacency[(src_dpid, path[1])]

                    actions = [parser.OFPActionOutput(out_port)]

                except KeyError as e:
                    # Topology changed mid-handler (link/switch removed). Fall
                    # back to flood so the packet is not silently dropped.
                    self.logger.warning(
                        "Path install aborted (KeyError: %s), flooding", e
                    )
                    actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]

        # Send the current packet out
        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data,
        )
        datapath.send_msg(out)

    # Dijkstra
    def dijkstra(self, src_dpid):
        """Return (dist, prev) dicts for shortest hop-count paths from src_dpid."""
        dist = {dpid: float('inf') for dpid in self.datapaths}
        prev = {dpid: None for dpid in self.datapaths}
        dist[src_dpid] = 0
        # min-heap: (cost, dpid)
        heap = [(0, src_dpid)]

        while heap:
            cost, u = heapq.heappop(heap)
            if cost > dist[u]:
                continue
            for (a, b), _port in self.adjacency.items():
                if a != u:
                    continue
                new_cost = dist[u] + 1  # uniform hop cost
                if new_cost < dist[b]:
                    dist[b] = new_cost
                    prev[b] = u
                    heapq.heappush(heap, (new_cost, b))

        return dist, prev

    def get_path(self, src_dpid, dst_dpid):
        """Return ordered list of dpids from src to dst, or [] if unreachable."""
        if src_dpid not in self.datapaths or dst_dpid not in self.datapaths:
            return []
        _dist, prev = self.dijkstra(src_dpid)
        path = []
        node = dst_dpid
        while node is not None:
            path.append(node)
            node = prev[node]
        path.reverse()
        if path and path[0] == src_dpid:
            return path
        return []

    # Helpers methods

    def _add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        kwargs = dict(datapath=datapath, priority=priority,
                      match=match, instructions=inst)
        if buffer_id is not None:
            kwargs['buffer_id'] = buffer_id
        datapath.send_msg(parser.OFPFlowMod(**kwargs))

    def _log_topology(self):
        self.logger.info(
            "Topology: %d switch(es), %d link(s)",
            len(self.datapaths), len(self.adjacency),
        )
        for (src, dst), port in self.adjacency.items():
            self.logger.info(
                "  %016x --port%d--> %016x", src, port, dst
            )

    def _compute_and_log_paths(self, src_dpid):
        """Log Dijkstra paths from src_dpid to every other known switch."""
        if len(self.datapaths) < 2:
            return
        dist, _prev = self.dijkstra(src_dpid)
        for dst_dpid in self.datapaths:
            if dst_dpid == src_dpid:
                continue
            path = self.get_path(src_dpid, dst_dpid)
            if path:
                hops = ' -> '.join('%016x' % d for d in path)
                self.logger.info(
                    "Shortest path %016x -> %016x (%d hops): %s",
                    src_dpid, dst_dpid, dist[dst_dpid], hops,
                )
            else:
                self.logger.info(
                    "No path from %016x to %016x", src_dpid, dst_dpid
                )
                
    def _find_dpid_for_mac(self, mac):
        for dpid, mac_table in self.mac_to_port.items():
            if mac in mac_table:
                return dpid
        return None
