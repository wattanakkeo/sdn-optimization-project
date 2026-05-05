"""
Runs Dijkstra but includes a flow timeout rule to help with pathing

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
        # dpid used to determine if a flow was high traffic
        self.possible_traffic = set()

    # Topology event handlers

    @set_ev_cls(topo_event.EventSwitchEnter)
    def switch_enter_handler(self, ev):
        switch = ev.switch
        dpid = switch.dp.id
        self.datapaths[dpid] = switch.dp
        self.logger.info("Switch connected: dpid=%016x", dpid)
        self._log_topology()

    @set_ev_cls(topo_event.EventSwitchLeave)
    def switch_leave_handler(self, ev):
        dpid = ev.switch.dp.id
        self.datapaths.pop(dpid, None)
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
        self._add_flow(datapath, 0, match, actions, idle_timeout=0, hard_timeout=0)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return  # handled by topology module

        src_mac = eth.src
        dst_mac = eth.dst
        src_dpid = datapath.id

        self.logger.info(
            "PacketIn dpid=%016x port=%d src=%s dst=%s",
            src_dpid, in_port, src_mac, dst_mac,
        )

        # compute the path and log it 
        self._compute_and_log_paths(src_dpid)

        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data,
        )
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        """Displays information about a flow that was removed"""
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        reason = msg.reason
        ofproto = datapath.ofproto
        
        removal_reason= {
            ofproto.OFPRR_IDLE_TIMEOUT: 'Idle Timeout',
            ofproto.OFPRR_HARD_TIMEOUT: 'Hard Timeout',
        }
        reason_str = removal_reason.get(reason, 'UNKNOWN')

        byte_count = msg.byte_count
        packet_count = msg.packet_count
        duration_sec = msg.duration_sec

        self.logger.info(
            "Flow removed: dpid=%016x reason=%s packets=%d bytes=%d duration=%ds",
            dpid, reason_str, packet_count, byte_count, duration_sec,
        )

        self._evaluate_expired_flow(dpid, reason, byte_count, duration_sec)

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

                if b in self.possible_traffic: # if the flow has heavy traffic, +3 hop cost
                    penalty = 3
                else:                       # if the flow doesn't have heavy traffic, +1 hop cost
                    penalty = 1 

                new_cost = dist[u] + penalty

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
    def _add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=15,hard_timeout=30):
        """Sets up flow and has it terminated when inactive for 15s or when 30s have passed since flow was added"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        kwargs = dict(datapath=datapath, priority=priority,
                      match=match, instructions=inst, 
                      idle_timeout=idle_timeout, hard_timeout=hard_timeout,
                      flags=ofproto.OFPFF_SEND_FLOW_REM)
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

    def _evaluate_expired_flow(self, dpid, reason, byte_count, duration_sec):
        """Determines if a flow would be considered high traffic or not"""
        ofproto = self.datapaths[dpid].ofproto
        traffic_threshold = 100_000

        if reason != ofproto.OFPRR_IDLE_TIMEOUT:
            return

        if duration_sec == 0:
            return

        bytes_per_sec = byte_count / duration_sec

        if bytes_per_sec > traffic_threshold:
            self.logger.warning(
                "High-traffic flow expired on dpid=%016x: %.2f KB/s over %ds",
                dpid, bytes_per_sec / 1000, duration_sec,
            )
            self.possible_traffic.add(dpid)
        else:
            self.possible_traffic.discard(dpid)
