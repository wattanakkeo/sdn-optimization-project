"""
ECMP-based shortest-path routing using Ryu OF 1.3.

Run:
    ryu-manager app/dijkstra_routing_switch.py --observe-links
"""

import heapq
import zlib

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, ipv4, tcp, udp
from ryu.topology import event as topo_event
from ryu.topology import switches as topo_switches

FLOW_PRIORITY = 10
FLOW_IDLE_TIMEOUT = 30


class ShortestPath13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'switches': topo_switches.Switches}

    def __init__(self, *args, **kwargs):
        super(ShortestPath13, self).__init__(*args, **kwargs)
        # dpid -> Datapath object
        self.datapaths = {}
        # adjacency[(src_dpid, dst_dpid)] = out_port on src toward dst
        self.adjacency = {}
        # host_location[mac] = (dpid, in_port)
        self.host_location = {}

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

    # OpenFlow event handling

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # Table-miss: send all unknown packets to controller
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

        # Learn host location on first PacketIn from each MAC
        if src_mac not in self.host_location:
            self.host_location[src_mac] = (src_dpid, in_port)
            self.logger.info(
                "Learned host %s at dpid=%016x port=%d",
                src_mac, src_dpid, in_port,
            )

        if dst_mac in self.host_location:
            dst_dpid, dst_port = self.host_location[dst_mac]
            self._install_ecmp_path(
                pkt, src_mac, dst_mac,
                src_dpid, in_port, dst_dpid, dst_port,
                msg.buffer_id, msg.data, ofproto, parser,
            )
        else:
            # Destination unknown: flood so hosts can ARP-discover each other
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

    # ECMP path installation

    def _install_ecmp_path(self, pkt, src_mac, dst_mac,
                           src_dpid, in_port, dst_dpid, dst_port,
                           buffer_id, raw_data, ofproto, parser):
        """Pick an ECMP path, install match/action rules on every hop, send PacketOut."""
        src_dp = self.datapaths[src_dpid]

        if src_dpid == dst_dpid:
            # Both hosts on the same switch
            match = parser.OFPMatch(eth_src=src_mac, eth_dst=dst_mac)
            actions = [parser.OFPActionOutput(dst_port)]
            self._add_flow(src_dp, FLOW_PRIORITY, match, actions,
                           idle_timeout=FLOW_IDLE_TIMEOUT)
            data = raw_data if buffer_id == ofproto.OFP_NO_BUFFER else None
            out = parser.OFPPacketOut(
                datapath=src_dp, buffer_id=buffer_id, in_port=in_port,
                actions=actions, data=data,
            )
            src_dp.send_msg(out)
            return

        all_paths = self._get_all_paths(src_dpid, dst_dpid)
        if not all_paths:
            self.logger.warning(
                "No path from %016x to %016x; flooding", src_dpid, dst_dpid
            )
            actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
            data = raw_data if buffer_id == ofproto.OFP_NO_BUFFER else None
            out = parser.OFPPacketOut(
                datapath=src_dp, buffer_id=buffer_id, in_port=in_port,
                actions=actions, data=data,
            )
            src_dp.send_msg(out)
            return

        n = len(all_paths)
        k = self._flow_hash(pkt, src_mac, dst_mac, n)
        chosen = all_paths[k]

        hops = ' -> '.join('%016x' % d for d in chosen)
        self.logger.info(
            "ECMP path %d/%d for flow %s->%s: %s",
            k + 1, n, src_mac, dst_mac, hops,
        )

        # Install a flow rule on every switch along the chosen path
        for i, dpid in enumerate(chosen):
            dp = self.datapaths[dpid]
            dp_parser = dp.ofproto_parser
            out_port = (self.adjacency[(dpid, chosen[i + 1])]
                        if i < len(chosen) - 1 else dst_port)
            match = dp_parser.OFPMatch(eth_src=src_mac, eth_dst=dst_mac)
            actions = [dp_parser.OFPActionOutput(out_port)]
            self._add_flow(dp, FLOW_PRIORITY, match, actions,
                           idle_timeout=FLOW_IDLE_TIMEOUT)

        # Send the in-flight packet out from the ingress switch
        first_out_port = (self.adjacency[(chosen[0], chosen[1])]
                          if len(chosen) > 1 else dst_port)
        actions = [parser.OFPActionOutput(first_out_port)]
        data = raw_data if buffer_id == ofproto.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(
            datapath=src_dp, buffer_id=buffer_id, in_port=in_port,
            actions=actions, data=data,
        )
        src_dp.send_msg(out)

    # Dijkstra (multi-path)

    def dijkstra(self, src_dpid):
        """Return (dist, preds) where preds[v] is a list of all equal-cost predecessors."""
        dist = {dpid: float('inf') for dpid in self.datapaths}
        preds = {dpid: [] for dpid in self.datapaths}
        dist[src_dpid] = 0
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
                    preds[b] = [u]
                    heapq.heappush(heap, (new_cost, b))
                elif new_cost == dist[b]:
                    # Equal-cost path: record this predecessor too
                    preds[b].append(u)

        return dist, preds

    def _get_all_paths(self, src_dpid, dst_dpid):
        """Return every equal-cost shortest path from src to dst as a list of dpid lists."""
        if src_dpid not in self.datapaths or dst_dpid not in self.datapaths:
            return []
        _dist, preds = self.dijkstra(src_dpid)
        if dst_dpid != src_dpid and not preds[dst_dpid]:
            return []  # unreachable

        # Backtrack through predecessor lists to enumerate all paths
        paths = []
        stack = [[dst_dpid]]
        while stack:
            partial = stack.pop()
            head = partial[0]
            if head == src_dpid:
                paths.append(list(reversed(partial)))
                continue
            for pred in preds[head]:
                stack.append([pred] + partial)
        return paths

    def get_path(self, src_dpid, dst_dpid):
        """Return one shortest path as an ordered list of dpids, or [] if unreachable."""
        paths = self._get_all_paths(src_dpid, dst_dpid)
        return paths[0] if paths else []

    # Flow hashing

    def _flow_hash(self, pkt, src_mac, dst_mac, n_paths):
        """Stable per-flow index in [0, n_paths); direction-symmetric."""
        # Sort MAC endpoints so A->B and B->A produce the same hash
        ep_a, ep_b = sorted((src_mac, dst_mac))

        ip_src, ip_dst, l4_src, l4_dst = 0, 0, 0, 0
        ip_layer = pkt.get_protocol(ipv4.ipv4)
        if ip_layer:
            def _ip_int(addr):
                return int.from_bytes(
                    bytes(int(x) for x in addr.split('.')), 'big')
            # Sort so reverse traffic hashes the same
            ip_src, ip_dst = sorted((_ip_int(ip_layer.src),
                                     _ip_int(ip_layer.dst)))
            tcp_layer = pkt.get_protocol(tcp.tcp)
            udp_layer = pkt.get_protocol(udp.udp)
            if tcp_layer:
                l4_src, l4_dst = sorted((tcp_layer.src_port,
                                         tcp_layer.dst_port))
            elif udp_layer:
                l4_src, l4_dst = sorted((udp_layer.src_port,
                                         udp_layer.dst_port))

        key = (ep_a, ep_b, ip_src, ip_dst, l4_src, l4_dst)
        return (zlib.crc32(str(key).encode()) & 0xFFFFFFFF) % n_paths

    # Helper methods

    def _add_flow(self, datapath, priority, match, actions,
                  buffer_id=None, idle_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        kwargs = dict(datapath=datapath, priority=priority,
                      match=match, instructions=inst,
                      idle_timeout=idle_timeout)
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
        """Log all ECMP paths from src_dpid to every other known switch."""
        if len(self.datapaths) < 2:
            return
        dist, _preds = self.dijkstra(src_dpid)
        for dst_dpid in self.datapaths:
            if dst_dpid == src_dpid:
                continue
            paths = self._get_all_paths(src_dpid, dst_dpid)
            if paths:
                for idx, path in enumerate(paths):
                    hops = ' -> '.join('%016x' % d for d in path)
                    self.logger.info(
                        "ECMP path %d/%d %016x -> %016x (%d hops): %s",
                        idx + 1, len(paths), src_dpid, dst_dpid,
                        dist[dst_dpid], hops,
                    )
            else:
                self.logger.info(
                    "No path from %016x to %016x", src_dpid, dst_dpid
                )
