package app.veil.vpn;

import com.wireguard.config.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;

final class ProfilePolicy {
    static Config parse(String text) throws Exception {
        if(text.isBlank() || text.getBytes(StandardCharsets.UTF_8).length > 65536) throw new IOException("Profile must be 1–65536 bytes.");
        Config c;
        try { c=Config.parse(new ByteArrayInputStream(text.getBytes(StandardCharsets.UTF_8))); }
        catch(Exception e) { throw new IOException("Invalid WireGuard profile. Check its keys, addresses and syntax."); }
        validate(c);
        return c;
    }
    static void validate(Config c) throws IOException {
        if(c.getPeers().size()!=1) throw new IOException("Import a profile with exactly one peer.");
        Interface i=c.getInterface(); Peer peer=c.getPeers().get(0);
        if(!i.getIncludedApplications().isEmpty() || !i.getExcludedApplications().isEmpty()) throw new IOException("Per-app and split-tunnel profiles are not supported.");
        if(!peer.getEndpoint().isPresent()) throw new IOException("Profile needs a server endpoint.");
        boolean v4Address=false, v4Default=false, v6Default=false, v6Used=false;
        for(InetNetwork n:i.getAddresses()) { if(n.getAddress() instanceof Inet4Address) v4Address=true; else v6Used=true; }
        for(InetAddress a:i.getDnsServers()) if(a instanceof Inet6Address) v6Used=true;
        for(InetNetwork n:peer.getAllowedIps()) {
            if(n.getAddress() instanceof Inet6Address) { v6Used=true; if(n.getMask()==0 && n.getAddress().isAnyLocalAddress()) v6Default=true; }
            else if(n.getMask()==0 && n.getAddress().isAnyLocalAddress()) v4Default=true;
        }
        if(!v4Address || !v4Default) throw new IOException("Profile needs an IPv4 address and AllowedIPs = 0.0.0.0/0.");
        if(v6Used && !v6Default) throw new IOException("IPv6 is configured: include ::/0 to avoid routing outside the VPN.");
    }
    static Config apply(Config c, FilterMode mode) throws Exception {
        validate(c);
        Interface old=c.getInterface();
        if(mode==FilterMode.PROFILE) {
            if(old.getDnsServers().isEmpty()) throw new IOException("Profile has no DNS server. Choose a filtering mode or import a profile with DNS.");
            return c;
        }
        Interface.Builder i=new Interface.Builder().addAddresses(old.getAddresses()).setKeyPair(old.getKeyPair());
        if(old.getMtu().isPresent()) i.setMtu(old.getMtu().get());
        if(old.getListenPort().isPresent()) i.setListenPort(old.getListenPort().get());
        for(String ip:mode.dns) i.addDnsServer(InetAddress.getByName(ip));
        return new Config.Builder().setInterface(i.build()).addPeers(c.getPeers()).build();
    }
}
