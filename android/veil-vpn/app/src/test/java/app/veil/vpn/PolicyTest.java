package app.veil.vpn;
import org.junit.Test;
import static org.junit.Assert.*;
import com.wireguard.config.*;
import com.wireguard.crypto.KeyPair;
import org.json.*;

public class PolicyTest {
    private String profile(String routes,String extra){return "[Interface]\nPrivateKey = "+new KeyPair().getPrivateKey().toBase64()+"\nAddress = 10.8.0.2/32\nDNS = 1.1.1.1\n"+extra+"\n[Peer]\nPublicKey = "+new KeyPair().getPublicKey().toBase64()+"\nEndpoint = 127.0.0.1:51820\nAllowedIPs = "+routes+"\n";}
    @Test public void filteringPreservesKeysAndPeer()throws Exception {
        Config c=ProfilePolicy.parse(profile("0.0.0.0/0", ""));Config filtered=ProfilePolicy.apply(c,FilterMode.ADS);
        assertEquals(c.getInterface().getKeyPair().getPrivateKey(),filtered.getInterface().getKeyPair().getPrivateKey());
        assertEquals(c.getPeers(),filtered.getPeers());
        assertTrue(filtered.getInterface().getDnsServers().stream().anyMatch(a->a.getHostAddress().equals("94.140.14.14")));
        assertEquals(2,filtered.getInterface().getDnsServers().size());
        assertSame(c,ProfilePolicy.apply(c,FilterMode.PROFILE));
    }
    @Test public void familyUsesDifferentResolvers()throws Exception {
        Config c=ProfilePolicy.apply(ProfilePolicy.parse(profile("0.0.0.0/0", "")),FilterMode.FAMILY);
        assertTrue(c.getInterface().getDnsServers().stream().anyMatch(a->a.getHostAddress().equals("94.140.14.15")));
    }
    @Test public void splitTunnelRejected(){assertThrows(Exception.class,()->ProfilePolicy.parse(profile("10.0.0.0/8","")));}
    @Test public void partialIpv6Rejected(){assertThrows(Exception.class,()->ProfilePolicy.parse(profile("0.0.0.0/0, fd00::/8","")));}
    @Test public void ipv6AddressWithoutDefaultRejected(){assertThrows(Exception.class,()->ProfilePolicy.parse(profile("0.0.0.0/0","Address = fd00::2/128")));}
    @Test public void fullDualStackAccepted()throws Exception {assertNotNull(ProfilePolicy.parse(profile("0.0.0.0/0, ::/0","Address = fd00::2/128")));}
    @Test public void missingDnsFailsOnlyProfileMode()throws Exception {
        Config c=ProfilePolicy.parse(profile("0.0.0.0/0","").replace("DNS = 1.1.1.1\n",""));
        assertThrows(Exception.class,()->ProfilePolicy.apply(c,FilterMode.PROFILE));assertNotNull(ProfilePolicy.apply(c,FilterMode.ADS));
    }
    @Test public void excessiveProfileRejected(){assertThrows(Exception.class,()->ProfilePolicy.parse("x".repeat(65537)));}
    @Test public void perAppProfileRejected(){assertThrows(Exception.class,()->ProfilePolicy.parse(profile("0.0.0.0/0","ExcludedApplications = com.example.app")));}
    private JSONObject answer(String pick,double confidence)throws Exception {return new JSONObject().put("answers",new JSONObject().put("filter_mode",new JSONObject().put("type","choice").put("choice",pick).put("confidence",confidence).put("probabilities",new JSONObject().put("ads",0.8).put("family",0.1).put("profile",0.05).put("unsupported",0.05))));}
    @Test public void requestContainsOnlyUserPreference()throws Exception {
        JSONObject p=JevApi.payload("Block trackers");assertEquals("jev-latest",p.getString("model"));assertEquals(1,p.getJSONObject("state").length());assertEquals("Block trackers",p.getJSONObject("state").getString("preference"));
    }
    @Test public void highConfidenceSupportsManualApply()throws Exception {assertTrue(JevApi.parse(answer("ads",0.9)).applicable());}
    @Test public void lowConfidenceCannotApply()throws Exception {assertFalse(JevApi.parse(answer("ads",0.5)).applicable());}
    @Test public void unsupportedCannotApply()throws Exception {assertFalse(JevApi.parse(answer("unsupported",1)).applicable());}
    @Test public void unknownModeRejected()throws Exception {assertThrows(Exception.class,()->JevApi.parse(answer("allow_all",1)));}
    @Test public void malformedProbabilityRejected()throws Exception {JSONObject a=answer("ads",0.8);a.getJSONObject("answers").getJSONObject("filter_mode").getJSONObject("probabilities").put("ads",1.5);assertThrows(Exception.class,()->JevApi.parse(a));}
    @Test public void missingDistributionRejected()throws Exception {JSONObject a=answer("ads",0.8);a.getJSONObject("answers").getJSONObject("filter_mode").remove("probabilities");assertThrows(Exception.class,()->JevApi.parse(a));}
    @Test public void confidenceOutOfRangeRejected()throws Exception {assertThrows(Exception.class,()->JevApi.parse(answer("ads",2)));}
    @Test public void invalidPreferenceRejected(){assertThrows(Exception.class,()->JevApi.payload(" "));assertThrows(Exception.class,()->JevApi.payload("x".repeat(2001)));}
}
