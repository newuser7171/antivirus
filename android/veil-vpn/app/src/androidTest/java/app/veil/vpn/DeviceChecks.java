package app.veil.vpn;

import android.app.*;
import android.content.*;
import android.net.*;
import android.os.*;
import com.wireguard.crypto.KeyPair;
import com.wireguard.android.backend.GoBackend;
import java.util.concurrent.atomic.AtomicReference;

/** Disposable-emulator smoke test; never run against a user's configured installation. */
public final class DeviceChecks extends Instrumentation {
    @Override public void onCreate(Bundle args){super.onCreate(args);start();}
    private static void check(boolean condition,String message){if(!condition)throw new AssertionError(message);}
    @Override public void onStart(){
        Bundle results=new Bundle();Context context=getTargetContext();TunnelController c=TunnelController.get(context);
        try {
            String config="[Interface]\nPrivateKey = "+new KeyPair().getPrivateKey().toBase64()+"\nAddress = 10.8.0.2/32\nDNS = 1.1.1.1\n[Peer]\nPublicKey = "+new KeyPair().getPublicKey().toBase64()+"\nEndpoint = 127.0.0.1:59999\nAllowedIPs = 0.0.0.0/0, ::/0\n";
            c.setMode(FilterMode.ADS);c.saveProfile(config);
            check(c.secrets.get("profile").equals(config),"Encrypted profile round trip");
            check(!context.getSharedPreferences("keys",0).getString("profile","").contains("PrivateKey"),"Profile stored as ciphertext");
            check(!new GoBackend(context).getVersion().isEmpty(),"Native backend loads");
            AtomicReference<Activity> activity=new AtomicReference<>();
            activity.set(startActivitySync(new Intent(context,MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)));
            waitForIdleSync();
            for(String method:new String[]{"jev","settings","home"})runOnMainSync(()->{try{var m=MainActivity.class.getDeclaredMethod(method);m.setAccessible(true);m.invoke(activity.get());}catch(Exception e){throw new RuntimeException(e);}});
            context.startForegroundService(new Intent(context,ShieldVpnService.class));
            long deadline=SystemClock.elapsedRealtime()+30000;
            while(!c.up&&SystemClock.elapsedRealtime()<deadline)Thread.sleep(200);
            check(c.up,"Tunnel reaches UP: "+c.status);check(!c.verified(),"Unreachable peer never claims a handshake");
            ConnectivityManager cm=context.getSystemService(ConnectivityManager.class);boolean found=false;
            for(Network n:cm.getAllNetworks()){
                NetworkCapabilities caps=cm.getNetworkCapabilities(n);LinkProperties lp=cm.getLinkProperties(n);
                if(caps!=null&&caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)&&lp!=null)for(var dns:lp.getDnsServers())if("94.140.14.14".equals(dns.getHostAddress()))found=true;
            }
            check(found,"Filtering DNS installed on VPN interface");
            c.disconnect();deadline=SystemClock.elapsedRealtime()+15000;
            while((c.up||c.busy)&&SystemClock.elapsedRealtime()<deadline)Thread.sleep(200);
            check(!c.up&&!c.busy,"Disconnect completes");
            c.clearProfile();check(c.secrets.get("profile").isEmpty(),"Profile removal");
            runOnMainSync(()->activity.get().finish());
            results.putString("stream","DEVICE CHECKS PASSED: encryption, native backend, three screens, VPN start, DNS, no false handshake, disconnect, removal\n");finish(Activity.RESULT_OK,results);
        }catch(Throwable e){c.disconnect();results.putString("stream","DEVICE CHECKS FAILED: "+e.getClass().getSimpleName()+": "+e.getMessage()+"\n");finish(Activity.RESULT_CANCELED,results);}
    }
}
