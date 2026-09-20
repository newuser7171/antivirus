package app.veil.vpn;

import android.content.Context;
import com.wireguard.android.backend.*;
import java.util.concurrent.*;

final class TunnelController implements Tunnel {
    private static TunnelController instance;
    static synchronized TunnelController get(Context context) {
        if(instance==null)instance=new TunnelController(context.getApplicationContext());
        return instance;
    }
    final Context context;
    final SecretStore secrets;
    private final ScheduledExecutorService worker=Executors.newSingleThreadScheduledExecutor();
    private GoBackend backend;
    private volatile ShieldVpnService service;
    volatile boolean up=false, busy=false;
    volatile String status="Disconnected";
    volatile long rx=0,tx=0,handshake=0;
    private TunnelController(Context c){context=c; secrets=new SecretStore(c); worker.scheduleWithFixedDelay(this::poll,3,3,TimeUnit.SECONDS);}
    public String getName(){return "veil";}
    public void onStateChange(State state){up=state==State.UP; if(!up)handshake=0;}
    FilterMode mode(){return FilterMode.from(context.getSharedPreferences("settings",0).getString("mode","ads"));}
    synchronized void setMode(FilterMode m)throws Exception {
        if(up||busy)throw new Exception("Disconnect before changing filtering.");
        String text=secrets.get("profile");
        if(!text.isEmpty())ProfilePolicy.apply(ProfilePolicy.parse(text),m);
        if(!context.getSharedPreferences("settings",0).edit().putString("mode",m.id).commit())throw new Exception("Could not save filtering mode.");
    }
    synchronized void saveProfile(String text)throws Exception {
        if(up||busy)throw new Exception("Disconnect before changing the profile.");
        ProfilePolicy.apply(ProfilePolicy.parse(text),mode());
        secrets.put("profile",text);
    }
    synchronized void clearProfile()throws Exception {
        if(up||busy)throw new Exception("Disconnect before removing the profile.");
        secrets.put("profile","");
    }
    synchronized void connect(ShieldVpnService s){
        service=s;
        if(up||busy)return;
        busy=true;status="Starting tunnel…";
        worker.execute(()->{
            try {
                if(backend==null)backend=new GoBackend(context);
                backend.setState(this,State.UP,ProfilePolicy.apply(ProfilePolicy.parse(secrets.get("profile")),mode()));
                status="Tunnel active · waiting for handshake";
            }catch(Exception e){status="Connection failed. Check your profile, VPN permission and network.";up=false;s.stopSelf();}
            finally{busy=false;}
        });
    }
    synchronized void disconnect(){
        if(busy)return;
        busy=true;status="Disconnecting…";
        worker.execute(()->{
            try{if(backend!=null)backend.setState(this,State.DOWN,null);status="Disconnected";}
            catch(Exception e){status="Could not stop tunnel. Use Android VPN settings.";}
            finally{busy=false; ShieldVpnService s=service;if(s!=null)s.stopSelf();}
        });
    }
    void stopped(ShieldVpnService s){if(service==s){service=null;up=false;handshake=0;if(status.startsWith("Tunnel")||status.startsWith("Handshake"))status="Disconnected";}}
    boolean verified(){long age=System.currentTimeMillis()-handshake;return up&&handshake>0&&age>=0&&age<180000;}
    private void poll(){
        if(!up||backend==null)return;
        try {
            Statistics stats=backend.getStatistics(this);rx=stats.totalRx();tx=stats.totalTx();
            long latest=0;
            for(var key:stats.peers())latest=Math.max(latest,stats.peer(key).latestHandshakeEpochMillis());
            handshake=latest;
            status=verified()?"Handshake confirmed":"Tunnel active · no recent handshake";
        }catch(Exception e){status="Tunnel active · statistics unavailable";handshake=0;}
    }
}
